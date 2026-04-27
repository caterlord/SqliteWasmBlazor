using SqliteWasmBlazor.Crypto.Abstractions.Models;
using SqliteWasmBlazor.Crypto.Abstractions.Services;
using SqliteWasmBlazor.Crypto.Testing;
using MessagePack;
using Microsoft.EntityFrameworkCore;
using SqliteWasmBlazor.CryptoSync.Tests.Fixtures;
using System.Security.Cryptography;
using Xunit;

namespace SqliteWasmBlazor.CryptoSync.Tests;

/// <summary>
/// Stage-3+4 seam coverage: drive the contact-invitation response leg
/// through <see cref="ISyncTransport"/> instead of an in-process channel,
/// and prove the wire is opaque to anyone without the OOB invitation token.
/// The underlying ContactAcceptancePayload (and the privacy invariant on
/// the contact's self-group CEK) must remain intact through the encrypted
/// transport.
/// </summary>
public class InvitationRoundtripTests
{
    [Fact]
    public async Task Roundtrip_ContactRespondsAdminAccepts_ViaSyncTransport()
    {
        var crypto = new BouncyCastleCryptoProvider();
        var groupEncryption = new GroupEncryptionService(crypto);
        var declarationSigner = new DeclarationSigner(crypto);
        var relay = new InMemorySyncRelay();

        var admin = await TestActor.CreateAsync("Admin", isAdmin: true, seedByte: 1, crypto);
        var contact = await TestActor.CreateAsync("Helen", isAdmin: false, seedByte: 220, crypto);
        try
        {
            var adminTransport = new InMemorySyncTransport(relay, admin.Keys.X25519PublicKey);
            var contactTransport = new InMemorySyncTransport(relay, contact.Keys.X25519PublicKey);

            // Fabricate the bundle (the admin-side placeholder creation is
            // covered in CreateInvitationTests; here we just need a token +
            // admin pubkey to drive the response leg).
            var token = RandomNumberGenerator.GetBytes(ContactService.InvitationTokenSize);
            var bundle = new InvitationBundle
            {
                Token = token,
                AdminX25519PublicKey = admin.Keys.X25519PublicKey
            };

            var contactSvc = new ContactInvitationService(contact.Context, groupEncryption, crypto, declarationSigner);
            await contactSvc.RespondToInvitationAsync(
                bundle,
                contact.Keys,
                new ContactUserData { Username = "Helen", Email = "helen@test.com" },
                contactTransport);

            // Admin pulls the encrypted envelope from the relay.
            var envelopeBytes = await adminTransport.TryReceiveAsync()
                ?? throw new InvalidOperationException("Admin's transport returned no envelope");

            // Wire-opacity check: plaintext markers (username/email/contact
            // pubkey) must not appear anywhere in the wire bytes. Otherwise
            // the relay/observer learns identity attributes.
            AssertNoPlaintextLeak(envelopeBytes, "Helen", "helen@test.com",
                contact.Keys.X25519PublicKey, contact.Keys.Ed25519PublicKey);

            // Manual decrypt — Stage 4d folds this into AcceptInvitationResponseAsync.
            var envelope = MessagePackSerializer.Deserialize<EncryptedInvitationResponse>(envelopeBytes);
            var psk = ContactInvitationService.DeriveInvitationPsk(token);
            var decryptResult = await crypto.DecryptSymmetricAsync(
                new SymmetricEncryptedData(envelope.Ciphertext, envelope.Nonce),
                psk);
            Assert.True(decryptResult.Success);
            var canonicalBase64 = decryptResult.Value
                ?? throw new InvalidOperationException("Decrypt succeeded but plaintext was null");
            var canonicalBytes = Convert.FromBase64String(canonicalBase64);
            var receivedPayload = MessagePackSerializer.Deserialize<ContactAcceptancePayload>(canonicalBytes);

            // Token must round-trip into the (signed) inner payload.
            Assert.Equal(token, receivedPayload.InvitationToken);

            // Existing accept path — transitional. 4d refactors to find-by-token.
            var adminSvc = new ContactInvitationService(admin.Context, groupEncryption, crypto, declarationSigner);
            var persisted = await adminSvc.AcceptInvitationResponseAsync(
                admin.Keys,
                receivedPayload,
                systemRole: SyncRole.EDITOR);

            Assert.Equal(ContactStatus.Verified, persisted.Status);
            Assert.False(persisted.IsAdmin);
            Assert.Equal(contact.Keys.X25519PublicKey, persisted.X25519PublicKey);

            var systemGroup = await admin.Context.ShareGroups
                .SingleAsync(g => g.GroupContext == CryptoSyncBootstrap.SystemGroupContext);
            var contactSystemTarget = await admin.Context.ShareTargets
                .SingleAsync(t => t.ShareGroupId == systemGroup.Id
                    && t.MemberPublicKey == contact.Keys.X25519PublicKey);
            Assert.Equal(SyncRole.EDITOR, contactSystemTarget.Role);

            var contactSelfGroup = await admin.Context.ShareGroups
                .SingleAsync(g => g.Id == receivedPayload.SelfGroupId);
            Assert.True(await admin.Context.ShareTargets
                .AnyAsync(t => t.ShareGroupId == contactSelfGroup.Id
                    && t.MemberPublicKey == contact.Keys.X25519PublicKey));

            // Inbox must be drained.
            Assert.Null(await adminTransport.TryReceiveAsync());
        }
        finally
        {
            await admin.DisposeAsync();
            await contact.DisposeAsync();
        }
    }

    [Fact]
    public async Task Roundtrip_WrongToken_DecryptionFails()
    {
        var crypto = new BouncyCastleCryptoProvider();
        var groupEncryption = new GroupEncryptionService(crypto);
        var declarationSigner = new DeclarationSigner(crypto);
        var relay = new InMemorySyncRelay();

        var admin = await TestActor.CreateAsync("Admin", isAdmin: true, seedByte: 1, crypto);
        var contact = await TestActor.CreateAsync("Mallory", isAdmin: false, seedByte: 215, crypto);
        try
        {
            var contactTransport = new InMemorySyncTransport(relay, contact.Keys.X25519PublicKey);
            var adminTransport = new InMemorySyncTransport(relay, admin.Keys.X25519PublicKey);

            var realToken = RandomNumberGenerator.GetBytes(ContactService.InvitationTokenSize);
            var bundle = new InvitationBundle
            {
                Token = realToken,
                AdminX25519PublicKey = admin.Keys.X25519PublicKey
            };

            var contactSvc = new ContactInvitationService(contact.Context, groupEncryption, crypto, declarationSigner);
            await contactSvc.RespondToInvitationAsync(
                bundle, contact.Keys, new ContactUserData { Username = "Mallory", Email = "m@test.com" },
                contactTransport);

            var envelopeBytes = await adminTransport.TryReceiveAsync()
                ?? throw new InvalidOperationException("No envelope received");
            var envelope = MessagePackSerializer.Deserialize<EncryptedInvitationResponse>(envelopeBytes);

            // Wrong token — AES-GCM auth tag must reject decryption.
            var wrongToken = RandomNumberGenerator.GetBytes(ContactService.InvitationTokenSize);
            var wrongPsk = ContactInvitationService.DeriveInvitationPsk(wrongToken);
            var decryptResult = await crypto.DecryptSymmetricAsync(
                new SymmetricEncryptedData(envelope.Ciphertext, envelope.Nonce), wrongPsk);

            Assert.False(decryptResult.Success);
        }
        finally
        {
            await admin.DisposeAsync();
            await contact.DisposeAsync();
        }
    }

    [Fact]
    public async Task DerivePsk_TamperedToken_ProducesDifferentKey()
    {
        var token = RandomNumberGenerator.GetBytes(ContactService.InvitationTokenSize);
        var keyA = ContactInvitationService.DeriveInvitationPsk(token);

        var tampered = (byte[])token.Clone();
        tampered[0] ^= 0x01;
        var keyB = ContactInvitationService.DeriveInvitationPsk(tampered);

        Assert.NotEqual(keyA, keyB);
        Assert.Equal(32, keyA.Length);
        Assert.Equal(32, keyB.Length);
        await Task.CompletedTask;
    }

    [Fact]
    public async Task Roundtrip_ImportFiresNotifier()
    {
        var crypto = new BouncyCastleCryptoProvider();
        var actor = await TestActor.CreateAsync("Solo", isAdmin: true, seedByte: 230, crypto);
        try
        {
            var notifier = new RecordingImportNotifier();
            var fakeDatabase = new FakeDatabaseService
            {
                CannedImportReport = new ImportReport { RowsImported = 3 }
            };

            var orchestrator = new SyncOrchestrator(fakeDatabase, actor.Context, notifier);
            var header = new V2CryptoHeader
            {
                Version = 2,
                SystemTables = ["Contacts", "ShareGroups", "ShareTargets"],
                GroupContext = CryptoSyncBootstrap.SystemGroupContext,
                KeyVersion = 1
            };

            var report = await orchestrator.ImportAsync("test.db", header, envelopeBytes: [0x01]);

            Assert.Equal(3, report.RowsImported);
            Assert.Single(notifier.Reports);
            Assert.Equal(3, notifier.Reports.Single().RowsImported);
        }
        finally
        {
            await actor.DisposeAsync();
        }
    }

    [Fact]
    public async Task PrivacyInvariant_AdminCannotUnwrapContactSelfGroupCek()
    {
        var crypto = new BouncyCastleCryptoProvider();
        var groupEncryption = new GroupEncryptionService(crypto);
        var declarationSigner = new DeclarationSigner(crypto);
        var relay = new InMemorySyncRelay();

        var admin = await TestActor.CreateAsync("Admin", isAdmin: true, seedByte: 1, crypto);
        var contact = await TestActor.CreateAsync("Ivy", isAdmin: false, seedByte: 240, crypto);
        try
        {
            var adminTransport = new InMemorySyncTransport(relay, admin.Keys.X25519PublicKey);
            var contactTransport = new InMemorySyncTransport(relay, contact.Keys.X25519PublicKey);

            var token = RandomNumberGenerator.GetBytes(ContactService.InvitationTokenSize);
            var bundle = new InvitationBundle
            {
                Token = token,
                AdminX25519PublicKey = admin.Keys.X25519PublicKey
            };

            var contactSvc = new ContactInvitationService(contact.Context, groupEncryption, crypto, declarationSigner);
            await contactSvc.RespondToInvitationAsync(
                bundle, contact.Keys, new ContactUserData { Username = "Ivy", Email = "ivy@test.com" },
                contactTransport);

            var envelopeBytes = await adminTransport.TryReceiveAsync()
                ?? throw new InvalidOperationException("No envelope");
            var envelope = MessagePackSerializer.Deserialize<EncryptedInvitationResponse>(envelopeBytes);
            var psk = ContactInvitationService.DeriveInvitationPsk(token);
            var decrypt = await crypto.DecryptSymmetricAsync(
                new SymmetricEncryptedData(envelope.Ciphertext, envelope.Nonce), psk);
            Assert.True(decrypt.Success);
            var plaintext = decrypt.Value
                ?? throw new InvalidOperationException("Decrypt succeeded but plaintext null");
            var receivedPayload = MessagePackSerializer
                .Deserialize<ContactAcceptancePayload>(Convert.FromBase64String(plaintext));

            var adminSvc = new ContactInvitationService(admin.Context, groupEncryption, crypto, declarationSigner);
            await adminSvc.AcceptInvitationResponseAsync(admin.Keys, receivedPayload);

            // Admin holds the contact's self-group rows but cannot unwrap the CEK.
            var selfGroup = await admin.Context.ShareGroups.SingleAsync(g => g.Id == receivedPayload.SelfGroupId);
            var selfTarget = await admin.Context.ShareTargets.SingleAsync(t => t.ShareGroupId == selfGroup.Id);
            var wrapped = CryptoSyncBootstrap.DeserializeWrappedCek(selfTarget.WrappedContentKey);

            var adminPriv = Convert.FromBase64String(admin.Keys.X25519PrivateKey);
            var wrongWk = await crypto.DeriveWrappingKeyAsync(
                adminPriv, contact.Keys.X25519PublicKey, selfGroup.GroupContext);
            Assert.True(wrongWk.Success);

            // wrongWk.Value is ReadOnlyMemory<byte> (value type) — Success
            // already asserted, so it's populated. Pass directly.
            var cekResult = await crypto.UnwrapContentKeyAsync(wrapped, wrongWk.Value);
            Assert.False(cekResult.Success);
        }
        finally
        {
            await admin.DisposeAsync();
            await contact.DisposeAsync();
        }
    }

    /// <summary>
    /// Treat the wire bytes as Latin-1 / ASCII and refuse any of the
    /// caller-supplied plaintext markers to appear as a substring. Catches
    /// the common "we serialized but forgot to encrypt" regression cleanly
    /// without reaching for entropy heuristics.
    /// </summary>
    private static void AssertNoPlaintextLeak(byte[] wire, params string[] markers)
    {
        var wireText = System.Text.Encoding.Latin1.GetString(wire);
        foreach (var marker in markers)
        {
            Assert.DoesNotContain(marker, wireText);
        }
    }
}
