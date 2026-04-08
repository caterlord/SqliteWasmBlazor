using BlazorPRF.Crypto.Abstractions;
using BlazorPRF.Crypto.Testing;
using Microsoft.EntityFrameworkCore;

namespace SqliteWasmBlazor.CryptoSync.Tests.Fixtures;

/// <summary>
/// Two-actor scenario fixture: an admin and one regular user, both bootstrapped
/// to the canonical "ready to sync" state. After <see cref="CreateAsync"/>:
///
/// <list type="bullet">
///   <item>Admin's DB has been initialized via <see cref="CryptoSyncBootstrap"/>:
///         <c>DeviceSettings.IsAdmin=true</c>, admin's <see cref="TrustedContact"/>
///         row in the public system scope at <see cref="TrustLevel.Full"/>, and
///         a self-<see cref="SharingKey"/> wrapping the deterministically-derived
///         system content key.</item>
///   <item>Admin has added user as a <see cref="TrustedContact"/> (Marginal trust
///         initially) and explicitly elevated to Full via
///         <see cref="ContactPromotionService.ElevateToFullAsync"/>.</item>
///   <item>Admin has issued a <see cref="SharingKey"/> for user on the system
///         scope, wrapping the system content key under user's X25519 public
///         key via the existing <c>ICryptoProvider.EncryptAsymmetricAsync</c>.</item>
///   <item>User's DB has been seeded with the rows that would arrive on user's
///         first sync: a <see cref="DeviceSettings"/> with
///         <c>IsAdmin=false, AdminContactId=&lt;admin-row-id&gt;</c>, copies of
///         both <see cref="TrustedContact"/> rows (preserving primary keys
///         per the "shadow and open share the plaintext PK" invariant), and a
///         copy of the <see cref="SharingKey"/> row that grants user access
///         to the system scope.</item>
/// </list>
///
/// Both actors share the same <see cref="ICryptoProvider"/> instance (Bouncy
/// Castle) — they're not networked; they're peers operating on disjoint
/// in-memory SQLite databases. The fixture lets test code reach into either
/// actor's services to assert post-state, simulate further sync events, or
/// run gate checks across both directions.
/// </summary>
public sealed class TwoActorBootstrap : IAsyncDisposable
{
    public TestActor Admin { get; }
    public TestActor User { get; }
    public ICryptoProvider Crypto { get; }

    private TwoActorBootstrap(TestActor admin, TestActor user, ICryptoProvider crypto)
    {
        Admin = admin;
        User = user;
        Crypto = crypto;
    }

    public static async Task<TwoActorBootstrap> CreateAsync(
        string adminName = "Admin",
        string userName = "Alice")
    {
        var crypto = new BouncyCastleCryptoProvider();

        var admin = await TestActor.CreateAsync(adminName, isAdmin: true, seedByte: 1, crypto);
        var user = await TestActor.CreateAsync(userName, isAdmin: false, seedByte: 100, crypto);

        // 1. Bootstrap admin's instance: DeviceSettings(IsAdmin=true), admin's
        //    own TrustedContact, and the admin self-SharingKey for the system scope.
        var adminContact = await admin.Bootstrap.InitializeAdminAsync(
            admin.Keys, adminName, $"{adminName.ToLowerInvariant()}@test.com", $"{adminName} Device");

        // 2. Admin creates a TrustedContact row for the user (Marginal trust by
        //    default — that's the canonical service contract from
        //    ContactService.AddContactAsync, see Phase E).
        var userContactOnAdmin = await admin.Contacts.AddContactAsync(
            new ContactUserData
            {
                Username = userName,
                Email = $"{userName.ToLowerInvariant()}@test.com"
            },
            user.Keys.X25519PublicKey,
            user.Keys.Ed25519PublicKey,
            SyncRole.Editor,
            TrustLevel.Marginal,
            TrustDirection.Sent);

        // 3. Admin explicitly elevates user from Marginal → Full.
        //    This flips the user contact's TrustLevel to Full and migrates its
        //    SharingScope from Client → Public + SharingId="system" so the row
        //    will broadcast to peers in the system scope (decision §9 + §12 — the
        //    elevation is always an explicit admin action, never automatic).
        await admin.Promotion.ElevateToFullAsync(userContactOnAdmin.Id);

        // Refresh the entity so we see the post-elevation state.
        await admin.Context.Entry(userContactOnAdmin).ReloadAsync();

        // 4. Admin issues a SharingKey for the user on the system scope.
        //    Admin re-derives the system content key from their private key and
        //    ECIES-wraps it under user's X25519 public key. The wrapped form
        //    goes into a SharingKey row that conceptually says "user has Viewer
        //    access to the system scope, granted by admin".
        var adminPrivKey = Convert.FromBase64String(admin.Keys.X25519PrivateKey);
        byte[]? systemContentKey = null;
        SharingKey sharingKeyForUserOnAdmin;
        try
        {
            systemContentKey = KeyDerivation.DeriveSystemContentKey(adminPrivKey);
            var contentKeyBase64 = Convert.ToBase64String(systemContentKey);
            var wrapResult = await crypto.EncryptAsymmetricAsync(contentKeyBase64, user.Keys.X25519PublicKey);
            if (!wrapResult.Success)
            {
                throw new InvalidOperationException(
                    $"Failed to wrap system content key for user: {wrapResult.ErrorCode}");
            }
            var wrappedForUser = EnvelopeBytes.Serialize(wrapResult.Value!);

            sharingKeyForUserOnAdmin = new SharingKey
            {
                Id = Guid.NewGuid(),
                SharingId = KeyDerivation.SystemSharingId,
                SharingScope = SharingScope.Public,
                ClientContactId = userContactOnAdmin.Id,
                WrappedContentKey = wrappedForUser,
                Role = SyncRole.Viewer,
                GrantedByContactId = adminContact.Id,
                CreatedAt = DateTime.UtcNow
            };
            admin.Context.SharingKeys.Add(sharingKeyForUserOnAdmin);
            await admin.Context.SaveChangesAsync();
        }
        finally
        {
            if (systemContentKey is not null)
            {
                System.Security.Cryptography.CryptographicOperations.ZeroMemory(systemContentKey);
            }
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(adminPrivKey);
        }

        // 5. Simulate the bootstrap delivery to user's DB. In a real run this
        //    would be a sync delta from admin → user containing exactly the
        //    rows below. We seed them directly because the sync wire path
        //    isn't built yet (Stages 5-7), and the IDs MUST match admin's
        //    side (the "shadow and open share the plaintext PK" invariant).

        var userDevice = new DeviceSettings
        {
            Id = Guid.NewGuid(),
            ClientGuid = Guid.NewGuid().ToString(),
            DeviceName = $"{userName} Device",
            IsAdmin = false,
            AdminContactId = adminContact.Id
        };
        user.Context.DeviceSettings.Add(userDevice);

        // Copy admin's TrustedContact row into user's DB (same Id).
        var adminContactCopy = new TrustedContact
        {
            Id = adminContact.Id,
            Username = adminContact.Username,
            Email = adminContact.Email,
            Comment = adminContact.Comment,
            X25519PublicKey = adminContact.X25519PublicKey,
            Ed25519PublicKey = adminContact.Ed25519PublicKey,
            Role = adminContact.Role,
            TrustLevel = adminContact.TrustLevel,
            Direction = TrustDirection.Received, // from user's perspective, admin invited them
            VerifiedAt = adminContact.VerifiedAt,
            UpdatedAt = adminContact.UpdatedAt,
            SharingScope = adminContact.SharingScope,
            SharingId = adminContact.SharingId
        };
        user.Context.Contacts.Add(adminContactCopy);

        // Copy the user's own TrustedContact row (same Id as on admin's side).
        var userContactCopy = new TrustedContact
        {
            Id = userContactOnAdmin.Id,
            Username = userContactOnAdmin.Username,
            Email = userContactOnAdmin.Email,
            Comment = userContactOnAdmin.Comment,
            X25519PublicKey = userContactOnAdmin.X25519PublicKey,
            Ed25519PublicKey = userContactOnAdmin.Ed25519PublicKey,
            Role = userContactOnAdmin.Role,
            TrustLevel = userContactOnAdmin.TrustLevel,
            Direction = TrustDirection.Sent, // from user's perspective, this is themself
            VerifiedAt = userContactOnAdmin.VerifiedAt,
            UpdatedAt = userContactOnAdmin.UpdatedAt,
            SharingScope = userContactOnAdmin.SharingScope,
            SharingId = userContactOnAdmin.SharingId
        };
        user.Context.Contacts.Add(userContactCopy);

        // Copy the SharingKey that grants user access to the system scope.
        var sharingKeyCopyForUser = new SharingKey
        {
            Id = sharingKeyForUserOnAdmin.Id,
            SharingId = sharingKeyForUserOnAdmin.SharingId,
            SharingScope = sharingKeyForUserOnAdmin.SharingScope,
            ClientContactId = sharingKeyForUserOnAdmin.ClientContactId,
            WrappedContentKey = sharingKeyForUserOnAdmin.WrappedContentKey,
            Role = sharingKeyForUserOnAdmin.Role,
            GrantedByContactId = sharingKeyForUserOnAdmin.GrantedByContactId,
            CreatedAt = sharingKeyForUserOnAdmin.CreatedAt
        };
        user.Context.SharingKeys.Add(sharingKeyCopyForUser);

        await user.Context.SaveChangesAsync();

        return new TwoActorBootstrap(admin, user, crypto);
    }

    public async ValueTask DisposeAsync()
    {
        await Admin.DisposeAsync();
        await User.DisposeAsync();
    }
}
