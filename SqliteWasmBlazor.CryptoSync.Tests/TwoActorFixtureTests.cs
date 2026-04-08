using Microsoft.EntityFrameworkCore;
using SqliteWasmBlazor.CryptoSync.Tests.Fixtures;
using Xunit;

namespace SqliteWasmBlazor.CryptoSync.Tests;

/// <summary>
/// Tests against the <see cref="TwoActorBootstrap"/> fixture — verifies the
/// post-bootstrap state of a two-actor scenario (admin + one user) is exactly
/// what every subsequent integration scenario can rely on as its starting point.
/// </summary>
public class TwoActorFixtureTests : IAsyncLifetime
{
    private TwoActorBootstrap _scenario = null!;

    public async Task InitializeAsync()
    {
        _scenario = await TwoActorBootstrap.CreateAsync();
    }

    public async Task DisposeAsync()
    {
        await _scenario.DisposeAsync();
    }

    // ----------------------------------------------------------------
    // ADMIN STATE
    // ----------------------------------------------------------------

    [Fact]
    public async Task Admin_DeviceSettings_IsAdminFlag_True()
    {
        Assert.True(await _scenario.Admin.DeviceIdentity.IsAdminAsync());
    }

    [Fact]
    public async Task Admin_AdminContactId_LinkedToOwnRow()
    {
        var settings = await _scenario.Admin.DeviceIdentity.GetAsync();
        Assert.NotNull(settings);
        Assert.NotNull(settings.AdminContactId);

        var adminContact = await _scenario.Admin.Contacts
            .GetByEd25519PublicKeyAsync(_scenario.Admin.Keys.Ed25519PublicKey);
        Assert.NotNull(adminContact);
        Assert.Equal(adminContact.Id, settings.AdminContactId);
    }

    [Fact]
    public async Task Admin_Contacts_ContainsBothActors()
    {
        var contacts = await _scenario.Admin.Contacts.GetAllAsync();
        Assert.Equal(2, contacts.Count);
        Assert.Contains(contacts, c => c.Ed25519PublicKey == _scenario.Admin.Keys.Ed25519PublicKey);
        Assert.Contains(contacts, c => c.Ed25519PublicKey == _scenario.User.Keys.Ed25519PublicKey);
    }

    [Fact]
    public async Task Admin_UserContact_IsFullTrustInSystemScope()
    {
        var userContact = await _scenario.Admin.Contacts
            .GetByEd25519PublicKeyAsync(_scenario.User.Keys.Ed25519PublicKey);
        Assert.NotNull(userContact);
        Assert.Equal(TrustLevel.Full, userContact.TrustLevel);
        Assert.Equal(SharingScope.Public, userContact.SharingScope);
        Assert.Equal(KeyDerivation.SystemSharingId, userContact.SharingId);
    }

    [Fact]
    public async Task Admin_HasSelfSharingKey_AndUserSharingKey_ForSystemScope()
    {
        var keys = await _scenario.Admin.Context.SharingKeys
            .Where(k => k.SharingId == KeyDerivation.SystemSharingId)
            .ToListAsync();

        Assert.Equal(2, keys.Count);

        var adminContact = await _scenario.Admin.Contacts
            .GetByEd25519PublicKeyAsync(_scenario.Admin.Keys.Ed25519PublicKey);
        var userContact = await _scenario.Admin.Contacts
            .GetByEd25519PublicKeyAsync(_scenario.User.Keys.Ed25519PublicKey);

        Assert.NotNull(adminContact);
        Assert.NotNull(userContact);
        Assert.Contains(keys, k => k.ClientContactId == adminContact.Id && k.Role == SyncRole.Owner);
        Assert.Contains(keys, k => k.ClientContactId == userContact.Id && k.Role == SyncRole.Viewer);
    }

    [Fact]
    public async Task Admin_GateAcceptsAdminAndUserAsFullTrustSenders()
    {
        // Both directions: admin's gate should let admin sync (self-sync, e.g.
        // multi-device admin) and let user sync (peer sync). Both pass because
        // both are TrustLevel.Full in admin's local Contacts table.
        var asAdmin = await _scenario.Admin.Gate.EnsureSenderTrustedAsync(_scenario.Admin.Keys.Ed25519PublicKey);
        var asUser = await _scenario.Admin.Gate.EnsureSenderTrustedAsync(_scenario.User.Keys.Ed25519PublicKey);
        Assert.Equal(TrustLevel.Full, asAdmin.TrustLevel);
        Assert.Equal(TrustLevel.Full, asUser.TrustLevel);
    }

    // ----------------------------------------------------------------
    // USER STATE (post-bootstrap delivery)
    // ----------------------------------------------------------------

    [Fact]
    public async Task User_DeviceSettings_IsAdminFlag_False()
    {
        Assert.False(await _scenario.User.DeviceIdentity.IsAdminAsync());
    }

    [Fact]
    public async Task User_AdminContactId_PointsAtAdminRow()
    {
        var settings = await _scenario.User.DeviceIdentity.GetAsync();
        Assert.NotNull(settings);
        Assert.NotNull(settings.AdminContactId);

        var adminContact = await _scenario.User.Contacts
            .GetByEd25519PublicKeyAsync(_scenario.Admin.Keys.Ed25519PublicKey);
        Assert.NotNull(adminContact);
        Assert.Equal(adminContact.Id, settings.AdminContactId);
    }

    [Fact]
    public async Task User_Contacts_ContainsBothActors()
    {
        var contacts = await _scenario.User.Contacts.GetAllAsync();
        Assert.Equal(2, contacts.Count);
        Assert.Contains(contacts, c => c.Ed25519PublicKey == _scenario.Admin.Keys.Ed25519PublicKey);
        Assert.Contains(contacts, c => c.Ed25519PublicKey == _scenario.User.Keys.Ed25519PublicKey);
    }

    [Fact]
    public async Task User_PrimaryKeysAreShared_WithAdmin()
    {
        // Invariant: shadow and open share the plaintext primary key — that
        // means after the bootstrap delivery, user's TrustedContact rows
        // carry the SAME row Id as admin's. Without this, mutual references
        // (DeviceSettings.AdminContactId, SharingKey.ClientContactId,
        // SharingKey.GrantedByContactId) would diverge across actors.
        var adminContactOnAdmin = await _scenario.Admin.Contacts
            .GetByEd25519PublicKeyAsync(_scenario.Admin.Keys.Ed25519PublicKey);
        var adminContactOnUser = await _scenario.User.Contacts
            .GetByEd25519PublicKeyAsync(_scenario.Admin.Keys.Ed25519PublicKey);
        var userContactOnAdmin = await _scenario.Admin.Contacts
            .GetByEd25519PublicKeyAsync(_scenario.User.Keys.Ed25519PublicKey);
        var userContactOnUser = await _scenario.User.Contacts
            .GetByEd25519PublicKeyAsync(_scenario.User.Keys.Ed25519PublicKey);

        Assert.NotNull(adminContactOnAdmin);
        Assert.NotNull(adminContactOnUser);
        Assert.NotNull(userContactOnAdmin);
        Assert.NotNull(userContactOnUser);

        Assert.Equal(adminContactOnAdmin.Id, adminContactOnUser.Id);
        Assert.Equal(userContactOnAdmin.Id, userContactOnUser.Id);
    }

    [Fact]
    public async Task User_GateAcceptsAdminAsFullTrustSender()
    {
        var resolved = await _scenario.User.Gate.EnsureSenderTrustedAsync(_scenario.Admin.Keys.Ed25519PublicKey);
        Assert.Equal(TrustLevel.Full, resolved.TrustLevel);
        Assert.Equal(_scenario.Admin.Keys.Ed25519PublicKey, resolved.Ed25519PublicKey);
    }

    [Fact]
    public async Task User_HasSharingKeyForSystemScope_WithViewerRole()
    {
        var userContact = await _scenario.User.Contacts
            .GetByEd25519PublicKeyAsync(_scenario.User.Keys.Ed25519PublicKey);
        Assert.NotNull(userContact);

        var key = await _scenario.User.Context.SharingKeys
            .SingleAsync(k => k.SharingId == KeyDerivation.SystemSharingId
                              && k.ClientContactId == userContact.Id);

        Assert.Equal(SharingScope.Public, key.SharingScope);
        Assert.Equal(SyncRole.Viewer, key.Role);
        Assert.NotEmpty(key.WrappedContentKey);
    }

    [Fact]
    public async Task BothActors_AgreeOnSystemContentKey_ViaTheirOwnSharingKeyRows()
    {
        // The deepest invariant: admin and user, after the bootstrap, both
        // unwrap their own SharingKey row to obtain the SAME 32-byte system
        // content key. This is the load-bearing property for system-scope
        // sync — admin can encrypt under it, user can decrypt under it,
        // and they're operating against byte-identical key material despite
        // having entirely separate databases and processing paths.

        var adminContact = await _scenario.Admin.Contacts
            .GetByEd25519PublicKeyAsync(_scenario.Admin.Keys.Ed25519PublicKey);
        Assert.NotNull(adminContact);
        var adminSelfKeyRow = await _scenario.Admin.Context.SharingKeys
            .SingleAsync(k => k.SharingId == KeyDerivation.SystemSharingId
                              && k.ClientContactId == adminContact.Id);

        var userContact = await _scenario.User.Contacts
            .GetByEd25519PublicKeyAsync(_scenario.User.Keys.Ed25519PublicKey);
        Assert.NotNull(userContact);
        var userKeyRow = await _scenario.User.Context.SharingKeys
            .SingleAsync(k => k.SharingId == KeyDerivation.SystemSharingId
                              && k.ClientContactId == userContact.Id);

        var adminUnwrap = await _scenario.Crypto.DecryptAsymmetricAsync(
            EnvelopeBytes.Deserialize(adminSelfKeyRow.WrappedContentKey),
            Convert.FromBase64String(_scenario.Admin.Keys.X25519PrivateKey));
        var userUnwrap = await _scenario.Crypto.DecryptAsymmetricAsync(
            EnvelopeBytes.Deserialize(userKeyRow.WrappedContentKey),
            Convert.FromBase64String(_scenario.User.Keys.X25519PrivateKey));

        Assert.True(adminUnwrap.Success);
        Assert.True(userUnwrap.Success);

        var adminKeyBytes = Convert.FromBase64String(adminUnwrap.Value!);
        var userKeyBytes = Convert.FromBase64String(userUnwrap.Value!);
        Assert.Equal(adminKeyBytes, userKeyBytes);

        // And it must equal the deterministic derivation from admin's private key.
        var derived = KeyDerivation.DeriveSystemContentKey(
            Convert.FromBase64String(_scenario.Admin.Keys.X25519PrivateKey));
        Assert.Equal(derived, adminKeyBytes);
    }
}
