using BlazorPRF.Crypto.Abstractions;
using BlazorPRF.Crypto.Abstractions.Models;
using BlazorPRF.Crypto.Abstractions.Services;
using BlazorPRF.Crypto.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Xunit;

namespace SqliteWasmBlazor.CryptoSync.Tests;

/// <summary>
/// Tests for <see cref="CryptoSyncBootstrap"/>: the first-launch admin
/// scaffolding. Verifies post-bootstrap state: DeviceSettings flagged admin,
/// admin's TrustedContact at Full trust in system scope, admin's self-ShareGroup +
/// self-ShareTarget present and well-formed.
/// </summary>
public class CryptoSyncBootstrapTests : IAsyncLifetime
{
    private SqliteConnection _connection = null!;
    private TestSyncContext _context = null!;
    private CryptoSyncBootstrap _bootstrap = null!;
    private ICryptoProvider _crypto = null!;
    private DualKeyPairFull _adminKeys = null!;

    public async Task InitializeAsync()
    {
        _connection = new SqliteConnection("DataSource=:memory:");
        _connection.Open();

        var options = new DbContextOptionsBuilder<TestSyncContext>()
            .UseSqlite(_connection)
            .Options;

        _context = new TestSyncContext(options);
        await _context.Database.EnsureCreatedAsync();

        _crypto = new BouncyCastleCryptoProvider();
        _bootstrap = new CryptoSyncBootstrap(_context, new GroupEncryptionService(_crypto));

        var adminSeed = new byte[32];
        for (var i = 0; i < adminSeed.Length; i++) { adminSeed[i] = (byte)(i + 1); }
        _adminKeys = await _crypto.DeriveDualKeyPairAsync(adminSeed);
    }

    public Task DisposeAsync()
    {
        _context.Dispose();
        _connection.Dispose();
        return Task.CompletedTask;
    }

    private async Task<TrustedContact> RunBootstrapAsync(string username = "Admin")
    {
        return await _bootstrap.InitializeAdminAsync(
            _adminKeys, username, $"{username.ToLowerInvariant()}@test.com", "Test Device");
    }

    [Fact]
    public async Task InitializeAdminAsync_CreatesAdminContact_WithIsAdminMarker()
    {
        var admin = await RunBootstrapAsync();

        Assert.NotEqual(Guid.Empty, admin.Id);
        Assert.Equal("Admin", admin.Username);
        Assert.Equal(_adminKeys.X25519PublicKey, admin.X25519PublicKey);
        Assert.Equal(_adminKeys.Ed25519PublicKey, admin.Ed25519PublicKey);
        Assert.Equal(SyncRole.Owner, admin.Role);
    }

    [Fact]
    public async Task InitializeAdminAsync_AdminContact_IsFullTrust()
    {
        var admin = await RunBootstrapAsync();
        Assert.Equal(TrustLevel.Full, admin.TrustLevel);
    }

    [Fact]
    public async Task InitializeAdminAsync_AdminContact_IsInPublicSystemScope()
    {
        var admin = await RunBootstrapAsync();
        Assert.Equal(SharingScope.Public, admin.SharingScope);
        Assert.Equal(CryptoSyncBootstrap.SystemSharingId, admin.SharingId);
    }

    [Fact]
    public async Task InitializeAdminAsync_CreatesDeviceSettings_WithIsAdminTrue()
    {
        var admin = await RunBootstrapAsync();

        var device = await _context.DeviceSettings.SingleAsync();
        Assert.True(device.IsAdmin);
        Assert.Equal("Test Device", device.DeviceName);
        Assert.Equal(admin.Id, device.AdminContactId);
    }

    [Fact]
    public async Task InitializeAdminAsync_CreatesSystemShareGroup()
    {
        await RunBootstrapAsync();

        var group = await _context.ShareGroups.SingleAsync();
        Assert.Equal(CryptoSyncBootstrap.SystemGroupContext, group.GroupContext);
        Assert.Equal(1, group.KeyVersion);
        Assert.Equal(_adminKeys.X25519PublicKey, group.AdminPublicKey);
        Assert.Equal(SharingScope.Public, group.SharingScope);
        Assert.Equal(CryptoSyncBootstrap.SystemSharingId, group.SharingId);
    }

    [Fact]
    public async Task InitializeAdminAsync_CreatesSelfShareTarget_ForSystemScope()
    {
        var admin = await RunBootstrapAsync();

        var target = await _context.ShareTargets.SingleAsync();
        Assert.Equal(_adminKeys.X25519PublicKey, target.MemberPublicKey);
        Assert.Equal(1, target.KeyVersion);
        Assert.Equal(SyncRole.Owner, target.Role);
        Assert.Equal(admin.Id, target.GrantedByContactId);
        Assert.NotNull(target.WrappedContentKey);
        Assert.True(target.WrappedContentKey.Length > 12, "WrappedContentKey should be [nonce(12) | ciphertext]");
    }

    [Fact]
    public async Task InitializeAdminAsync_SelfShareTarget_CanUnwrapCek()
    {
        // The wrapped CEK on the admin's self-ShareTarget, when unwrapped
        // with the admin's wrapping key (ECDH + HKDF), must yield a valid
        // 32-byte AES-256 key. This proves the roundtrip from
        // CreateGroupKeysAsync → serialize → deserialize → unwrap works.
        await RunBootstrapAsync();

        var target = await _context.ShareTargets.SingleAsync();
        var group = await _context.ShareGroups.SingleAsync();
        var wrapped = CryptoSyncBootstrap.DeserializeWrappedCek(target.WrappedContentKey);

        // Derive wrapping key (same ECDH + HKDF path the worker uses)
        var adminPrivateKey = Convert.FromBase64String(_adminKeys.X25519PrivateKey);
        var wrappingKeyResult = await _crypto.DeriveWrappingKeyAsync(
            adminPrivateKey, _adminKeys.X25519PublicKey, group.GroupContext);
        Assert.True(wrappingKeyResult.Success);

        var unwrapResult = await _crypto.UnwrapContentKeyAsync(
            wrapped, wrappingKeyResult.Value!);
        Assert.True(unwrapResult.Success);
        Assert.Equal(32, unwrapResult.Value!.Length);
    }

    [Fact]
    public async Task InitializeAdminAsync_Idempotent_DoesNotDuplicateRows()
    {
        var first = await RunBootstrapAsync();
        var second = await RunBootstrapAsync("Admin");

        Assert.Equal(first.Id, second.Id);
        Assert.Equal(1, await _context.Contacts.CountAsync());
        Assert.Equal(1, await _context.DeviceSettings.CountAsync());
        Assert.Equal(1, await _context.ShareGroups.CountAsync());
        Assert.Equal(1, await _context.ShareTargets.CountAsync());
    }

    [Fact]
    public async Task InitializeAdminAsync_GateAcceptsAdminAfterBootstrap()
    {
        var admin = await RunBootstrapAsync();
        var gate = new SyncGate(new ContactService(_context));

        var resolved = await gate.EnsureSenderTrustedAsync(_adminKeys.Ed25519PublicKey);

        Assert.Equal(admin.Id, resolved.Id);
    }
}
