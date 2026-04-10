using BlazorPRF.Crypto.Abstractions;
using BlazorPRF.Crypto.Abstractions.Services;
using BlazorPRF.Crypto.Testing;
using Microsoft.EntityFrameworkCore;

namespace SqliteWasmBlazor.CryptoSync.Tests.Fixtures;

/// <summary>
/// Two-actor scenario fixture: an admin and one regular user, both bootstrapped
/// to the canonical "ready to sync" state. After <see cref="CreateAsync"/>:
///
/// <list type="bullet">
///   <item>Admin's DB: DeviceSettings(IsAdmin=true), admin's TrustedContact at Full trust,
///         system ShareGroup + admin self-ShareTarget.</item>
///   <item>Admin has added user as a TrustedContact (elevated to Full), and issued a
///         ShareTarget wrapping the system CEK for the user.</item>
///   <item>User's DB: seeded with admin's contact, user's own contact, and user's
///         ShareTarget for the system scope.</item>
/// </list>
/// </summary>
public sealed class TwoActorBootstrap : IAsyncDisposable
{
    public TestActor Admin { get; }
    public TestActor User { get; }
    public ICryptoProvider Crypto { get; }
    public IGroupEncryption GroupEncryption { get; }

    private TwoActorBootstrap(TestActor admin, TestActor user, ICryptoProvider crypto, IGroupEncryption groupEncryption)
    {
        Admin = admin;
        User = user;
        Crypto = crypto;
        GroupEncryption = groupEncryption;
    }

    public static async Task<TwoActorBootstrap> CreateAsync(
        string adminName = "Admin",
        string userName = "Alice")
    {
        var crypto = new BouncyCastleCryptoProvider();
        var groupEncryption = new GroupEncryptionService(crypto);

        var admin = await TestActor.CreateAsync(adminName, isAdmin: true, seedByte: 1, crypto);
        var user = await TestActor.CreateAsync(userName, isAdmin: false, seedByte: 100, crypto);

        // 1. Bootstrap admin: DeviceSettings, admin TrustedContact, system ShareGroup + self-ShareTarget
        var adminContact = await admin.Bootstrap.InitializeAdminAsync(
            admin.Keys, adminName, $"{adminName.ToLowerInvariant()}@test.com", $"{adminName} Device");

        // 2. Admin creates a TrustedContact for the user (Marginal → Full)
        var userContactOnAdmin = await admin.Contacts.AddContactAsync(
            new ContactUserData
            {
                Username = userName,
                Email = $"{userName.ToLowerInvariant()}@test.com"
            },
            user.Keys.X25519PublicKey,
            user.Keys.Ed25519PublicKey);

        // 3. Trust the user
        await admin.Contacts.TrustAsync(userContactOnAdmin.Id);
        await admin.Context.Entry(userContactOnAdmin).ReloadAsync();

        // 4. Admin issues a ShareTarget for the user on the system scope.
        //    Uses AddGroupMembersAsync to unwrap admin's CEK and re-wrap for user.
        var systemGroup = await admin.Context.ShareGroups
            .SingleAsync(g => g.GroupContext == CryptoSyncBootstrap.SystemGroupContext);
        var adminTarget = await admin.Context.ShareTargets
            .SingleAsync(t => t.ShareGroupId == systemGroup.Id
                && t.MemberPublicKey == admin.Keys.X25519PublicKey);

        var adminPrivKey = Convert.FromBase64String(admin.Keys.X25519PrivateKey);
        var adminWrappedCek = CryptoSyncBootstrap.DeserializeWrappedCek(adminTarget.WrappedContentKey);
        ShareTarget userTargetOnAdmin;
        try
        {
            var addResult = await groupEncryption.AddGroupMembersAsync(
                adminPrivKey,
                admin.Keys.X25519PublicKey,
                adminWrappedCek,
                [user.Keys.X25519PublicKey],
                systemGroup.GroupContext);

            if (!addResult.Success)
            {
                throw new InvalidOperationException(
                    $"Failed to wrap CEK for user: {addResult.ErrorCode}");
            }

            var userWrappedKey = addResult.Value![0];

            userTargetOnAdmin = new ShareTarget
            {
                Id = Guid.NewGuid(),
                ShareGroupId = systemGroup.Id,
                KeyVersion = systemGroup.KeyVersion,
                MemberPublicKey = user.Keys.X25519PublicKey,
                WrappedContentKey = CryptoSyncBootstrap.SerializeWrappedCek(userWrappedKey.WrappedContentKey),
                Role = SyncRole.Viewer,
                GrantedByContactId = adminContact.Id,
                UpdatedAt = DateTime.UtcNow,
                SharingScope = SharingScope.Public,
                SharingId = CryptoSyncBootstrap.SystemSharingId
            };
            admin.Context.ShareTargets.Add(userTargetOnAdmin);
            await admin.Context.SaveChangesAsync();
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(adminPrivKey);
        }

        // 5. Seed user's DB with the rows that would arrive on first sync.
        var userDevice = new DeviceSettings
        {
            Id = Guid.NewGuid(),
            ClientGuid = Guid.NewGuid().ToString(),
            DeviceName = $"{userName} Device",
            IsAdmin = false,
            AdminContactId = adminContact.Id
        };
        user.Context.DeviceSettings.Add(userDevice);

        // Copy contacts (same Ids)
        user.Context.Contacts.Add(new TrustedContact
        {
            Id = adminContact.Id,
            Username = adminContact.Username,
            Email = adminContact.Email,
            Comment = adminContact.Comment,
            X25519PublicKey = adminContact.X25519PublicKey,
            Ed25519PublicKey = adminContact.Ed25519PublicKey,
            IsAdmin = adminContact.IsAdmin,
            IsTrusted = adminContact.IsTrusted,
            UpdatedAt = adminContact.UpdatedAt,
            SharingScope = adminContact.SharingScope,
            SharingId = adminContact.SharingId
        });

        user.Context.Contacts.Add(new TrustedContact
        {
            Id = userContactOnAdmin.Id,
            Username = userContactOnAdmin.Username,
            Email = userContactOnAdmin.Email,
            Comment = userContactOnAdmin.Comment,
            X25519PublicKey = userContactOnAdmin.X25519PublicKey,
            Ed25519PublicKey = userContactOnAdmin.Ed25519PublicKey,
            IsAdmin = userContactOnAdmin.IsAdmin,
            IsTrusted = userContactOnAdmin.IsTrusted,
            UpdatedAt = userContactOnAdmin.UpdatedAt,
            SharingScope = userContactOnAdmin.SharingScope,
            SharingId = userContactOnAdmin.SharingId
        });

        // Copy the system ShareGroup and user's ShareTarget
        user.Context.ShareGroups.Add(new ShareGroup
        {
            Id = systemGroup.Id,
            GroupContext = systemGroup.GroupContext,
            KeyVersion = systemGroup.KeyVersion,
            AdminPublicKey = systemGroup.AdminPublicKey,
            CreatedAt = systemGroup.CreatedAt,
            UpdatedAt = systemGroup.UpdatedAt,
            SharingScope = systemGroup.SharingScope,
            SharingId = systemGroup.SharingId
        });

        user.Context.ShareTargets.Add(new ShareTarget
        {
            Id = userTargetOnAdmin.Id,
            ShareGroupId = userTargetOnAdmin.ShareGroupId,
            KeyVersion = userTargetOnAdmin.KeyVersion,
            MemberPublicKey = userTargetOnAdmin.MemberPublicKey,
            WrappedContentKey = userTargetOnAdmin.WrappedContentKey,
            Role = userTargetOnAdmin.Role,
            GrantedByContactId = userTargetOnAdmin.GrantedByContactId,
            UpdatedAt = userTargetOnAdmin.UpdatedAt,
            SharingScope = userTargetOnAdmin.SharingScope,
            SharingId = userTargetOnAdmin.SharingId
        });

        await user.Context.SaveChangesAsync();

        return new TwoActorBootstrap(admin, user, crypto, groupEncryption);
    }

    public async ValueTask DisposeAsync()
    {
        await Admin.DisposeAsync();
        await User.DisposeAsync();
    }
}
