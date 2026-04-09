using System.Security.Cryptography;
using BlazorPRF.Crypto.Abstractions;
using BlazorPRF.Crypto.Abstractions.Models;
using BlazorPRF.Crypto.Abstractions.Services;
using Microsoft.EntityFrameworkCore;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// First-launch scaffolding for a CryptoSync admin instance. Idempotent.
///
/// <para>
/// Creates everything needed for a functional admin: <see cref="DeviceSettings"/>,
/// the admin's own <see cref="TrustedContact"/>, a system <see cref="ShareGroup"/>,
/// and a self-<see cref="ShareTarget"/> (the admin is the sole member of the system
/// group — self-group pattern per PDF spec).
/// </para>
///
/// <para>
/// Uses <see cref="IGroupEncryption.CreateGroupKeysAsync"/> to generate a random CEK
/// and wrap it for the admin. The wrapped CEK is stored in <see cref="ShareTarget.WrappedContentKey"/>
/// as raw bytes: <c>[nonce(12) | ciphertext]</c>.
/// </para>
/// </summary>
public class CryptoSyncBootstrap(
    CryptoSyncContextBase context,
    IGroupEncryption groupEncryption)
{
    /// <summary>Well-known group context for the system scope (v1).</summary>
    public const string SystemGroupContext = "system:v1";

    /// <summary>Well-known SharingId for the system scope.</summary>
    public const string SystemSharingId = "system";

    /// <summary>
    /// Initialize this device as the admin instance.
    /// </summary>
    public async ValueTask<TrustedContact> InitializeAdminAsync(
        DualKeyPairFull adminKeys,
        string adminUsername,
        string adminEmail,
        string deviceName)
    {
        // ---- Idempotency check ----
        var existingDevice = await context.DeviceSettings.FirstOrDefaultAsync();
        if (existingDevice is { IsAdmin: true })
        {
            var existingAdmin = await context.Contacts
                .FirstOrDefaultAsync(c => c.Ed25519PublicKey == adminKeys.Ed25519PublicKey);
            if (existingAdmin is not null)
            {
                return existingAdmin;
            }
        }

        var now = DateTime.UtcNow;

        // ---- 1. DeviceSettings ----
        if (existingDevice is null)
        {
            existingDevice = new DeviceSettings
            {
                Id = Guid.NewGuid(),
                ClientGuid = Guid.NewGuid().ToString(),
                DeviceName = deviceName,
                IsAdmin = true
            };
            context.DeviceSettings.Add(existingDevice);
        }
        else
        {
            existingDevice.IsAdmin = true;
            existingDevice.DeviceName = deviceName;
        }

        // ---- 2. Admin's own TrustedContact row ----
        var adminContact = new TrustedContact
        {
            Id = Guid.NewGuid(),
            Username = adminUsername,
            Email = adminEmail,
            X25519PublicKey = adminKeys.X25519PublicKey,
            Ed25519PublicKey = adminKeys.Ed25519PublicKey,
            Role = SyncRole.Owner,
            TrustLevel = TrustLevel.Full,
            Direction = TrustDirection.Sent,
            VerifiedAt = now,
            UpdatedAt = now,
            SharingScope = SharingScope.Public,
            SharingId = SystemSharingId
        };
        context.Contacts.Add(adminContact);

        existingDevice.AdminContactId = adminContact.Id;

        // ---- 3. System ShareGroup + admin self-ShareTarget ----
        var adminPrivateKeyBytes = Convert.FromBase64String(adminKeys.X25519PrivateKey);

        try
        {
            var createResult = await groupEncryption.CreateGroupKeysAsync(
                adminPrivateKeyBytes,
                adminKeys.X25519PublicKey,
                [adminKeys.X25519PublicKey], // self-group: admin is sole member
                SystemGroupContext);

            if (!createResult.Success)
            {
                throw new InvalidOperationException(
                    $"Failed to create system group keys: {createResult.ErrorCode}");
            }

            var bundle = createResult.Value
                ?? throw new InvalidOperationException("CreateGroupKeysAsync returned null bundle");

            // ShareGroup — the system scope group
            var shareGroup = new ShareGroup
            {
                Id = Guid.NewGuid(),
                GroupContext = SystemGroupContext,
                KeyVersion = bundle.KeyVersion,
                AdminPublicKey = adminKeys.X25519PublicKey,
                CreatedAt = now,
                UpdatedAt = now,
                SharingScope = SharingScope.Public,
                SharingId = SystemSharingId
            };
            context.ShareGroups.Add(shareGroup);

            // ShareTarget — admin's own wrapped CEK (self-group pattern)
            if (bundle.MemberKeys.Count == 0)
            {
                throw new InvalidOperationException("CreateGroupKeysAsync returned empty MemberKeys");
            }
            var adminWrappedKey = bundle.MemberKeys[0];

            var shareTarget = new ShareTarget
            {
                Id = Guid.NewGuid(),
                ShareGroupId = shareGroup.Id,
                KeyVersion = bundle.KeyVersion,
                MemberPublicKey = adminKeys.X25519PublicKey,
                WrappedContentKey = SerializeWrappedCek(adminWrappedKey.WrappedContentKey),
                Role = SyncRole.Owner,
                GrantedByContactId = adminContact.Id,
                UpdatedAt = now,
                SharingScope = SharingScope.Public,
                SharingId = SystemSharingId
            };
            context.ShareTargets.Add(shareTarget);

            await context.SaveChangesAsync();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(adminPrivateKeyBytes);
        }

        return adminContact;
    }

    /// <summary>
    /// Serialize a <see cref="SymmetricEncryptedData"/> (Base64 ciphertext + nonce)
    /// into the raw byte[] format used for <see cref="ShareTarget.WrappedContentKey"/>:
    /// <c>[nonce(12) | ciphertext]</c>.
    /// </summary>
    public static byte[] SerializeWrappedCek(SymmetricEncryptedData wrapped)
    {
        var nonce = Convert.FromBase64String(wrapped.Nonce);
        var ciphertext = Convert.FromBase64String(wrapped.Ciphertext);
        var result = new byte[nonce.Length + ciphertext.Length];
        nonce.CopyTo(result.AsSpan());
        ciphertext.CopyTo(result.AsSpan(nonce.Length));
        return result;
    }

    /// <summary>
    /// Deserialize the raw byte[] format back into a <see cref="SymmetricEncryptedData"/>.
    /// Inverse of <see cref="SerializeWrappedCek"/>.
    /// </summary>
    public static SymmetricEncryptedData DeserializeWrappedCek(byte[] data)
    {
        if (data.Length < 12)
        {
            throw new ArgumentException("WrappedContentKey must be at least 12 bytes (nonce)");
        }
        var nonce = Convert.ToBase64String(data.AsSpan(0, 12));
        var ciphertext = Convert.ToBase64String(data.AsSpan(12));
        return new SymmetricEncryptedData(ciphertext, nonce);
    }
}
