using BlazorPRF.Crypto.Abstractions;
using BlazorPRF.Crypto.Abstractions.Models;
using MessagePack;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Orchestrates encrypted delta export and import using dual-table architecture.
///
/// Import flow:
///   1. Decrypt envelope → get plain V2 bytes
///   2. BulkImport into _crypto_ table (raw blob storage, fast)
///   3. Decrypt matching scope rows (this client has the key)
///   4. BulkImport into open table (conflict resolution + readonlyColumns)
///
/// Export flow:
///   1. BulkExport changed rows from open table → plain V2 bytes
///   2. Encrypt V2 bytes → EncryptedDelta envelope
///   3. Serialize for relay upload
///
/// Note: _crypto_ table insert during import is done by the worker alongside
/// the open table insert. The V2 bytes go to the open table; the encrypted
/// blob is stored separately. For now, the crypto table is populated via
/// a second BulkImport call with the encrypted data.
/// </summary>
public class SyncOrchestrator(
    ISqliteWasmDatabaseService databaseService,
    ICryptoProvider crypto,
    ContactService contactService,
    PermissionService permissionService)
{
    /// <summary>
    /// Export data as an encrypted delta for all active contacts.
    /// </summary>
    public async ValueTask<byte[]> ExportAsync(
        string databaseName,
        BulkExportMetadata exportMetadata,
        DualKeyPairFull senderKeys,
        DualKeyPairFull adminKeys)
    {
        // 1. BulkExport from open table → plain V2 bytes
        var v2Bytes = await databaseService.BulkExportAsync(databaseName, exportMetadata);

        // 2. Get recipient public keys (all active contacts + self)
        var recipientPks = await contactService.GetRecipientPublicKeysAsync();
        var allRecipients = recipientPks.Append(senderKeys.X25519PublicKey).Distinct().ToArray();

        // 3. Build permission map
        var permissions = await permissionService.GetPermissionMapAsync();
        if (!permissions.ContainsKey(senderKeys.Ed25519PublicKey))
        {
            permissions[senderKeys.Ed25519PublicKey] = new();
        }

        // 4. Encrypt envelope
        var adminPrivateKey = Convert.FromBase64String(adminKeys.Ed25519PrivateKey);
        var delta = await EncryptedDeltaService.EncryptAsync(
            crypto, v2Bytes, senderKeys, allRecipients,
            permissions, adminPrivateKey, adminKeys.Ed25519PublicKey);

        // 5. Serialize for transport
        return EncryptedDeltaService.Serialize(delta);
    }

    /// <summary>
    /// Import an encrypted delta: decrypt, verify permissions, apply to open table.
    /// </summary>
    public async ValueTask<int> ImportAsync(
        string databaseName,
        byte[] envelopeBytes,
        DualKeyPairFull recipientKeys,
        Dictionary<string, string[]> allTableColumns,
        ConflictResolutionStrategy conflictStrategy = ConflictResolutionStrategy.DeltaWins)
    {
        // 1. Deserialize envelope
        var delta = EncryptedDeltaService.Deserialize(envelopeBytes);

        // 2. Verify sender is a known contact
        var senderContact = await contactService.GetByEd25519PublicKeyAsync(delta.SenderPublicKey);
        if (senderContact is null)
        {
            throw new InvalidOperationException($"Unknown sender: {delta.SenderPublicKey[..16]}...");
        }

        // 3. Decrypt → plain V2 bytes
        var recipientPrivateKey = Convert.FromBase64String(recipientKeys.X25519PrivateKey);
        var v2Bytes = await EncryptedDeltaService.DecryptAsync(
            crypto, delta, recipientPrivateKey, recipientKeys.X25519PublicKey);

        // 4. Peek V2 header for table name
        var header = MessagePackSerializer.Deserialize<object[]>(v2Bytes);
        var tableName = header[7]?.ToString() ?? "";

        // 5. Check sender's table-level permission
        var accessCheck = PermissionHelper.CheckWriteAccess(
            delta.Permissions, delta.SenderPublicKey, tableName, []);
        if (!accessCheck.IsAllowed)
        {
            throw new UnauthorizedAccessException($"Sender lacks table access: {accessCheck.Reason}");
        }

        // 6. Build readonly columns for worker-side validation
        var readonlyColumns = await permissionService.BuildReadonlyColumnMapAsync(
            delta.SenderPublicKey, allTableColumns);

        // 7. BulkImport into open table with conflict resolution + readonly validation
        return await databaseService.BulkImportAsync(
            databaseName, v2Bytes, conflictStrategy, readonlyColumns);
    }

    /// <summary>
    /// Import raw V2 bytes (already decrypted) directly into the open table.
    /// Used for scope changes when re-decrypting rows from _crypto_ table.
    /// </summary>
    public async ValueTask<int> ImportDecryptedAsync(
        string databaseName,
        byte[] v2Bytes,
        ConflictResolutionStrategy conflictStrategy = ConflictResolutionStrategy.DeltaWins)
    {
        return await databaseService.BulkImportAsync(databaseName, v2Bytes, conflictStrategy);
    }
}
