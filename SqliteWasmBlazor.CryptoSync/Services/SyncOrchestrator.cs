using BlazorPRF.Crypto.Abstractions;
using BlazorPRF.Crypto.Abstractions.Models;
using MessagePack;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Orchestrates encrypted delta export and import.
/// Single entry point for app developers — handles crypto, permissions, and BulkImport/Export.
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
    /// <param name="databaseName">Source database filename</param>
    /// <param name="exportMetadata">V2 export metadata (table, columns, etc.)</param>
    /// <param name="senderKeys">Sender's full keypair (from PRF derivation)</param>
    /// <param name="adminKeys">Admin's keypair for signing permissions (often same as sender)</param>
    /// <returns>Serialized EncryptedDelta bytes (MessagePack) ready for relay upload</returns>
    public async ValueTask<byte[]> ExportAsync(
        string databaseName,
        BulkExportMetadata exportMetadata,
        DualKeyPairFull senderKeys,
        DualKeyPairFull adminKeys)
    {
        // 1. BulkExport → plain V2 bytes
        var v2Bytes = await databaseService.BulkExportAsync(databaseName, exportMetadata);

        // 2. Get recipient public keys (all active contacts + self)
        var recipientPks = await contactService.GetRecipientPublicKeysAsync();
        var allRecipients = recipientPks.Append(senderKeys.X25519PublicKey).Distinct().ToArray();

        // 3. Build permission map
        var permissions = await permissionService.GetPermissionMapAsync();
        // Ensure sender is in the permission map
        if (!permissions.ContainsKey(senderKeys.Ed25519PublicKey))
        {
            permissions[senderKeys.Ed25519PublicKey] = new(); // sender has full access
        }

        // 4. Encrypt
        var adminPrivateKey = Convert.FromBase64String(adminKeys.Ed25519PrivateKey);
        var delta = await EncryptedDeltaService.EncryptAsync(
            crypto, v2Bytes, senderKeys, allRecipients,
            permissions, adminPrivateKey, adminKeys.Ed25519PublicKey);

        // 5. Serialize for transport
        return EncryptedDeltaService.Serialize(delta);
    }

    /// <summary>
    /// Import an encrypted delta: decrypt, verify, check permissions, apply.
    /// </summary>
    /// <param name="databaseName">Target database filename</param>
    /// <param name="envelopeBytes">Serialized EncryptedDelta bytes (from relay)</param>
    /// <param name="recipientKeys">This device's keypair for decryption</param>
    /// <param name="allTableColumns">Map of table → all column names (for readonly column resolution)</param>
    /// <param name="conflictStrategy">Conflict resolution for the bulk import</param>
    /// <returns>Number of rows imported</returns>
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

        // 3. Table-level permission check
        var permMap = delta.Permissions;
        // (V2 header peek happens after decryption — we check table-level access then)

        // 4. Decrypt
        var recipientPrivateKey = Convert.FromBase64String(recipientKeys.X25519PrivateKey);
        var v2Bytes = await EncryptedDeltaService.DecryptAsync(
            crypto, delta, recipientPrivateKey, recipientKeys.X25519PublicKey);

        // 5. Peek V2 header for table name
        var header = MessagePackSerializer.Deserialize<object[]>(v2Bytes);
        var tableName = header[7]?.ToString() ?? "";

        // 6. Check sender's table-level permission
        var accessCheck = PermissionHelper.CheckWriteAccess(
            permMap, delta.SenderPublicKey, tableName, []);
        if (!accessCheck.IsAllowed)
        {
            throw new UnauthorizedAccessException($"Sender lacks table access: {accessCheck.Reason}");
        }

        // 7. Build readonly columns for worker-side validation
        var readonlyColumns = await permissionService.BuildReadonlyColumnMapAsync(
            delta.SenderPublicKey, allTableColumns);

        // 8. BulkImport with readonly validation
        return await databaseService.BulkImportAsync(
            databaseName, v2Bytes, conflictStrategy, readonlyColumns);
    }
}
