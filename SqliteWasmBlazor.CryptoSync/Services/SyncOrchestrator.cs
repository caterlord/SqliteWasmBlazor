using BlazorPRF.Crypto.Abstractions;
using BlazorPRF.Crypto.Abstractions.Models;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Orchestrates encrypted delta export and import using the dual-table architecture.
///
/// <para>
/// Phase D-1: still C#-side encrypt/decrypt of the V2 payload via
/// <see cref="EncryptedDeltaService"/>; the worker only handles plain V2 bytes.
/// Phase D-2 will move the symmetric crypto into the worker
/// (<c>BulkExportEncryptedAsync</c> / <c>BulkImportEncryptedAsync</c>) and reduce
/// this orchestrator to envelope assembly + ECIES wrap/unwrap.
/// Phase D-3 adds in-transaction permission enforcement inside the worker.
/// </para>
///
/// <para>
/// Permissions are no longer shipped in the envelope (decision §6). Receivers will
/// enforce permissions by querying the locally-applied <c>SyncPermission</c> table
/// during the staggered apply pass.
/// </para>
/// </summary>
public class SyncOrchestrator(
    ISqliteWasmDatabaseService databaseService,
    ICryptoProvider crypto,
    ContactService contactService)
{
    /// <summary>
    /// Export data as an encrypted delta for all recipients.
    /// </summary>
    public async ValueTask<byte[]> ExportAsync(
        string databaseName,
        BulkExportMetadata exportMetadata,
        DualKeyPairFull senderKeys)
    {
        // 1. BulkExport from open table → plain V2 bytes
        var v2Bytes = await databaseService.BulkExportAsync(databaseName, exportMetadata);

        // 2. Get recipient public keys (all active contacts + self for round-trip)
        var recipientPks = await contactService.GetRecipientPublicKeysAsync();
        var allRecipients = recipientPks.Append(senderKeys.X25519PublicKey).Distinct().ToArray();

        // 3. Encrypt envelope (no permissions payload — decision §6)
        var delta = await EncryptedDeltaService.EncryptAsync(
            crypto, v2Bytes, senderKeys, allRecipients);

        // 4. Serialize for transport
        return EncryptedDeltaService.Serialize(delta);
    }

    /// <summary>
    /// Import an encrypted delta: decrypt and apply to the local database.
    /// Permission enforcement will move into the worker in Phase D-3.
    /// </summary>
    public async ValueTask<int> ImportAsync(
        string databaseName,
        byte[] envelopeBytes,
        DualKeyPairFull recipientKeys,
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

        // 4. Apply to open table. Permission enforcement is deferred to Phase D-3
        //    (in-transaction SQL lookup against SyncPermission inside the worker).
        return await databaseService.BulkImportAsync(databaseName, v2Bytes, conflictStrategy);
    }

    /// <summary>
    /// Import raw V2 bytes (already decrypted) directly into the open table.
    /// Used for scope changes when re-decrypting rows from the _crypto_ table.
    /// </summary>
    public async ValueTask<int> ImportDecryptedAsync(
        string databaseName,
        byte[] v2Bytes,
        ConflictResolutionStrategy conflictStrategy = ConflictResolutionStrategy.DeltaWins)
    {
        return await databaseService.BulkImportAsync(databaseName, v2Bytes, conflictStrategy);
    }
}
