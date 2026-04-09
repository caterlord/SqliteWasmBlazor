using BlazorPRF.Crypto.Abstractions;
using BlazorPRF.Crypto.Abstractions.Models;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Bridge between the C# domain layer and the worker's encrypted bulk
/// import/export. The worker owns all symmetric crypto (AES-GCM with AAD),
/// key derivation (ECDH + HKDF via crypto-core), Ed25519 signing/verification,
/// and tamper detection enforcement. C# handles transport orchestration,
/// DeltaEnvelope serialization, and ShareGroup/ShareTarget lookup.
///
/// <para>
/// Stage D will wire the full V2 flow:
///   Export: V2CryptoHeader → worker export → ShadowRowGroup → DeltaEnvelope
///   Import: DeltaEnvelope → V2CryptoHeader + groups → worker import → ImportReport
/// </para>
///
/// <para>
/// This is a compile-green placeholder after the SharingKey/EncryptedDelta/EnvelopeBytes
/// deletions in Stage B. Full implementation lands in Stage D.
/// </para>
/// </summary>
public class SyncOrchestrator(
    ISqliteWasmDatabaseService databaseService,
    ICryptoProvider crypto,
    ContactService contactService)
{
    /// <summary>
    /// Export data as an encrypted delta for all contacts plus self (round-trip).
    /// Stage D: will build DeltaEnvelope from V2 worker export results.
    /// </summary>
    public ValueTask<byte[]> ExportAsync(
        string databaseName,
        BulkExportMetadata exportMetadata,
        DualKeyPairFull senderKeys)
    {
        // TODO Stage D: wire V2CryptoHeader → BulkExportEncryptedV2Async → DeltaEnvelope
        throw new NotImplementedException("SyncOrchestrator.ExportAsync — pending Stage D rewire");
    }

    /// <summary>
    /// Import an encrypted delta: verify sender, derive keys, apply with tamper detection.
    /// Stage D: will return ImportReport instead of raw int.
    /// </summary>
    public ValueTask<ImportReport> ImportAsync(
        string databaseName,
        byte[] envelopeBytes,
        DualKeyPairFull recipientKeys,
        ConflictResolutionStrategy conflictStrategy = ConflictResolutionStrategy.DeltaWins)
    {
        // TODO Stage D: wire DeltaEnvelope → V2CryptoHeader → BulkImportEncryptedV2Async → ImportReport
        throw new NotImplementedException("SyncOrchestrator.ImportAsync — pending Stage D rewire");
    }
}
