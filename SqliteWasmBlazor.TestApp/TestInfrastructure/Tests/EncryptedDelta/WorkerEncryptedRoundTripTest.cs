using SqliteWasmBlazor.TestApp.TestInfrastructure.CryptoSync;
using Microsoft.EntityFrameworkCore;

namespace SqliteWasmBlazor.TestApp.TestInfrastructure.Tests.EncryptedDelta;

/// <summary>
/// Worker-side V2 encrypted roundtrip: export with crypto-core key derivation
/// (ECDH + HKDF + AES-GCM with AAD) → import with tamper detection → verify.
///
/// TODO: Wire V2CryptoHeader + BulkExportEncryptedV2Async + BulkImportEncryptedV2Async
/// once the full ShareGroup/ShareTarget bootstrap is available in the TestApp context.
/// </summary>
internal class WorkerEncryptedRoundTripTest(
    IDbContextFactory<CryptoTestContext> cryptoFactory,
    ISqliteWasmDatabaseService databaseService)
    : CryptoSyncTestBase(cryptoFactory, databaseService)
{
    public override string Name => "CryptoSync_WorkerEncryptedRoundTrip";

    public override ValueTask<string?> RunTestAsync()
    {
        // Pending V2 orchestrator wiring — the V1 API (BulkExportEncryptedAsync /
        // BulkImportEncryptedAsync) has been removed. This test needs ShareGroup +
        // ShareTarget bootstrap + V2CryptoHeader construction to work.
        return new ValueTask<string?>("PENDING: V2 crypto-core integration — awaiting orchestrator wiring");
    }
}
