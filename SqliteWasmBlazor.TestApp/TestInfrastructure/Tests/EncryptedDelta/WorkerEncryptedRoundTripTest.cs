using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using SqliteWasmBlazor.Components.Interop;
using SqliteWasmBlazor.CryptoSync;
using SqliteWasmBlazor.TestApp.TestInfrastructure.CryptoSync;

namespace SqliteWasmBlazor.TestApp.TestInfrastructure.Tests.EncryptedDelta;

/// <summary>
/// Worker-side encrypted roundtrip: export with content key (worker encrypts) →
/// import with content key (worker decrypts). Plain V2 bytes never leave the worker.
/// </summary>
internal class WorkerEncryptedRoundTripTest(
    IDbContextFactory<CryptoTestContext> cryptoFactory,
    ISqliteWasmDatabaseService databaseService)
    : CryptoSyncTestBase(cryptoFactory, databaseService)
{
    public override string Name => "CryptoSync_WorkerEncryptedRoundTrip";

    public override async ValueTask<string?> RunTestAsync()
    {
        if (DatabaseService is null)
        {
            throw new InvalidOperationException("ISqliteWasmDatabaseService not available");
        }

        // 1. Seed test items
        var item1Id = Guid.NewGuid();
        var item2Id = Guid.NewGuid();
        await using (var ctx = await CryptoFactory.CreateDbContextAsync())
        {
            ctx.CryptoTestItems.Add(new CryptoTestItem
            {
                Id = item1Id, Title = "Milk", Description = "2L", Price = 1.99m,
                IsBought = false, SharingScope = SharingScope.Public, SharingId = "list-1",
                UpdatedAt = DateTime.UtcNow
            });
            ctx.CryptoTestItems.Add(new CryptoTestItem
            {
                Id = item2Id, Title = "Eggs", Description = "12pk", Price = 3.49m,
                IsBought = true, SharingScope = SharingScope.Public, SharingId = "list-1",
                UpdatedAt = DateTime.UtcNow
            });
            await ctx.SaveChangesAsync();
        }

        // 2. Generate content key (would come from ECIES in production)
        var contentKey = new byte[32];
        RandomNumberGenerator.Fill(contentKey);

        // 3. Encrypted export — worker encrypts, plain V2 never leaves worker
        var exportMetadata = new BulkExportMetadata
        {
            TableName = "CryptoTestItems",
            Columns = MessagePackFileHeaderV2.Create<CryptoTestItemDto>(
                tableName: "CryptoTestItems", primaryKeyColumn: "Id",
                recordCount: 0, mode: 1,
                sqlTypeOverrides: new Dictionary<string, string> { ["Id"] = "BLOB" }).Columns,
            PrimaryKeyColumn = "Id",
            SchemaHash = "test",
            DataType = "CryptoTestItem",
            Mode = 1
        };

        var (encryptedBlob, nonce) = await DatabaseService.BulkExportEncryptedAsync(
            CryptoDatabaseName, exportMetadata, contentKey);

        Console.WriteLine($"[{Name}] Encrypted export: {encryptedBlob.Length} bytes, nonce: {nonce.Length} bytes");

        if (encryptedBlob.Length == 0)
        {
            throw new InvalidOperationException("Encrypted export returned empty blob");
        }

        // 4. Delete items
        await using (var ctx = await CryptoFactory.CreateDbContextAsync())
        {
            ctx.CryptoTestItems.RemoveRange(await ctx.CryptoTestItems.ToListAsync());
            await ctx.SaveChangesAsync();
        }

        // 5. Encrypted import — worker decrypts + inserts
        // Need fresh content key (same value — in production this comes from ECIES unwrap)
        var importKey = new byte[32];
        contentKey.CopyTo(importKey.AsSpan());

        var rowsImported = await DatabaseService.BulkImportEncryptedAsync(
            CryptoDatabaseName, encryptedBlob, nonce, importKey,
            ConflictResolutionStrategy.DeltaWins);

        // Zero keys
        CryptographicOperations.ZeroMemory(contentKey);
        CryptographicOperations.ZeroMemory(importKey);

        if (rowsImported != 2)
        {
            throw new InvalidOperationException($"Expected 2 rows, got {rowsImported}");
        }

        // 6. Verify roundtrip
        await using (var ctx = await CryptoFactory.CreateDbContextAsync())
        {
            var items = await ctx.CryptoTestItems.OrderBy(i => i.Title).ToListAsync();
            if (items.Count != 2)
            {
                throw new InvalidOperationException($"Expected 2 items, got {items.Count}");
            }
            if (items[0].Title != "Eggs" || items[1].Title != "Milk")
            {
                throw new InvalidOperationException($"Titles: '{items[0].Title}', '{items[1].Title}'");
            }
            if (items[0].Price != 3.49m || items[1].Price != 1.99m)
            {
                throw new InvalidOperationException($"Prices: {items[0].Price}, {items[1].Price}");
            }
        }

        return "OK";
    }
}
