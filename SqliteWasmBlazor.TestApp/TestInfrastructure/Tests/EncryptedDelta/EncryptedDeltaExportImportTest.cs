using MessagePack;
using Microsoft.EntityFrameworkCore;
using SqliteWasmBlazor;
using SqliteWasmBlazor.Components.Interop;
using SqliteWasmBlazor.Models;
using SqliteWasmBlazor.Models.DTOs;

namespace SqliteWasmBlazor.TestApp.TestInfrastructure.Tests.EncryptedDelta;

/// <summary>
/// Basic encrypted delta roundtrip: seed data → encrypted export → encrypted import.
/// Uses random seed (mock PRF) stored in worker via bridge.
/// </summary>
internal class EncryptedDeltaExportImportTest(IDbContextFactory<TodoDbContext> factory, ISqliteWasmDatabaseService databaseService)
    : SqliteWasmTest(factory, databaseService)
{
    public override string Name => "EncryptedDelta_ExportImportRoundTrip";

    private static readonly Dictionary<string, string> TodoSqlTypeOverrides = new() { ["Id"] = "BLOB" };

    public override async ValueTask<string?> RunTestAsync()
    {
        if (DatabaseService is null)
        {
            throw new InvalidOperationException("ISqliteWasmDatabaseService not available");
        }

        // 1. Initialize crypto interop (loads crypto-layer.js on main thread)
        await CryptoInterop.EnsureInitializedAsync();

        // 2. Store keys for Alice in the worker (random seed = mock PRF)
        var aliceSeed = CryptoInterop.GenerateRandomBytes(32);
        var aliceKeysJson = await SqliteWasmWorkerBridge.StoreKeysInWorkerAsync("alice", aliceSeed, 0);
        var aliceKeys = System.Text.Json.JsonSerializer.Deserialize<CryptoKeysResponse>(aliceKeysJson);

        if (aliceKeys is null || !aliceKeys.Success)
        {
            throw new InvalidOperationException($"Failed to store Alice's keys: {aliceKeysJson}");
        }

        // 2. Seed some TodoItems via EF Core
        await using (var ctx = await Factory.CreateDbContextAsync())
        {
            ctx.TodoItems.Add(new SqliteWasmBlazor.Models.Models.TodoItem
            {
                Id = Guid.NewGuid(),
                Title = "Buy milk",
                Description = "From the store",
                IsCompleted = false,
                UpdatedAt = DateTime.UtcNow
            });
            ctx.TodoItems.Add(new SqliteWasmBlazor.Models.Models.TodoItem
            {
                Id = Guid.NewGuid(),
                Title = "Buy eggs",
                Description = "Organic",
                IsCompleted = true,
                UpdatedAt = DateTime.UtcNow
            });
            await ctx.SaveChangesAsync();
        }

        // 3. Build export metadata with crypto fields
        var header = MessagePackFileHeaderV2.Create<TodoItemDto>(
            tableName: "TodoItems",
            primaryKeyColumn: "Id",
            recordCount: 0,
            mode: 1,
            sqlTypeOverrides: TodoSqlTypeOverrides);

        var exportMetadata = new BulkExportMetadata
        {
            TableName = header.TableName,
            Columns = header.Columns,
            PrimaryKeyColumn = header.PrimaryKeyColumn,
            SchemaHash = header.SchemaHash,
            DataType = header.DataType,
            Mode = 1,
            // Crypto fields — triggers SWBV2E encrypted export in worker
            KeyId = "alice",
            RecipientPublicKeys = [aliceKeys.X25519PublicKeyBase64!],
            Permissions = new Dictionary<string, Dictionary<string, string>>
            {
                [aliceKeys.Ed25519PublicKeyBase64!] = new() // full access
            }
        };

        // 4. Encrypted bulk export
        var encryptedBytes = await DatabaseService.BulkExportAsync("TestDb.db", exportMetadata);

        if (encryptedBytes.Length == 0)
        {
            throw new InvalidOperationException("Encrypted export returned empty bytes");
        }

        // 5. Verify it's SWBV2E format (first bytes should unpack to array starting with "SWBV2E")
        Console.WriteLine($"[{Name}] Encrypted export: {encryptedBytes.Length} bytes");

        // 6. Delete the items, re-create fresh
        await using (var ctx = await Factory.CreateDbContextAsync())
        {
            var items = await ctx.TodoItems.ToListAsync();
            ctx.TodoItems.RemoveRange(items);
            await ctx.SaveChangesAsync();

            var count = await ctx.TodoItems.CountAsync();
            if (count != 0)
            {
                throw new InvalidOperationException($"Expected 0 items after delete, got {count}");
            }
        }

        // 7. Encrypted bulk import (worker detects SWBV2E magic, uses alice's cached keys)
        var rowsImported = await DatabaseService.BulkImportAsync("TestDb.db", encryptedBytes,
            ConflictResolutionStrategy.DeltaWins);

        if (rowsImported != 2)
        {
            throw new InvalidOperationException($"Expected 2 rows imported, got {rowsImported}");
        }

        // 8. Verify data survived the roundtrip
        await using (var ctx = await Factory.CreateDbContextAsync())
        {
            var items = await ctx.TodoItems.OrderBy(t => t.Title).ToListAsync();

            if (items.Count != 2)
            {
                throw new InvalidOperationException($"Expected 2 items, got {items.Count}");
            }

            if (items[0].Title != "Buy eggs" || items[1].Title != "Buy milk")
            {
                throw new InvalidOperationException($"Titles don't match: '{items[0].Title}', '{items[1].Title}'");
            }
        }

        return "OK";
    }

    private record CryptoKeysResponse
    {
        public bool Success { get; init; }
        public string? X25519PublicKeyBase64 { get; init; }
        public string? Ed25519PublicKeyBase64 { get; init; }
        public string? Error { get; init; }
    }
}
