using Microsoft.EntityFrameworkCore;
using SqliteWasmBlazor.Crypto.Abstractions;

namespace SqliteWasmBlazor.TestApp.TestInfrastructure.VfsEncryption;

/// <summary>
/// R3.2 composition test: drive two distinct synthetic PRF seeds → two
/// distinct X25519 pubkey-byte VFS Ks, run the rotation ceremony
/// (ExportDatabaseAsync REKEY → DeleteDatabaseAsync → InstallEncryptionKeyAsync
/// (K_new) → ImportDatabaseAsync), and verify (a) rows survive under K_new,
/// (b) K_old fails verification on the rekeyed slot 0. Validates the rekey
/// primitive end-to-end against the seed → keypair → K chain — the same
/// path SyncEngine will drive when a future KeyRotation API consumes the
/// underlying rekey primitive.
/// </summary>
internal sealed class SyntheticPrfSeedKeyRotationTest
{
    private const int RowCount = 25;
    private const string KeyIdOld = "prf-keys:synthetic-rotate-old";
    private const string KeyIdNew = "prf-keys:synthetic-rotate-new";

    private readonly IDbContextFactory<PrfVfsTestContext> _factory;
    private readonly ISqliteWasmDatabaseService _databaseService;
    private readonly ICryptoProvider _cryptoProvider;

    public string Name => "Synthetic_PrfSeed_KeyRotationPreservesRowsUnderNewKey";

    public SyntheticPrfSeedKeyRotationTest(
        IDbContextFactory<PrfVfsTestContext> factory,
        ISqliteWasmDatabaseService databaseService,
        ICryptoProvider cryptoProvider)
    {
        _factory = factory;
        _databaseService = databaseService;
        _cryptoProvider = cryptoProvider;
    }

    public async ValueTask<string?> RunAsync()
    {
        var dbName = PrfVfsTestContext.DatabaseName;

        await CleanupAsync(dbName);

        // Two distinct synthetic seeds — distinguishable byte patterns so a
        // crossed-wires bug between K_old and K_new would show up obviously.
        var seedOld = new byte[32];
        var seedNew = new byte[32];
        for (var i = 0; i < 32; i++)
        {
            seedOld[i] = (byte)(0x10 + i);
            seedNew[i] = (byte)(0xC0 + i);
        }

        var storeOld = await _cryptoProvider.StoreKeysAsync(KeyIdOld, seedOld, ttlMs: null);
        if (!storeOld.Success || storeOld.Value is null)
        {
            return $"FAIL: StoreKeysAsync(old) returned {storeOld.ErrorCode}";
        }
        var storeNew = await _cryptoProvider.StoreKeysAsync(KeyIdNew, seedNew, ttlMs: null);
        if (!storeNew.Success || storeNew.Value is null)
        {
            return $"FAIL: StoreKeysAsync(new) returned {storeNew.ErrorCode}";
        }

        byte[] kOld;
        byte[] kNew;
        try
        {
            kOld = Convert.FromBase64String(storeOld.Value.X25519PublicKey);
            kNew = Convert.FromBase64String(storeNew.Value.X25519PublicKey);
        }
        catch (FormatException ex)
        {
            return $"FAIL: X25519 pubkey decode failed: {ex.Message}";
        }

        if (kOld.Length != 32 || kNew.Length != 32)
        {
            return $"FAIL: pubkey lengths old={kOld.Length} new={kNew.Length}, expected 32";
        }

        // Sanity check — distinct seeds must yield distinct Ks. A regression
        // that broke the seed → pubkey derivation could collapse the two
        // and silently make the rotation look OK.
        if (kOld.AsSpan().SequenceEqual(kNew))
        {
            return "FAIL: K_old and K_new are identical — seed → pubkey derivation collapsed";
        }

        try
        {
            // Phase 1 — install K_old, write rows.
            if (await _databaseService.InstallEncryptionKeyAsync(dbName, kOld) != VfsKeyInstallResult.NO_EXISTING_DB)
            {
                return "FAIL: phase 1 expected NO_EXISTING_DB";
            }
            await using (var ctx = await _factory.CreateDbContextAsync())
            {
                await ctx.Database.EnsureCreatedAsync();
                for (var i = 0; i < RowCount; i++)
                {
                    ctx.Items.Add(new VfsTestItem
                    {
                        Marker = $"rotate-{i}",
                        Payload = $"payload-{i}-{Guid.NewGuid():N}",
                    });
                }
                await ctx.SaveChangesAsync();
            }

            // Phase 2 — rotate. Export under K_old → re-encrypt under K_new
            // → wipe → install K_new → import rekeyed bytes. Mirrors what
            // PrfVfsTest.razor's "Rotate to pasted pubkey" performs in the
            // browser; here we drive it without WebAuthn.
            var rekeyed = await _databaseService.ExportDatabaseAsync(dbName, VfsExportMode.REKEY, kNew);
            await _databaseService.DeleteDatabaseAsync(dbName);
            await _databaseService.ClearEncryptionKeyAsync(dbName);

            if (await _databaseService.InstallEncryptionKeyAsync(dbName, kNew) != VfsKeyInstallResult.NO_EXISTING_DB)
            {
                return "FAIL: post-wipe install expected NO_EXISTING_DB";
            }
            var importOutcome = await _databaseService.ImportDatabaseAsync(dbName, rekeyed);
            if (importOutcome != VfsImportResult.OK)
            {
                return $"FAIL: rekey import expected OK, got {importOutcome}";
            }

            // Phase 3 — read rows back under K_new.
            List<VfsTestItem> rows;
            await using (var ctx = await _factory.CreateDbContextAsync())
            {
                rows = await ctx.Items.OrderBy(x => x.Id).ToListAsync();
            }
            if (rows.Count != RowCount)
            {
                return $"FAIL: expected {RowCount} rows under K_new, got {rows.Count}";
            }
            for (var i = 0; i < RowCount; i++)
            {
                if (rows[i].Marker != $"rotate-{i}")
                {
                    return $"FAIL: row {i} Marker mismatch (got '{rows[i].Marker}')";
                }
            }

            // Phase 4 — confirm K_old now fails verification. Must close +
            // clear first because slot 0 was authenticated under K_new in
            // phase 2; without the clear the worker sees the existing
            // registry entry and skips re-verification.
            await _databaseService.CloseDatabaseAsync(dbName);
            await _databaseService.ClearEncryptionKeyAsync(dbName);
            var oldOutcome = await _databaseService.InstallEncryptionKeyAsync(dbName, kOld);
            if (oldOutcome != VfsKeyInstallResult.WRONG_KEY)
            {
                return $"FAIL: K_old after rotation expected WRONG_KEY, got {oldOutcome}";
            }

            return "OK";
        }
        finally
        {
            _cryptoProvider.RemoveCachedKey(KeyIdOld);
            _cryptoProvider.RemoveCachedKey(KeyIdNew);
            await CleanupAsync(dbName);
            Array.Clear(kOld, 0, kOld.Length);
            Array.Clear(kNew, 0, kNew.Length);
            Array.Clear(seedOld, 0, seedOld.Length);
            Array.Clear(seedNew, 0, seedNew.Length);
        }
    }

    private async Task CleanupAsync(string dbName)
    {
        try { await _databaseService.CloseDatabaseAsync(dbName); } catch { }
        try { await _databaseService.ClearEncryptionKeyAsync(dbName); } catch { }
        try { await _databaseService.DeleteDatabaseAsync(dbName); } catch { }
    }
}
