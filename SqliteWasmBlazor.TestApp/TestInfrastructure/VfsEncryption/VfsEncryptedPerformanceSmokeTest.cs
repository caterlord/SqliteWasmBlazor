using Microsoft.EntityFrameworkCore;
using SqliteWasmBlazor.Models;
using SqliteWasmBlazor.Models.Models;
using System.Diagnostics;

namespace SqliteWasmBlazor.TestApp.TestInfrastructure.VfsEncryption;

/// <summary>
/// Default-configuration perf smoke: plain DB vs encrypted DB, both in
/// <c>journal_mode=WAL</c> — the vendor default, and also the default
/// for encrypted DBs because the VFS encrypts WAL frames with the same
/// envelope as the main DB.
///
/// This measures what a user actually experiences with default settings.
/// Because both paths share the same journal mode, the ratio is dominated
/// by page-level AEAD cost; this test and
/// <see cref="VfsSameJournalModePerformanceTest"/> overlap considerably.
///
/// Fails only on a catastrophic slowdown (encrypted &gt; 10× plain).
/// </summary>
internal sealed class VfsEncryptedPerformanceSmokeTest
{
    // 500 rows × ~200 bytes ≈ 100 KB, comfortably multi-page for both plain
    // and encrypted. Higher counts produce exponentially more EF Core
    // ChangeTracking log events in Debug builds (EnableSensitiveDataLogging
    // + LogTo Console) and make the page look unresponsive while the
    // JSInterop-backed console catches up. 500 is enough signal to catch
    // catastrophic slowdowns without drowning the DevTools console.
    private const int RowCount = 500;
    private const double CatastrophicRatio = 10.0;

    private readonly IDbContextFactory<TodoDbContext> _plainFactory;
    private readonly IDbContextFactory<EncryptedTestContext> _encFactory;
    private readonly ISqliteWasmDatabaseService _databaseService;

    public VfsEncryptedPerformanceSmokeTest(
        IDbContextFactory<TodoDbContext> plainFactory,
        IDbContextFactory<EncryptedTestContext> encFactory,
        ISqliteWasmDatabaseService databaseService)
    {
        _plainFactory = plainFactory;
        _encFactory = encFactory;
        _databaseService = databaseService;
    }

    public string Name => "VFS_PerformanceSmoke";

    public async ValueTask<string?> RunTestWithFreshDatabaseAsync()
    {
        await using (var ctx = await _plainFactory.CreateDbContextAsync())
        {
            await ctx.Database.EnsureDeletedAsync();
            await ctx.Database.EnsureCreatedAsync();
        }
        await using (var ctx = await _encFactory.CreateDbContextAsync())
        {
            await ctx.Database.EnsureDeletedAsync();
            await ctx.Database.EnsureCreatedAsync();
        }

        return await RunTestAsync();
    }

    private async Task<string?> RunTestAsync()
    {
        var plainMs = await MeasureAsync(async () =>
        {
            await using var ctx = await _plainFactory.CreateDbContextAsync();
            // N^2 → N on the bulk add path. StartedTracking events still
            // fire per entity, but change-detection no longer reruns on
            // every Add — shaves real time off the measurement.
            ctx.ChangeTracker.AutoDetectChangesEnabled = false;
            var listId = Guid.NewGuid();
            ctx.TodoLists.Add(new TodoList
            {
                Id = listId,
                Title = "perf-list",
                IsActive = true,
                CreatedAt = DateTime.UtcNow,
            });
            for (var i = 0; i < RowCount; i++)
            {
                ctx.Todos.Add(new Todo { Title = $"todo-{i}", Description = new string('x', 200), TodoListId = listId });
            }
            ctx.ChangeTracker.DetectChanges();
            await ctx.SaveChangesAsync();
        });

        var encMs = await MeasureAsync(async () =>
        {
            await using var ctx = await _encFactory.CreateDbContextAsync();
            ctx.ChangeTracker.AutoDetectChangesEnabled = false;
            for (var i = 0; i < RowCount; i++)
            {
                ctx.Items.Add(new VfsTestItem { Marker = $"item-{i}", Payload = new string('x', 200) });
            }
            ctx.ChangeTracker.DetectChanges();
            await ctx.SaveChangesAsync();
        });

        var ratio = plainMs > 0 ? (double)encMs / plainMs : double.PositiveInfinity;

        Console.WriteLine(
            $"[{Name}] plain={plainMs} ms (WAL), encrypted={encMs} ms (WAL), " +
            $"ratio={ratio:F2}× ({RowCount} rows each) — default modes are " +
            $"WAL on both sides");

        if (ratio > CatastrophicRatio)
        {
            return $"Encrypted path {ratio:F1}× slower than plain (plain={plainMs}ms, enc={encMs}ms) — exceeds {CatastrophicRatio}× tolerance";
        }

        return null;
    }

    private static async Task<long> MeasureAsync(Func<Task> body)
    {
        var sw = Stopwatch.StartNew();
        await body();
        sw.Stop();
        return sw.ElapsedMilliseconds;
    }
}
