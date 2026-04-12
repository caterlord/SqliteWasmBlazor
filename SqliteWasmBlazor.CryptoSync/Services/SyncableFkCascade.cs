using Microsoft.EntityFrameworkCore;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Shared FK-walk helper for soft-deleting an entire <see cref="SyncableEntity"/>
/// subtree. Uses the generator-emitted <c>SyncableFkMap</c> for compile-time FK
/// discovery — no runtime EF metadata walks, no <c>System.Reflection</c>,
/// AOT/trim-safe.
///
/// <para>
/// Used by both:
/// </para>
/// <list type="bullet">
///   <item><see cref="SharingService.UnshareAsync"/> — application-level
///     "soft-delete this list and everything under it".</item>
///   <item><see cref="CryptoSyncSaveChangesInterceptor"/>'s <c>Deleted</c>
///     branch — converts an EF <c>Remove()</c> on a parent row into a
///     subtree soft-delete in one save batch.</item>
/// </list>
/// </summary>
public static class SyncableFkCascade
{
    /// <summary>
    /// Soft-delete the row identified by (<paramref name="parentTableName"/>,
    /// <paramref name="parentId"/>) and every descendant reachable via
    /// foreign keys. Sets <c>IsDeleted = true</c>, <c>DeletedAt = now</c>,
    /// <c>UpdatedAt = now</c> on each row. Returns the total number of rows
    /// updated (parent + descendants).
    /// </summary>
    public static async Task<int> SoftDeleteSubtreeAsync(
        CryptoSyncContextBase context,
        string parentTableName,
        Guid parentId,
        CancellationToken cancellationToken = default)
    {
        var visited = new HashSet<(string Table, Guid Id)>();
        var now = DateTime.UtcNow;
        var rowsAffected = 0;

        await WalkAsync(parentTableName, parentId).ConfigureAwait(false);
        return rowsAffected;

        async Task WalkAsync(string tableName, Guid rowId)
        {
            if (!visited.Add((tableName, rowId)))
            {
                return;
            }

#pragma warning disable EF1002
            var affected = await context.Database.ExecuteSqlRawAsync(
                $"UPDATE \"{tableName}\" SET \"IsDeleted\" = 1, \"DeletedAt\" = {{0}}, \"UpdatedAt\" = {{1}} WHERE \"Id\" = {{2}} AND \"IsDeleted\" = 0",
                [now, now, rowId],
                cancellationToken).ConfigureAwait(false);
#pragma warning restore EF1002
            rowsAffected += affected;

            var children = context.GetChildFkRelations(tableName);
            foreach (var child in children)
            {
#pragma warning disable EF1002
                var childIds = await context.Database
                    .SqlQueryRaw<Guid>(
                        $"SELECT \"Id\" AS \"Value\" FROM \"{child.ChildTable}\" WHERE \"{child.FkColumn}\" = {{0}} AND \"IsDeleted\" = 0",
                        rowId)
                    .ToListAsync(cancellationToken)
                    .ConfigureAwait(false);
#pragma warning restore EF1002

                foreach (var childId in childIds)
                {
                    await WalkAsync(child.ChildTable, childId).ConfigureAwait(false);
                }
            }
        }
    }
}
