using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Shared FK-walk helper for soft-deleting an entire <see cref="SyncableEntity"/>
/// subtree. Walks <see cref="IEntityType.GetReferencingForeignKeys"/> downward
/// from a parent row, recursively soft-deleting every descendant whose CLR
/// type inherits <see cref="SyncableEntity"/>. Uses raw SQL via EF model
/// metadata so it stays AOT/trim-safe (no runtime <c>System.Reflection</c>,
/// no dynamic <c>DbSet&lt;&gt;</c> lookups).
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
        var parentEntityType = FindEntityTypeByTable(context, parentTableName)
            ?? throw new InvalidOperationException(
                $"SyncableFkCascade: no entity type mapped to table '{parentTableName}'");
        EnsureSyncableEntity(parentEntityType);

        var visited = new HashSet<(string Table, Guid Id)>();
        var now = DateTime.UtcNow;
        var rowsAffected = 0;

        await WalkAsync(parentEntityType, parentId).ConfigureAwait(false);
        return rowsAffected;

        async Task WalkAsync(IEntityType entityType, Guid rowId)
        {
            var table = entityType.GetTableName()
                ?? throw new InvalidOperationException(
                    $"SyncableFkCascade: entity {entityType.ClrType.Name} has no mapped table");

            if (!visited.Add((table, rowId)))
            {
                return;
            }

            // EF1002 suppressed: `table` comes from EF model metadata, not user input.
#pragma warning disable EF1002
            var affected = await context.Database.ExecuteSqlRawAsync(
                $"UPDATE \"{table}\" SET \"IsDeleted\" = 1, \"DeletedAt\" = {{0}}, \"UpdatedAt\" = {{1}} WHERE \"Id\" = {{2}}",
                [now, now, rowId],
                cancellationToken).ConfigureAwait(false);
#pragma warning restore EF1002
            rowsAffected += affected;

            foreach (var fk in entityType.GetReferencingForeignKeys())
            {
                if (fk.Properties.Count != 1)
                {
                    continue;
                }

                var childType = fk.DeclaringEntityType;
                if (!typeof(SyncableEntity).IsAssignableFrom(childType.ClrType))
                {
                    continue;
                }

                var childTable = childType.GetTableName()
                    ?? throw new InvalidOperationException(
                        $"SyncableFkCascade: child entity {childType.ClrType.Name} has no mapped table");
                var fkColumn = fk.Properties[0].GetColumnName()
                    ?? throw new InvalidOperationException(
                        $"SyncableFkCascade: FK {fk.Properties[0].Name} on {childType.ClrType.Name} has no mapped column");

                // EF1002 suppressed: identifiers come from EF model metadata.
#pragma warning disable EF1002
                var childIds = await context.Database
                    .SqlQueryRaw<Guid>(
                        $"SELECT \"Id\" AS \"Value\" FROM \"{childTable}\" WHERE \"{fkColumn}\" = {{0}} AND \"IsDeleted\" = 0",
                        rowId)
                    .ToListAsync(cancellationToken)
                    .ConfigureAwait(false);
#pragma warning restore EF1002

                foreach (var childId in childIds)
                {
                    await WalkAsync(childType, childId).ConfigureAwait(false);
                }
            }
        }
    }

    internal static IEntityType? FindEntityTypeByTable(CryptoSyncContextBase context, string tableName)
    {
        foreach (var entityType in context.Model.GetEntityTypes())
        {
            if (string.Equals(entityType.GetTableName(), tableName, StringComparison.Ordinal))
            {
                return entityType;
            }
        }
        return null;
    }

    internal static void EnsureSyncableEntity(IEntityType entityType)
    {
        if (!typeof(SyncableEntity).IsAssignableFrom(entityType.ClrType))
        {
            throw new InvalidOperationException(
                $"SyncableFkCascade: entity {entityType.ClrType.Name} does not inherit SyncableEntity — " +
                "only syncable entities can participate in the cascade graph");
        }
    }
}
