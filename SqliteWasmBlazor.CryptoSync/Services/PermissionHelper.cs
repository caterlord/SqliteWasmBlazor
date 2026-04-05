using System.Security.Cryptography;
using System.Text;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Permission utilities for encrypted delta sync.
/// Permission format: default = full readwrite, only diffs stored:
/// - "Table": "readonly" — whole table readonly
/// - "Table.Column": "readwrite" — column override within readonly table
/// - {} = full access
/// </summary>
public static class PermissionHelper
{
    /// <summary>
    /// Compute a deterministic SHA-256 hash of a permission map.
    /// Keys sorted for canonical ordering — must match the TS implementation.
    /// </summary>
    public static byte[] HashPermissions(Dictionary<string, Dictionary<string, string>> permissions)
    {
        using var ms = new MemoryStream();

        foreach (var pk in permissions.Keys.Order(StringComparer.Ordinal))
        {
            ms.Write(Encoding.UTF8.GetBytes(pk));

            var diff = permissions[pk];
            foreach (var key in diff.Keys.Order(StringComparer.Ordinal))
            {
                ms.Write(Encoding.UTF8.GetBytes(key));
                ms.Write(Encoding.UTF8.GetBytes(diff[key]));
            }
        }

        return SHA256.HashData(ms.ToArray());
    }

    /// <summary>
    /// Check if a sender has write access to a table/columns per the permission map.
    /// </summary>
    public static PermissionCheckResult CheckWriteAccess(
        Dictionary<string, Dictionary<string, string>> permissions,
        string senderEd25519PublicKey,
        string tableName,
        string[] columnNames)
    {
        if (!permissions.TryGetValue(senderEd25519PublicKey, out var diff))
        {
            return PermissionCheckResult.Rejected($"Sender '{senderEd25519PublicKey}' not in permissions");
        }

        if (diff.Count == 0)
        {
            return PermissionCheckResult.Allowed();
        }

        if (!diff.TryGetValue(tableName, out var tablePermission))
        {
            return PermissionCheckResult.Allowed(); // No restriction on this table
        }

        if (tablePermission == "readonly")
        {
            foreach (var col in columnNames)
            {
                var colKey = $"{tableName}.{col}";
                if (!diff.TryGetValue(colKey, out var colPermission) || colPermission != "readwrite")
                {
                    return PermissionCheckResult.Rejected($"Column '{col}' on table '{tableName}' is readonly for sender");
                }
            }
        }

        return PermissionCheckResult.Allowed();
    }

    /// <summary>
    /// Extract readonly columns for a specific table from the sender's permission diff.
    /// Returns the column names that are readonly (for worker-side validation).
    /// </summary>
    public static string[] GetReadonlyColumns(
        Dictionary<string, Dictionary<string, string>> permissions,
        string senderEd25519PublicKey,
        string tableName,
        string[] allColumns)
    {
        if (!permissions.TryGetValue(senderEd25519PublicKey, out var diff))
        {
            return []; // Unknown sender — all columns treated as readonly (handled elsewhere)
        }

        if (diff.Count == 0)
        {
            return []; // Full access
        }

        if (!diff.TryGetValue(tableName, out var tablePermission) || tablePermission != "readonly")
        {
            return []; // Table is not readonly
        }

        // Table is readonly — find columns NOT overridden as readwrite
        return allColumns
            .Where(col => !diff.TryGetValue($"{tableName}.{col}", out var colPerm) || colPerm != "readwrite")
            .ToArray();
    }
}

public record PermissionCheckResult
{
    public bool IsAllowed { get; init; }
    public string? Reason { get; init; }

    public static PermissionCheckResult Allowed() => new() { IsAllowed = true };
    public static PermissionCheckResult Rejected(string reason) => new() { IsAllowed = false, Reason = reason };
}
