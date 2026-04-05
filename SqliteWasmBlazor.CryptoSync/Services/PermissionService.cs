using System.Text.Json;
using Microsoft.EntityFrameworkCore;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Reads permissions from SyncPermission table and builds enforcement structures.
/// </summary>
public class PermissionService(CryptoSyncContextBase context)
{
    /// <summary>
    /// Build the full permission map for EncryptedDeltaService.
    /// Maps each contact's Ed25519 public key → their permission diff.
    /// Contacts without explicit permissions get default (full readwrite = empty dict).
    /// </summary>
    public async ValueTask<Dictionary<string, Dictionary<string, string>>> GetPermissionMapAsync()
    {
        var contacts = await context.Contacts.ToListAsync();
        var permissions = await context.Permissions.ToListAsync();

        var permByRole = permissions
            .GroupBy(p => p.Role)
            .ToDictionary(
                g => g.Key,
                g => MergePermissionDiffs(g.ToList())
            );

        var map = new Dictionary<string, Dictionary<string, string>>();

        foreach (var contact in contacts)
        {
            if (permByRole.TryGetValue(contact.Role, out var diff))
            {
                map[contact.Ed25519PublicKey] = diff;
            }
            else
            {
                map[contact.Ed25519PublicKey] = new(); // default = full access
            }
        }

        return map;
    }

    /// <summary>
    /// Get the SyncRole for a contact identified by Ed25519 public key.
    /// Returns null if contact not found.
    /// </summary>
    public async ValueTask<SyncRole?> GetRoleForContactAsync(string ed25519PublicKey)
    {
        var contact = await context.Contacts.FirstOrDefaultAsync(c => c.Ed25519PublicKey == ed25519PublicKey);
        return contact?.Role;
    }

    /// <summary>
    /// Build the readonlyColumns map for BulkImportAsync.
    /// Given a sender's public key, determines which columns are readonly per table.
    /// </summary>
    public async ValueTask<Dictionary<string, string[]>?> BuildReadonlyColumnMapAsync(
        string senderEd25519PublicKey,
        Dictionary<string, string[]> allTableColumns)
    {
        var contact = await context.Contacts.FirstOrDefaultAsync(c => c.Ed25519PublicKey == senderEd25519PublicKey);
        if (contact is null)
        {
            return null; // Unknown sender
        }

        var permissions = await context.Permissions
            .Where(p => p.Role == contact.Role)
            .ToListAsync();

        if (permissions.Count == 0)
        {
            return null; // No restrictions
        }

        var merged = MergePermissionDiffs(permissions);
        if (merged.Count == 0)
        {
            return null; // Full access
        }

        var result = new Dictionary<string, string[]>();

        foreach (var (tableName, columns) in allTableColumns)
        {
            var readonlyCols = PermissionHelper.GetReadonlyColumns(
                new Dictionary<string, Dictionary<string, string>> { [senderEd25519PublicKey] = merged },
                senderEd25519PublicKey,
                tableName,
                columns);

            if (readonlyCols.Length > 0)
            {
                result[tableName] = readonlyCols;
            }
        }

        return result.Count > 0 ? result : null;
    }

    /// <summary>
    /// Merge multiple SyncPermission rows (same role, different tables) into a single diff.
    /// </summary>
    private static Dictionary<string, string> MergePermissionDiffs(List<SyncPermission> permissions)
    {
        var merged = new Dictionary<string, string>();

        foreach (var perm in permissions)
        {
            var diff = JsonSerializer.Deserialize<Dictionary<string, string>>(perm.PermissionDiffJson);
            if (diff is null)
            {
                continue;
            }

            foreach (var (key, value) in diff)
            {
                merged[key] = value;
            }
        }

        return merged;
    }
}
