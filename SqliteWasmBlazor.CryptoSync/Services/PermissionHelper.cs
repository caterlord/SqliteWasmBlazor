using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Canonical hashing for permission diff data.
///
/// <para>
/// The runtime permission enforcement (CheckWriteAccess / GetReadonlyColumns) lives
/// in the TS worker — see <c>permission-check.ts</c>. This C# helper now exists
/// solely to compute the canonical hash that the admin signs when persisting a
/// <see cref="SyncPermission"/> row, and that the worker re-computes to verify
/// the admin signature on incoming permission updates.
/// </para>
///
/// <para>
/// Format (PermissionDiffSchemaVersion 2): nested per-table diff
/// <c>{ "Tbl": { "delete": "deny", "insert": "deny", "columns": { "Price": "readonly" } } }</c>.
/// Owner full-access emits <c>{}</c>.
/// </para>
/// </summary>
public static class PermissionHelper
{
    /// <summary>
    /// Compute a deterministic SHA-256 hash of a single PermissionDiffJson string.
    /// The TS worker MUST produce the same bytes for the same input.
    ///
    /// <para>
    /// Canonicalization: parse the JSON, walk keys in <see cref="StringComparer.Ordinal"/>
    /// order at every level, and write the canonical UTF-8 form before hashing.
    /// This ensures reordered-but-equivalent JSON produces the same hash.
    /// </para>
    /// </summary>
    public static byte[] HashPermissionDiff(string permissionDiffJson)
    {
        using var doc = JsonDocument.Parse(permissionDiffJson);
        using var ms = new MemoryStream();
        WriteCanonical(doc.RootElement, ms);
        return SHA256.HashData(ms.ToArray());
    }

    private static void WriteCanonical(JsonElement element, Stream output)
    {
        switch (element.ValueKind)
        {
            case JsonValueKind.Object:
                output.WriteByte((byte)'{');
                var keys = new List<string>();
                foreach (var prop in element.EnumerateObject())
                {
                    keys.Add(prop.Name);
                }
                keys.Sort(StringComparer.Ordinal);
                var first = true;
                foreach (var key in keys)
                {
                    if (!first) output.WriteByte((byte)',');
                    first = false;
                    output.WriteByte((byte)'"');
                    output.Write(Encoding.UTF8.GetBytes(key));
                    output.WriteByte((byte)'"');
                    output.WriteByte((byte)':');
                    WriteCanonical(element.GetProperty(key), output);
                }
                output.WriteByte((byte)'}');
                break;

            case JsonValueKind.String:
                output.WriteByte((byte)'"');
                output.Write(Encoding.UTF8.GetBytes(element.GetString() ?? string.Empty));
                output.WriteByte((byte)'"');
                break;

            case JsonValueKind.Number:
            case JsonValueKind.True:
            case JsonValueKind.False:
            case JsonValueKind.Null:
                output.Write(Encoding.UTF8.GetBytes(element.GetRawText()));
                break;

            case JsonValueKind.Array:
                output.WriteByte((byte)'[');
                var firstArr = true;
                foreach (var item in element.EnumerateArray())
                {
                    if (!firstArr) output.WriteByte((byte)',');
                    firstArr = false;
                    WriteCanonical(item, output);
                }
                output.WriteByte((byte)']');
                break;

            default:
                throw new InvalidOperationException($"Unsupported JSON kind: {element.ValueKind}");
        }
    }
}
