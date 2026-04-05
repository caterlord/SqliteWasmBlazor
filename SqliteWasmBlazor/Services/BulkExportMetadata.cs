namespace SqliteWasmBlazor;

/// <summary>
/// Typed metadata for worker-side bulk export.
/// All required fields enforced at compile time — prevents JS undefined/fixext issues.
///
/// When <see cref="KeyId"/> and <see cref="RecipientPublicKeys"/> are set,
/// the worker does encrypted export: encrypt + sign + wrap per recipient.
/// The response is an encrypted envelope instead of raw V2 bytes.
/// </summary>
public record BulkExportMetadata
{
    public required string TableName { get; init; }
    public required string[][] Columns { get; init; }
    public required string PrimaryKeyColumn { get; init; }
    public required string SchemaHash { get; init; }
    public required string DataType { get; init; }
    public string? AppIdentifier { get; init; }
    public int Mode { get; init; }
    public string? Where { get; init; }
    public string[]? WhereParams { get; init; }
    public string? OrderBy { get; init; }

    // Crypto extension — when set, worker does encrypted export
    /// <summary>Worker key cache ID (from CryptoStoreKeys). When set, enables encrypted export.</summary>
    public string? KeyId { get; init; }
    /// <summary>X25519 public keys of recipients for key wrapping.</summary>
    public string[]? RecipientPublicKeys { get; init; }
    /// <summary>Permission map to include in encrypted header: ed25519pk → { "Table": "readonly", ... }</summary>
    public Dictionary<string, Dictionary<string, string>>? Permissions { get; init; }
}
