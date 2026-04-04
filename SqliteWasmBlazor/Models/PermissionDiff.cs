using System.Text.Json.Serialization;

namespace SqliteWasmBlazor;

/// <summary>
/// C# representation of the TS PermissionMap.
/// Maps Ed25519 public key (Base64) → permission diff dictionary.
///
/// Permission diff format (default = full readwrite, only overrides stored):
/// - "TableName": "readonly"              — whole table readonly
/// - "TableName.Column": "readwrite"      — column override within readonly table
/// - {} (empty)                           — full access (default)
/// </summary>
[JsonSerializable(typeof(Dictionary<string, Dictionary<string, string>>))]
public partial class PermissionMapJsonContext : JsonSerializerContext;
