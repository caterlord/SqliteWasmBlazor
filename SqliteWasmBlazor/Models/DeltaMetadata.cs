using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace SqliteWasmBlazor;

/// <summary>
/// Key-value metadata stored in the _deltaMetadata table.
/// Managed by the worker (raw SQL) and mapped via EF Core for C# access.
/// Worker is the source of truth — C# reads for UI enforcement.
///
/// Known keys:
/// - "permissions"      → PermissionMap JSON (who can write what)
/// - "adminPublicKey"   → Base64 Ed25519 trust chain root
/// - "myPublicKey"      → Base64 Ed25519 of current user
/// - "encryptedTables"  → JSON array of table names needing column encryption
/// </summary>
[Table("_deltaMetadata")]
public class DeltaMetadata
{
    [Key]
    [Column("key")]
    public string Key { get; set; } = string.Empty;

    [Required]
    [Column("value")]
    public string Value { get; set; } = string.Empty;
}
