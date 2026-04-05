using MessagePack;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Encrypted delta envelope for transport (MessagePack serialized).
/// Contains encrypted V2 payload, per-recipient wrapped keys, and signed permissions.
///
/// Plaintext (relay-visible): SenderPublicKey, ContentSignature, RecipientEnvelopes
/// Encrypted: V2 header + row data, permissions
/// </summary>
[MessagePackObject]
public class EncryptedDelta
{
    /// <summary>V2 rows encrypted with content key (AES-GCM).</summary>
    [Key(0)]
    public byte[] Ciphertext { get; set; } = [];

    /// <summary>AES-GCM nonce for ciphertext.</summary>
    [Key(1)]
    public byte[] Nonce { get; set; } = [];

    /// <summary>Ed25519 signature over ciphertext — proves sender produced this data.</summary>
    [Key(2)]
    public byte[] ContentSignature { get; set; } = [];

    /// <summary>Ed25519 public key of the data producer.</summary>
    [Key(3)]
    public string SenderPublicKey { get; set; } = string.Empty;

    /// <summary>Per-recipient wrapped content keys. Key = X25519 public key (Base64), Value = ECIES wrapped key.</summary>
    [Key(4)]
    public Dictionary<string, byte[]> RecipientEnvelopes { get; set; } = new();

    /// <summary>
    /// Permission map (encrypted in transit, plaintext after decryption).
    /// Ed25519 public key → permission diff from default.
    /// Default = full readwrite. Only overrides stored:
    /// "Table": "readonly", "Table.Column": "readwrite"
    /// </summary>
    [Key(5)]
    public Dictionary<string, Dictionary<string, string>> Permissions { get; set; } = new();

    /// <summary>Ed25519 signature over canonical hash of Permissions.</summary>
    [Key(6)]
    public byte[] PermissionsSignature { get; set; } = [];

    /// <summary>Ed25519 public key of the admin who signed permissions (trust chain root).</summary>
    [Key(7)]
    public string AdminPublicKey { get; set; } = string.Empty;
}
