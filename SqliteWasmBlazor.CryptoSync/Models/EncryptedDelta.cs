using MessagePack;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Encrypted delta envelope for transport (MessagePack serialized).
/// Contains the encrypted V2 payload and per-recipient wrapped content keys.
///
/// <para>
/// Plaintext (relay-visible): <see cref="SenderPublicKey"/>, <see cref="ContentSignature"/>,
/// <see cref="RecipientEnvelopes"/>, <see cref="Nonce"/>.
/// Encrypted: <see cref="Ciphertext"/> (V2 header + row data).
/// </para>
///
/// <para>
/// Permissions are NOT shipped in the envelope. Receivers enforce permissions
/// by querying the locally-applied <c>SyncPermission</c> table during the
/// staggered apply pass — see <c>permission-check.ts</c>. This prevents senders
/// from lying about op-kind or table rules and lets a permission change shipped
/// in the same delta as a domain change take effect first.
/// </para>
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
}
