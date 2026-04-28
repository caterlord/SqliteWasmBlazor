using MessagePack;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Out-of-band invitation handout produced by the admin device and
/// delivered to the contact via QR code, email, messenger, etc.
/// Rewritten in commit 2 of the invitation pivot — current shape is
/// transitional.
/// </summary>
[MessagePackObject]
public sealed class InvitationBundle
{
    /// <summary>Wire format version. Bumped on schema changes.</summary>
    [Key(0)]
    public int Version { get; set; } = 1;

    /// <summary>One-shot invitation token (32 bytes). Replaced by a 32-byte
    /// shared transport secret in commit 2.</summary>
    [Key(1)]
    public required byte[] Token { get; init; }

    /// <summary>Admin's X25519 public key (Base64).</summary>
    [Key(2)]
    public required string AdminX25519PublicKey { get; init; }

    /// <summary>Optional relay URL hint.</summary>
    [Key(3)]
    public string? RelayHint { get; init; }
}
