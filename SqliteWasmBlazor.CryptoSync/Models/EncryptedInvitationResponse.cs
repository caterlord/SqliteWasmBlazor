using MessagePack;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Wire-level wrapper for the contact's response to an admin-initiated
/// invitation. Carries an AES-256-GCM-encrypted, MessagePack-serialized
/// <see cref="ContactAcceptancePayload"/>.
///
/// <para>
/// The encryption key (PSK) is derived from the
/// <see cref="InvitationBundle.Token"/> via HKDF-SHA256 with the
/// fixed info string <c>"crypto-sync-invitation-v1"</c>. The token itself
/// never appears on the wire — admin trial-decrypts against each open
/// <see cref="ContactStatus.Invited"/> placeholder until one succeeds, then
/// finalizes the bind. This keeps the wire opaque to anyone who didn't
/// receive the OOB invitation bundle.
/// </para>
/// </summary>
[MessagePackObject]
public sealed class EncryptedInvitationResponse
{
    /// <summary>HKDF info string used to derive the AES key from the
    /// invitation token. Pinned constant so encrypt/decrypt agree.</summary>
    public const string PskInfoContext = "crypto-sync-invitation-v1";

    /// <summary>Wire format version. Bumped on schema changes.</summary>
    [Key(0)]
    public int Version { get; set; } = 1;

    /// <summary>AES-256-GCM ciphertext + auth tag (Base64).</summary>
    [Key(1)]
    public required string Ciphertext { get; init; }

    /// <summary>AES-256-GCM nonce (Base64, 12 bytes).</summary>
    [Key(2)]
    public required string Nonce { get; init; }
}
