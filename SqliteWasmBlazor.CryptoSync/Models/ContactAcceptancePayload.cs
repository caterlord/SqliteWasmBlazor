using MessagePack;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// The signed bundle a contact's device hands to the admin's device when
/// accepting an invitation. Carries the contact's identity (public keys
/// + display info) and the contact's pre-built self-group rows
/// (<see cref="ShareGroup"/> + <see cref="ShareTarget"/>) — the
/// <see cref="SelfWrappedContentKey"/> is wrapped via
/// <c>HKDF(ECDH(contactPriv, contactPub), info=SelfGroupContext)</c>, so
/// the admin can persist the rows but cannot decrypt the underlying CEK.
///
/// <para>
/// Out-of-band integrity: the contact verifies the admin's identity via a
/// QR code, fingerprint compare, etc. Once accepted, the
/// <see cref="AcceptancePayloadSignature"/> Ed25519 signature locks the
/// payload contents — any tampering between the contact and the admin
/// (relay corruption, MITM) is detected at acceptance time.
/// </para>
///
/// <para>
/// <b>NOTE:</b> <see cref="AcceptancePayloadSignature"/> is a payload-integrity
/// signature, not a layer-2 envelope signature. It binds the
/// <em>invitation</em>, not individual <c>Crypto_*</c> rows.
/// </para>
/// </summary>
[MessagePackObject]
public sealed class ContactAcceptancePayload
{
    [Key(0)] public int Version { get; set; } = 1;

    [Key(1)] public required Guid ContactId { get; init; }

    [Key(2)] public required string Username { get; init; }

    [Key(3)] public required string Email { get; init; }

    [Key(4)] public string? Comment { get; init; }

    /// <summary>X25519 public key (Base64) — used for ECDH key wrapping.</summary>
    [Key(5)] public required string X25519PublicKey { get; init; }

    /// <summary>Ed25519 public key (Base64) — used to verify the signature on this payload.</summary>
    [Key(6)] public required string Ed25519PublicKey { get; init; }

    /// <summary>Identity of the contact's pre-built self-group <see cref="ShareGroup"/> row.</summary>
    [Key(7)] public required Guid SelfGroupId { get; init; }

    /// <summary>HKDF info / AAD binding string for the self-group, e.g. <c>"self-{contactId:N}:v1"</c>.</summary>
    [Key(8)] public required string SelfGroupContext { get; init; }

    /// <summary>Self-group key version (always <c>1</c> at invitation time).</summary>
    [Key(9)] public required int SelfKeyVersion { get; init; }

    /// <summary>
    /// Contact's wrapped self-CEK in <c>[nonce(12)|ciphertext]</c> form.
    /// Wrapped via <c>HKDF(ECDH(contactPriv, contactPub), info=SelfGroupContext)</c>
    /// — only the holder of <c>contactPriv</c> can ever re-derive the wrapping key.
    /// </summary>
    [Key(10)] public required byte[] SelfWrappedContentKey { get; init; }

    /// <summary>
    /// Ed25519 signature over the MessagePack-serialized payload with this
    /// field set to <c>[]</c> at sign time. Verified on accept by the
    /// admin device against <see cref="Ed25519PublicKey"/>.
    ///
    /// <para>
    /// <b>INVARIANT:</b> must remain the highest <c>[Key(N)]</c> index on
    /// this type. Canonical signing clears this field, serializes, signs,
    /// then restores. A new field at <c>[Key(12)]</c> would silently shift
    /// the canonical bytes and break verification of every prior payload.
    /// A unit test pins this invariant.
    /// </para>
    /// </summary>
    [Key(11)] public byte[] AcceptancePayloadSignature { get; set; } = [];
}
