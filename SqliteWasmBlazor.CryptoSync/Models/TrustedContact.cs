using System.ComponentModel.DataAnnotations;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// A verified contact with public keys for encryption and signature verification.
/// User data (username, email, comment) is encrypted with PRF-derived symmetric key.
/// Ported from BlazorPRF.Persistence.
/// </summary>
public sealed class TrustedContact
{
    public Guid Id { get; set; }

    /// <summary>
    /// Encrypted JSON containing username, email, and comment.
    /// Encrypted with PRF-derived symmetric key for at-rest protection.
    /// </summary>
    [MaxLength(4096)]
    public required string EncryptedUserData { get; set; }

    /// <summary>X25519 public key (Base64) for asymmetric encryption.</summary>
    [MaxLength(64)]
    public required string X25519PublicKey { get; set; }

    /// <summary>Ed25519 public key (Base64) for signature verification.</summary>
    [MaxLength(64)]
    public required string Ed25519PublicKey { get; set; }

    /// <summary>Role assigned to this contact for permission enforcement.</summary>
    public SyncRole Role { get; set; }

    public TrustLevel TrustLevel { get; set; }
    public TrustDirection Direction { get; set; }
    public DateTime VerifiedAt { get; set; }
    public DateTime CreatedAt { get; set; }
}

/// <summary>
/// Decrypted user data for a contact.
/// Serialized as JSON, encrypted at rest in TrustedContact.EncryptedUserData.
/// </summary>
public sealed class ContactUserData
{
    public required string Username { get; init; }
    public required string Email { get; init; }
    public string? Comment { get; init; }
}
