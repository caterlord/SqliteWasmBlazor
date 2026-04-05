using System.ComponentModel.DataAnnotations;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Tracks an invitation created by the user.
/// Ported from BlazorPRF.Persistence.
/// </summary>
public sealed class SentInvitation
{
    public Guid Id { get; set; }

    [MaxLength(32)]
    public required string InviteCode { get; set; }

    /// <summary>Encrypted email address of the invitee.</summary>
    [MaxLength(1024)]
    public required string EncryptedEmail { get; set; }

    /// <summary>Full armored invite for re-sending if needed.</summary>
    [MaxLength(8192)]
    public required string ArmoredInvite { get; set; }

    public InviteStatus Status { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? AcceptedAt { get; set; }
    public Guid? TrustedContactId { get; set; }
    public TrustedContact? TrustedContact { get; set; }
}
