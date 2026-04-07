using Microsoft.EntityFrameworkCore;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Manages sent and received invitations. All write methods on the sent side
/// are admin-only (decision §12) — only the admin device issues invitations.
/// Received-side methods are open to any device because every device persists
/// the invitations it has accepted locally.
///
/// <para>
/// This is the canonical CryptoSync surface (decision §13). It is not a wrapper
/// around BlazorPRF.Persistence and does not adapt to BlazorPRF.Mail's
/// <c>IInvitePersistence</c>. The eventual mail-layer migration consumes this
/// service directly.
/// </para>
/// </summary>
public class InvitationService(
    CryptoSyncContextBase context,
    DeviceIdentityService deviceIdentity)
{
    // ============================================================
    // SENT INVITATIONS (admin-only writes)
    // ============================================================

    /// <summary>
    /// Create a sent invitation record. Admin-only.
    /// </summary>
    public async ValueTask<SentInvitation> CreateSentInvitationAsync(
        string inviteCode,
        string email,
        string armoredInvite)
    {
        await EnsureAdminAsync();

        var invitation = new SentInvitation
        {
            Id = Guid.NewGuid(),
            InviteCode = inviteCode,
            Email = email,
            ArmoredInvite = armoredInvite,
            Status = InviteStatus.Pending,
            CreatedAt = DateTime.UtcNow
        };

        context.SentInvitations.Add(invitation);
        await context.SaveChangesAsync();
        return invitation;
    }

    /// <summary>
    /// Get all sent invitations.
    /// </summary>
    public async ValueTask<IReadOnlyList<SentInvitation>> GetSentInvitationsAsync()
    {
        return await context.SentInvitations.OrderByDescending(i => i.CreatedAt).ToListAsync();
    }

    /// <summary>
    /// Get a sent invitation by invite code, or <c>null</c> if not found.
    /// </summary>
    public ValueTask<SentInvitation?> GetSentInvitationByCodeAsync(string inviteCode)
    {
        return new ValueTask<SentInvitation?>(
            context.SentInvitations.FirstOrDefaultAsync(i => i.InviteCode == inviteCode));
    }

    /// <summary>
    /// Mark a sent invitation as accepted and link it to the resulting trusted contact.
    /// Admin-only.
    /// </summary>
    public async ValueTask MarkSentInvitationAcceptedAsync(string inviteCode, Guid trustedContactId)
    {
        await EnsureAdminAsync();

        var invitation = await context.SentInvitations.FirstOrDefaultAsync(i => i.InviteCode == inviteCode)
            ?? throw new InvalidOperationException($"Sent invitation not found: {inviteCode}");

        invitation.Status = InviteStatus.Accepted;
        invitation.AcceptedAt = DateTime.UtcNow;
        invitation.TrustedContactId = trustedContactId;
        await context.SaveChangesAsync();
    }

    /// <summary>
    /// Update a sent invitation's status (e.g. <c>Revoked</c>, <c>Expired</c>). Admin-only.
    /// </summary>
    public async ValueTask UpdateSentInvitationStatusAsync(Guid id, InviteStatus status)
    {
        await EnsureAdminAsync();

        var invitation = await context.SentInvitations.FindAsync(id)
            ?? throw new InvalidOperationException($"Sent invitation not found: {id}");

        invitation.Status = status;
        await context.SaveChangesAsync();
    }

    /// <summary>
    /// Delete a sent invitation. Admin-only.
    /// </summary>
    public async ValueTask DeleteSentInvitationAsync(Guid id)
    {
        await EnsureAdminAsync();

        var invitation = await context.SentInvitations.FindAsync(id);
        if (invitation is not null)
        {
            context.SentInvitations.Remove(invitation);
            await context.SaveChangesAsync();
        }
    }

    // ============================================================
    // RECEIVED INVITATIONS (open to any device)
    // ============================================================

    /// <summary>
    /// Create a received invitation record. Any device may call this.
    /// </summary>
    public async ValueTask<ReceivedInvitation> CreateReceivedInvitationAsync(
        string inviteCode,
        string inviterEd25519PublicKey,
        Guid? trustedContactId = null)
    {
        var invitation = new ReceivedInvitation
        {
            Id = Guid.NewGuid(),
            InviteCode = inviteCode,
            InviterEd25519PublicKey = inviterEd25519PublicKey,
            AcceptedAt = DateTime.UtcNow,
            TrustedContactId = trustedContactId
        };

        context.ReceivedInvitations.Add(invitation);
        await context.SaveChangesAsync();
        return invitation;
    }

    /// <summary>
    /// Get all received invitations.
    /// </summary>
    public async ValueTask<IReadOnlyList<ReceivedInvitation>> GetReceivedInvitationsAsync()
    {
        return await context.ReceivedInvitations.OrderByDescending(i => i.AcceptedAt).ToListAsync();
    }

    /// <summary>
    /// Link a received invitation to the trusted contact created during the handshake.
    /// </summary>
    public async ValueTask LinkReceivedInvitationToContactAsync(Guid invitationId, Guid trustedContactId)
    {
        var invitation = await context.ReceivedInvitations.FindAsync(invitationId)
            ?? throw new InvalidOperationException($"Received invitation not found: {invitationId}");

        invitation.TrustedContactId = trustedContactId;
        await context.SaveChangesAsync();
    }

    /// <summary>
    /// Returns true if a received invitation with this code has already been persisted.
    /// </summary>
    public ValueTask<bool> ReceivedInvitationExistsAsync(string inviteCode)
    {
        return new ValueTask<bool>(
            context.ReceivedInvitations.AnyAsync(i => i.InviteCode == inviteCode));
    }

    // ============================================================
    // GUARDS
    // ============================================================

    private async ValueTask EnsureAdminAsync()
    {
        if (!await deviceIdentity.IsAdminAsync())
        {
            throw new InvalidOperationException(
                "Only the admin device can issue or modify invitations (decision §12).");
        }
    }
}
