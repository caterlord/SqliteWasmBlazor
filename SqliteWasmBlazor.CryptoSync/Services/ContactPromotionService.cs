using Microsoft.EntityFrameworkCore;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Manages the explicit <see cref="TrustLevel.Marginal"/> → <see cref="TrustLevel.Full"/>
/// promotion of trusted contacts. Admin-only — promotion is never automatic
/// (resolved decision §9).
///
/// <para>
/// Mechanics: a contact created by the invitation handshake starts at
/// <see cref="TrustLevel.Marginal"/> with <see cref="SharingScope.Client"/>
/// (admin-private — only the admin device can decrypt the contact row). On
/// explicit elevation, the contact's row migrates to
/// <see cref="SharingScope.Public"/> with <c>SharingId = "system"</c>, causing
/// the next sync to broadcast it under the public content key to every
/// existing Full-trust peer. The other peers then learn about this contact.
/// </para>
///
/// <para>
/// SharingKey emission for the new contact (so every existing Full peer gets a
/// content-key envelope for the public scope) is deferred to Phase F where
/// <c>OwnershipTransferService.RotateContentKeyAsync</c> provides the rewrap
/// primitive that this service can reuse.
/// </para>
/// </summary>
public class ContactPromotionService(
    CryptoSyncContextBase context,
    DeviceIdentityService deviceIdentity)
{
    /// <summary>
    /// Promote a contact from <see cref="TrustLevel.Marginal"/> to
    /// <see cref="TrustLevel.Full"/> and migrate its row from the admin-private
    /// scope to the public scope. Admin-only.
    /// </summary>
    public async ValueTask ElevateToFullAsync(Guid contactId)
    {
        await EnsureAdminAsync();

        var contact = await context.Contacts.FindAsync(contactId)
            ?? throw new InvalidOperationException($"Contact not found: {contactId}");

        if (contact.TrustLevel == TrustLevel.Full)
        {
            return; // Idempotent
        }

        if (contact.TrustLevel == TrustLevel.None)
        {
            throw new InvalidOperationException(
                $"Cannot elevate contact {contactId} from None to Full — invitation handshake must run first.");
        }

        contact.TrustLevel = TrustLevel.Full;
        contact.SharingScope = SharingScope.Public;
        contact.SharingId = "system";
        contact.UpdatedAt = DateTime.UtcNow;
        await context.SaveChangesAsync();

        // TODO (Phase F): emit a SharingKey row for every existing Full-trust peer
        // so they can decrypt the contact row on the next sync. The rewrap primitive
        // will live in OwnershipTransferService.RotateContentKeyAsync and this method
        // will reuse it.
    }

    /// <summary>
    /// Demote a contact's trust level (e.g. revert to <see cref="TrustLevel.Marginal"/>).
    /// Admin-only. Reverts the contact row to <see cref="SharingScope.Client"/>.
    /// </summary>
    public async ValueTask DemoteAsync(Guid contactId, TrustLevel newLevel)
    {
        await EnsureAdminAsync();

        var contact = await context.Contacts.FindAsync(contactId)
            ?? throw new InvalidOperationException($"Contact not found: {contactId}");

        contact.TrustLevel = newLevel;
        contact.SharingScope = newLevel == TrustLevel.Full ? SharingScope.Public : SharingScope.Client;
        contact.SharingId = newLevel == TrustLevel.Full ? "system" : string.Empty;
        contact.UpdatedAt = DateTime.UtcNow;
        await context.SaveChangesAsync();
    }

    private async ValueTask EnsureAdminAsync()
    {
        if (!await deviceIdentity.IsAdminAsync())
        {
            throw new InvalidOperationException(
                "Only the admin device can promote/demote contacts (decision §12).");
        }
    }
}
