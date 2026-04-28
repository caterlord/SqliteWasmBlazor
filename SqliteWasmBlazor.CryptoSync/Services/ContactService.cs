using Microsoft.EntityFrameworkCore;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Admin-facing read/admin operations over the trusted-contact table.
/// Contact creation + trust establishment lives in
/// <see cref="ContactInvitationService"/>.
/// </summary>
public class ContactService(CryptoSyncContextBase context)
{
    public async ValueTask<TrustedContact?> GetByEd25519PublicKeyAsync(string ed25519PublicKey)
    {
        return await context.Contacts.FirstOrDefaultAsync(c => c.Ed25519PublicKey == ed25519PublicKey);
    }

    public async ValueTask<List<TrustedContact>> GetAllAsync()
    {
        return await context.Contacts.ToListAsync();
    }

    public async ValueTask<string[]> GetRecipientPublicKeysAsync()
    {
        return await context.Contacts
            .Select(c => c.X25519PublicKey)
            .ToArrayAsync();
    }

    public async ValueTask DeleteAsync(Guid contactId)
    {
        var contact = await context.Contacts.FindAsync(contactId);
        if (contact is not null)
        {
            contact.IsDeleted = true;
            contact.DeletedAt = DateTime.UtcNow;
            contact.UpdatedAt = DateTime.UtcNow;
            await context.SaveChangesAsync();
        }
    }
}
