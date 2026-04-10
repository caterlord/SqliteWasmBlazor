using Microsoft.EntityFrameworkCore;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Manages trusted contacts. System table — only the admin device creates
/// contacts; other devices receive them via the system-scope sync.
/// </summary>
public class ContactService(CryptoSyncContextBase context)
{
    /// <summary>
    /// Create a new contact. Starts untrusted (<see cref="TrustedContact.IsTrusted"/> = false)
    /// unless explicitly set — an untrusted contact is a pending invitation.
    /// </summary>
    public async ValueTask<TrustedContact> AddContactAsync(
        ContactUserData userData,
        string x25519PublicKey,
        string ed25519PublicKey,
        bool isAdmin = false,
        bool isTrusted = false)
    {
        var contact = new TrustedContact
        {
            Id = Guid.NewGuid(),
            Username = userData.Username,
            Email = userData.Email,
            Comment = userData.Comment,
            X25519PublicKey = x25519PublicKey,
            Ed25519PublicKey = ed25519PublicKey,
            IsAdmin = isAdmin,
            IsTrusted = isTrusted,
            UpdatedAt = DateTime.UtcNow,
            SharingScope = SharingScope.Client,
            SharingId = string.Empty
        };

        context.Contacts.Add(contact);
        await context.SaveChangesAsync();
        return contact;
    }

    /// <summary>
    /// Trust a contact (accept the invitation). Moves the contact to the
    /// public system scope so it broadcasts to all trusted peers on next sync.
    /// </summary>
    public async ValueTask TrustAsync(Guid contactId)
    {
        var contact = await context.Contacts.FindAsync(contactId)
            ?? throw new InvalidOperationException($"Contact {contactId} not found");

        contact.IsTrusted = true;
        contact.SharingScope = SharingScope.Public;
        contact.SharingId = CryptoSyncBootstrap.SystemSharingId;
        contact.UpdatedAt = DateTime.UtcNow;
        await context.SaveChangesAsync();
    }

    /// <summary>
    /// Untrust a contact. Reverts to client-private scope.
    /// </summary>
    public async ValueTask UntrustAsync(Guid contactId)
    {
        var contact = await context.Contacts.FindAsync(contactId)
            ?? throw new InvalidOperationException($"Contact {contactId} not found");

        contact.IsTrusted = false;
        contact.SharingScope = SharingScope.Client;
        contact.SharingId = string.Empty;
        contact.UpdatedAt = DateTime.UtcNow;
        await context.SaveChangesAsync();
    }

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
            .Where(c => c.IsTrusted)
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
