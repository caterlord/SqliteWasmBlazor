using System.Text.Json;
using BlazorPRF.Crypto.Abstractions;
using BlazorPRF.Crypto.Abstractions.Models;
using Microsoft.EntityFrameworkCore;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Manages trusted contacts with encrypted user data.
/// User data (name, email, comment) is encrypted at rest with a symmetric key.
/// </summary>
public class ContactService(CryptoSyncContextBase context, ICryptoProvider crypto)
{
    /// <summary>
    /// Add a new trusted contact. User data is encrypted before storage.
    /// </summary>
    public async ValueTask<TrustedContact> AddContactAsync(
        ContactUserData userData,
        string x25519PublicKey,
        string ed25519PublicKey,
        SyncRole role,
        TrustLevel trustLevel,
        TrustDirection direction,
        ReadOnlyMemory<byte> encryptionKey)
    {
        var encryptedData = await EncryptUserDataAsync(userData, encryptionKey);

        var contact = new TrustedContact
        {
            Id = Guid.NewGuid(),
            EncryptedUserData = encryptedData,
            X25519PublicKey = x25519PublicKey,
            Ed25519PublicKey = ed25519PublicKey,
            Role = role,
            TrustLevel = trustLevel,
            Direction = direction,
            VerifiedAt = DateTime.UtcNow,
            CreatedAt = DateTime.UtcNow
        };

        context.Contacts.Add(contact);
        await context.SaveChangesAsync();
        return contact;
    }

    /// <summary>
    /// Get a contact by Ed25519 public key (used to identify delta senders).
    /// </summary>
    public async ValueTask<TrustedContact?> GetByEd25519PublicKeyAsync(string ed25519PublicKey)
    {
        return await context.Contacts.FirstOrDefaultAsync(c => c.Ed25519PublicKey == ed25519PublicKey);
    }

    /// <summary>
    /// Get all active (non-revoked) contacts.
    /// </summary>
    public async ValueTask<List<TrustedContact>> GetAllActiveAsync()
    {
        return await context.Contacts.ToListAsync();
    }

    /// <summary>
    /// Get all contacts with decrypted user data.
    /// </summary>
    public async ValueTask<List<(TrustedContact Contact, ContactUserData UserData)>> GetAllWithUserDataAsync(ReadOnlyMemory<byte> decryptionKey)
    {
        var contacts = await context.Contacts.ToListAsync();
        var result = new List<(TrustedContact, ContactUserData)>();

        foreach (var contact in contacts)
        {
            var userData = await DecryptUserDataAsync(contact.EncryptedUserData, decryptionKey);
            result.Add((contact, userData));
        }

        return result;
    }

    /// <summary>
    /// Get X25519 public keys of all active contacts (for building recipient list).
    /// </summary>
    public async ValueTask<string[]> GetRecipientPublicKeysAsync()
    {
        return await context.Contacts
            .Select(c => c.X25519PublicKey)
            .ToArrayAsync();
    }

    /// <summary>
    /// Update a contact's role.
    /// </summary>
    public async ValueTask UpdateRoleAsync(Guid contactId, SyncRole newRole)
    {
        var contact = await context.Contacts.FindAsync(contactId);
        if (contact is null)
        {
            throw new InvalidOperationException($"Contact {contactId} not found");
        }

        contact.Role = newRole;
        await context.SaveChangesAsync();
    }

    /// <summary>
    /// Remove a contact.
    /// </summary>
    public async ValueTask DeleteAsync(Guid contactId)
    {
        var contact = await context.Contacts.FindAsync(contactId);
        if (contact is not null)
        {
            context.Contacts.Remove(contact);
            await context.SaveChangesAsync();
        }
    }

    private async ValueTask<string> EncryptUserDataAsync(ContactUserData userData, ReadOnlyMemory<byte> key)
    {
        var json = JsonSerializer.Serialize(userData);
        var result = await crypto.EncryptSymmetricAsync(json, key);
        if (!result.Success)
        {
            throw new InvalidOperationException($"Failed to encrypt user data: {result.ErrorCode}");
        }

        // Store as JSON: { "ciphertext": "...", "nonce": "..." }
        return JsonSerializer.Serialize(result.Value);
    }

    private async ValueTask<ContactUserData> DecryptUserDataAsync(string encryptedJson, ReadOnlyMemory<byte> key)
    {
        var encrypted = JsonSerializer.Deserialize<SymmetricEncryptedMessage>(encryptedJson);
        if (encrypted is null)
        {
            throw new InvalidOperationException("Invalid encrypted user data format");
        }

        var result = await crypto.DecryptSymmetricAsync(encrypted, key);
        if (!result.Success)
        {
            throw new InvalidOperationException($"Failed to decrypt user data: {result.ErrorCode}");
        }

        return JsonSerializer.Deserialize<ContactUserData>(result.Value!)
            ?? throw new InvalidOperationException("Failed to deserialize user data");
    }
}
