using System.Security.Cryptography;
using BlazorPRF.Crypto.Abstractions;
using BlazorPRF.Crypto.Abstractions.Models;

namespace SqliteWasmBlazor.CryptoSync;

/// <summary>
/// Service for creating and consuming encrypted deltas.
///
/// Phase D-1: still C#-side encrypt/decrypt of the V2 payload. Phase D-2 will
/// move this to the worker (<c>BulkExportEncryptedAsync</c> /
/// <c>BulkImportEncryptedAsync</c>) and reduce this service to envelope assembly
/// (ECIES wrap/unwrap + signing) only.
///
/// Permissions are no longer shipped in the envelope — see <see cref="EncryptedDelta"/>.
/// </summary>
public static class EncryptedDeltaService
{
    /// <summary>
    /// Encrypt V2 payload bytes into an EncryptedDelta envelope.
    /// </summary>
    /// <param name="crypto">Crypto provider (BC for tests, Noble for browser)</param>
    /// <param name="v2Bytes">Plain V2 MessagePack bytes from BulkExportAsync</param>
    /// <param name="senderKeys">Sender's derived key pair (Ed25519 for signing, X25519 for self-envelope)</param>
    /// <param name="recipientX25519PublicKeys">X25519 public keys (Base64) of all recipients</param>
    public static async ValueTask<EncryptedDelta> EncryptAsync(
        ICryptoProvider crypto,
        byte[] v2Bytes,
        DualKeyPairFull senderKeys,
        string[] recipientX25519PublicKeys)
    {
        // Generate random content key
        var contentKey = new byte[32];
        RandomNumberGenerator.Fill(contentKey);

        // Encrypt V2 payload with content key
        var v2Base64 = Convert.ToBase64String(v2Bytes);
        var encryptResult = await crypto.EncryptSymmetricAsync(v2Base64, contentKey);
        if (!encryptResult.Success)
        {
            throw new InvalidOperationException($"Encryption failed: {encryptResult.ErrorCode}");
        }

        var ciphertext = Convert.FromBase64String(encryptResult.Value!.Ciphertext);
        var nonce = Convert.FromBase64String(encryptResult.Value.Nonce);

        // Sign the ciphertext with sender's Ed25519 key
        var ciphertextBase64 = Convert.ToBase64String(ciphertext);
        var senderEd25519Private = Convert.FromBase64String(senderKeys.Ed25519PrivateKey);
        var signResult = await crypto.SignAsync(ciphertextBase64, senderEd25519Private);
        if (!signResult.Success)
        {
            throw new InvalidOperationException($"Signing failed: {signResult.ErrorCode}");
        }

        var contentSignature = Convert.FromBase64String(signResult.Value!);

        // Wrap content key for each recipient via X25519 ECIES
        var recipientEnvelopes = new Dictionary<string, byte[]>();
        var contentKeyBase64 = Convert.ToBase64String(contentKey);
        foreach (var recipientPk in recipientX25519PublicKeys)
        {
            var wrapResult = await crypto.EncryptAsymmetricAsync(contentKeyBase64, recipientPk);
            if (!wrapResult.Success)
            {
                throw new InvalidOperationException($"Key wrapping failed: {wrapResult.ErrorCode}");
            }

            var wrapped = SerializeEncryptedMessage(wrapResult.Value!);
            recipientEnvelopes[recipientPk] = wrapped;
        }

        // Clear content key
        CryptographicOperations.ZeroMemory(contentKey);

        return new EncryptedDelta
        {
            Ciphertext = ciphertext,
            Nonce = nonce,
            ContentSignature = contentSignature,
            SenderPublicKey = senderKeys.Ed25519PublicKey,
            RecipientEnvelopes = recipientEnvelopes
        };
    }

    /// <summary>
    /// Decrypt an EncryptedDelta envelope back to V2 payload bytes.
    /// Verifies the content signature, unwraps the recipient's content key,
    /// and decrypts the payload. Permission enforcement happens later in the
    /// worker — this method only returns the plaintext bytes.
    /// </summary>
    public static async ValueTask<byte[]> DecryptAsync(
        ICryptoProvider crypto,
        EncryptedDelta delta,
        ReadOnlyMemory<byte> recipientX25519PrivateKey,
        string recipientX25519PublicKey)
    {
        // 1. Verify content signature
        var ciphertextBase64 = Convert.ToBase64String(delta.Ciphertext);
        var signatureBase64 = Convert.ToBase64String(delta.ContentSignature);
        var isValid = await crypto.VerifyAsync(ciphertextBase64, signatureBase64, delta.SenderPublicKey);
        if (!isValid)
        {
            throw new InvalidOperationException("Content signature verification failed");
        }

        // 2. Find our wrapped key
        if (!delta.RecipientEnvelopes.TryGetValue(recipientX25519PublicKey, out var wrappedKeyBytes))
        {
            throw new InvalidOperationException("Delta not encrypted for this recipient");
        }

        // 3. Unwrap content key
        var encryptedMsg = DeserializeEncryptedMessage(wrappedKeyBytes);
        var unwrapResult = await crypto.DecryptAsymmetricAsync(encryptedMsg, recipientX25519PrivateKey);
        if (!unwrapResult.Success)
        {
            throw new InvalidOperationException($"Key unwrapping failed: {unwrapResult.ErrorCode}");
        }

        var contentKey = Convert.FromBase64String(unwrapResult.Value!);

        // 4. Decrypt the V2 payload
        var encrypted = new SymmetricEncryptedMessage(
            Convert.ToBase64String(delta.Ciphertext),
            Convert.ToBase64String(delta.Nonce)
        );
        var decryptResult = await crypto.DecryptSymmetricAsync(encrypted, contentKey);

        CryptographicOperations.ZeroMemory(contentKey);

        if (!decryptResult.Success)
        {
            throw new InvalidOperationException($"Decryption failed: {decryptResult.ErrorCode}");
        }

        return Convert.FromBase64String(decryptResult.Value!);
    }

    /// <summary>
    /// Serialize EncryptedDelta to MessagePack bytes for transport.
    /// </summary>
    public static byte[] Serialize(EncryptedDelta delta)
    {
        return MessagePack.MessagePackSerializer.Serialize(delta);
    }

    /// <summary>
    /// Deserialize EncryptedDelta from MessagePack bytes.
    /// </summary>
    public static EncryptedDelta Deserialize(byte[] data)
    {
        return MessagePack.MessagePackSerializer.Deserialize<EncryptedDelta>(data);
    }

    // Pack ECIES result into a byte array for storage in RecipientEnvelopes
    private static byte[] SerializeEncryptedMessage(EncryptedMessage msg)
    {
        var ephPk = Convert.FromBase64String(msg.EphemeralPublicKey);
        var ct = Convert.FromBase64String(msg.Ciphertext);
        var nonce = Convert.FromBase64String(msg.Nonce);

        // Format: [ephPkLen(1) | ephPk | nonceLen(1) | nonce | ciphertext]
        var result = new byte[1 + ephPk.Length + 1 + nonce.Length + ct.Length];
        result[0] = (byte)ephPk.Length;
        ephPk.CopyTo(result.AsSpan(1));
        result[1 + ephPk.Length] = (byte)nonce.Length;
        nonce.CopyTo(result.AsSpan(2 + ephPk.Length));
        ct.CopyTo(result.AsSpan(2 + ephPk.Length + nonce.Length));
        return result;
    }

    private static EncryptedMessage DeserializeEncryptedMessage(byte[] data)
    {
        var ephPkLen = data[0];
        var ephPk = data.AsSpan(1, ephPkLen);
        var nonceLen = data[1 + ephPkLen];
        var nonce = data.AsSpan(2 + ephPkLen, nonceLen);
        var ct = data.AsSpan(2 + ephPkLen + nonceLen);

        return new EncryptedMessage(
            Convert.ToBase64String(ephPk),
            Convert.ToBase64String(ct),
            Convert.ToBase64String(nonce)
        );
    }
}
