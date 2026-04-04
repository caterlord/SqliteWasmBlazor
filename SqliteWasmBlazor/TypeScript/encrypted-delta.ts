/**
 * Encrypted delta operations for the worker.
 *
 * Uses crypto-layer.ts directly — no abstraction layer.
 * In tests: random seed → storeKeys() → real crypto.
 * In production: PRF seed → storeKeys() → same real crypto.
 */

import {
    encryptAesGcm, decryptAesGcm,
    encryptAsymmetricAesGcm, decryptAsymmetricCachedAesGcm,
    signWithCachedKey, ed25519Verify,
    getPublicKeys, generateRandomBytes
} from './crypto-layer';
import {
    type PermissionMap, type EncryptedDeltaEnvelope,
    verifyContentSignature, verifyPermissionsSignature,
    checkWriteAccess, hashPermissions, signPermissions,
    type SignFn, type VerifyFn
} from './crypto-permissions';

// ============================================================
// TYPES
// ============================================================

export interface EncryptedExportResult {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    contentSignature: Uint8Array;
    senderPublicKey: string;
    recipientEnvelopes: Record<string, Uint8Array>;
}

export interface EncryptedImportResult {
    rowsAffected: number;
}

// ============================================================
// BASE64 HELPERS (bridge between crypto-layer's Base64 API and Uint8Array)
// ============================================================

function bytesToBase64(bytes: Uint8Array): string {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

// ============================================================
// ENCRYPTED EXPORT
// ============================================================

/**
 * Encrypt a V2 payload for the given recipients.
 *
 * 1. Generate random content key
 * 2. Encrypt V2 bytes with AES-GCM
 * 3. Sign ciphertext with sender's cached Ed25519 key
 * 4. Wrap content key per recipient via X25519 ECIES
 * 5. Return envelope (minus permissions — C# attaches those)
 */
export async function encryptedExport(
    v2Bytes: Uint8Array,
    keyId: string,
    recipientX25519Pks: string[]
): Promise<EncryptedExportResult> {
    // Generate random content key
    const contentKeyBase64 = generateRandomBytes(32);

    // Encrypt V2 payload
    const encryptResult = JSON.parse(await encryptAesGcm(bytesToBase64(v2Bytes), contentKeyBase64));
    if (!encryptResult.success) {
        throw new Error(`Encryption failed: ${encryptResult.error}`);
    }

    const ciphertext = base64ToBytes(encryptResult.ciphertextBase64);
    const nonce = base64ToBytes(encryptResult.nonceBase64);

    // Sign the ciphertext with cached Ed25519 key
    const signResult = JSON.parse(signWithCachedKey(keyId, encryptResult.ciphertextBase64));
    if (!signResult.success) {
        throw new Error(`Signing failed: ${signResult.error}`);
    }

    const contentSignature = base64ToBytes(signResult.signatureBase64);

    // Get sender's public keys
    const pubKeysResult = JSON.parse(getPublicKeys(keyId));
    if (!pubKeysResult.success) {
        throw new Error(`Failed to get public keys: ${pubKeysResult.error}`);
    }

    const senderPublicKey = pubKeysResult.ed25519PublicKeyBase64;

    // Wrap content key for each recipient via X25519 ECIES
    const recipientEnvelopes: Record<string, Uint8Array> = {};
    for (const recipientPk of recipientX25519Pks) {
        const wrapResult = JSON.parse(await encryptAsymmetricAesGcm(contentKeyBase64, recipientPk));
        if (!wrapResult.success) {
            throw new Error(`Key wrapping failed for recipient: ${wrapResult.error}`);
        }
        // Pack ephemeralPublicKey + ciphertext + nonce into a single wrapped key blob
        const ephPk = base64ToBytes(wrapResult.ephemeralPublicKeyBase64);
        const wrappedCt = base64ToBytes(wrapResult.ciphertextBase64);
        const wrappedNonce = base64ToBytes(wrapResult.nonceBase64);
        // Format: [ephPkLen(1) | ephPk | nonceLen(1) | nonce | ciphertext]
        const wrapped = new Uint8Array(1 + ephPk.length + 1 + wrappedNonce.length + wrappedCt.length);
        wrapped[0] = ephPk.length;
        wrapped.set(ephPk, 1);
        wrapped[1 + ephPk.length] = wrappedNonce.length;
        wrapped.set(wrappedNonce, 2 + ephPk.length);
        wrapped.set(wrappedCt, 2 + ephPk.length + wrappedNonce.length);
        recipientEnvelopes[recipientPk] = wrapped;
    }

    return {
        ciphertext,
        nonce,
        contentSignature,
        senderPublicKey,
        recipientEnvelopes
    };
}

// ============================================================
// ENCRYPTED IMPORT
// ============================================================

/**
 * Verify, check permissions, unwrap, and decrypt an encrypted delta.
 * Returns the decrypted V2 bytes for bulk import.
 *
 * 1. Verify content signature
 * 2. Verify permissions signature
 * 3. Check sender's write access
 * 4. Unwrap content key
 * 5. Decrypt → V2 bytes
 */
export async function encryptedImport(
    envelope: EncryptedDeltaEnvelope,
    keyId: string,
    tableName: string,
    columnNames: string[]
): Promise<Uint8Array> {
    // Build verify function using real ed25519Verify
    const verifyFn: VerifyFn = (data, signature, publicKey) => {
        return ed25519Verify(bytesToBase64(data), bytesToBase64(signature), publicKey);
    };

    // 1. Verify content signature
    if (!verifyContentSignature(envelope.ciphertext, envelope.contentSignature, envelope.senderPublicKey, verifyFn)) {
        throw new Error('Content signature verification failed');
    }

    // 2. Verify permissions signature
    if (!verifyPermissionsSignature(envelope.permissions, envelope.permissionsSignature, envelope.adminPublicKey, verifyFn)) {
        throw new Error('Permissions signature verification failed');
    }

    // 3. Check sender's write access
    const accessResult = checkWriteAccess(envelope.permissions, envelope.senderPublicKey, tableName, columnNames);
    if (!accessResult.allowed) {
        throw new Error(`Write access denied: ${accessResult.reason}`);
    }

    // 4. Unwrap content key — find our envelope
    const pubKeysResult = JSON.parse(getPublicKeys(keyId));
    if (!pubKeysResult.success) {
        throw new Error('Failed to get own public keys');
    }
    const myX25519Pk = pubKeysResult.x25519PublicKeyBase64;

    const wrappedKeyBlob = envelope.recipientEnvelopes[myX25519Pk];
    if (!wrappedKeyBlob) {
        throw new Error('Delta not encrypted for this recipient');
    }

    // Unpack wrapped key blob: [ephPkLen(1) | ephPk | nonceLen(1) | nonce | ciphertext]
    const ephPkLen = wrappedKeyBlob[0];
    const ephPk = wrappedKeyBlob.slice(1, 1 + ephPkLen);
    const nonceLen = wrappedKeyBlob[1 + ephPkLen];
    const wrappedNonce = wrappedKeyBlob.slice(2 + ephPkLen, 2 + ephPkLen + nonceLen);
    const wrappedCt = wrappedKeyBlob.slice(2 + ephPkLen + nonceLen);

    const unwrapResult = JSON.parse(await decryptAsymmetricCachedAesGcm(
        keyId,
        bytesToBase64(ephPk),
        bytesToBase64(wrappedCt),
        bytesToBase64(wrappedNonce)
    ));
    if (!unwrapResult.success) {
        throw new Error(`Key unwrapping failed: ${unwrapResult.error}`);
    }

    const contentKeyBase64 = unwrapResult.plaintextBase64;

    // 5. Decrypt the V2 payload
    const decryptResult = JSON.parse(await decryptAesGcm(
        bytesToBase64(envelope.ciphertext),
        bytesToBase64(envelope.nonce),
        contentKeyBase64
    ));
    if (!decryptResult.success) {
        throw new Error(`Decryption failed: ${decryptResult.error}`);
    }

    return base64ToBytes(decryptResult.plaintextBase64);
}

// ============================================================
// PERMISSION SIGNING HELPER
// ============================================================

/**
 * Sign a permission map using the cached admin key.
 * Returns the signature and admin's Ed25519 public key.
 */
export function signPermissionsWithCachedKey(
    permissions: PermissionMap,
    adminKeyId: string
): { permissionsSignature: Uint8Array; adminPublicKey: string } {
    const pubKeysResult = JSON.parse(getPublicKeys(adminKeyId));
    if (!pubKeysResult.success) {
        throw new Error('Failed to get admin public keys');
    }

    const signFn: SignFn = (data, keyIdentity) => {
        const result = JSON.parse(signWithCachedKey(keyIdentity, bytesToBase64(data)));
        if (!result.success) {
            throw new Error(`Permission signing failed: ${result.error}`);
        }
        return base64ToBytes(result.signatureBase64);
    };

    return signPermissions(permissions, adminKeyId, signFn, pubKeysResult.ed25519PublicKeyBase64);
}
