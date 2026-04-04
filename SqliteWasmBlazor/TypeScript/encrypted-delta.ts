/**
 * Encrypted delta operations for the worker — SWBV2E format.
 *
 * Format: plaintext outer envelope + encrypted header + encrypted data.
 * A hijacked delta reveals only recipient pubkeys — no schema, no permissions, no data.
 *
 * Outer envelope (plaintext, MessagePack array — relay can read for routing):
 *   [0] "SWBV2E"                    magic
 *   [1] senderPublicKey             Ed25519 Base64 (for signature verification)
 *   [2] contentSignature            Uint8Array (Ed25519 over encryptedData)
 *   [3] recipientEnvelopes          { x25519pk: wrappedKey (Uint8Array) }
 *   [4] headerNonce                 Uint8Array (12 bytes)
 *   [5] encryptedHeader             Uint8Array (AES-GCM)
 *   [6] dataNonce                   Uint8Array (12 bytes)
 *   [7] encryptedData               Uint8Array (AES-GCM)
 *
 * Inner header (decrypted = MessagePack array):
 *   [0]-[9] original V2 header fields
 *   [10] permissions                PermissionMap
 *   [11] permissionsSignature       Uint8Array
 *   [12] adminPublicKey             string (Ed25519 Base64)
 */

import {
    encryptAesGcm, decryptAesGcm,
    encryptAsymmetricAesGcm, decryptAsymmetricCachedAesGcm,
    signWithCachedKey, ed25519Verify,
    getPublicKeys, generateRandomBytes
} from './crypto-layer';
import {
    type PermissionMap,
    verifyContentSignature, verifyPermissionsSignature,
    checkWriteAccess, hashPermissions,
    type SignFn, type VerifyFn
} from './crypto-permissions';

// ============================================================
// TYPES
// ============================================================

/** Outer envelope fields (plaintext portion) */
export interface EncryptedV2Envelope {
    magic: string;
    senderPublicKey: string;
    contentSignature: Uint8Array;
    recipientEnvelopes: Record<string, Uint8Array>;
    headerNonce: Uint8Array;
    encryptedHeader: Uint8Array;
    dataNonce: Uint8Array;
    encryptedData: Uint8Array;
}

/** Decrypted inner header (V2 header + crypto fields) */
export interface DecryptedInnerHeader {
    v2Header: any[];
    permissions: PermissionMap;
    permissionsSignature: Uint8Array;
    adminPublicKey: string;
}

// ============================================================
// BASE64 HELPERS
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
 * Build an encrypted SWBV2E envelope from a V2 header + row bytes.
 *
 * 1. Generate content key
 * 2. Build inner header (V2 header + permissions) → encrypt with content key
 * 3. Encrypt row bytes with content key
 * 4. Sign encryptedData with sender's Ed25519
 * 5. Wrap content key per recipient via X25519 ECIES
 * 6. Pack outer envelope → single MessagePack blob
 */
export async function encryptedExport(
    v2Header: any[],
    rowBytes: Uint8Array,
    keyId: string,
    recipientX25519Pks: string[],
    permissions: PermissionMap,
    permissionsSignature: Uint8Array,
    adminPublicKey: string,
    packFn: (data: any) => Uint8Array
): Promise<Uint8Array> {
    const contentKeyBase64 = generateRandomBytes(32);

    // Build inner header: V2 header [0]-[9] + permissions [10] + sig [11] + adminPk [12]
    const innerHeader = [...v2Header, permissions, permissionsSignature, adminPublicKey];
    const innerHeaderBytes = packFn(innerHeader);

    // Encrypt inner header
    const headerEncResult = JSON.parse(await encryptAesGcm(bytesToBase64(innerHeaderBytes), contentKeyBase64));
    if (!headerEncResult.success) {
        throw new Error(`Header encryption failed: ${headerEncResult.error}`);
    }

    // Encrypt row data
    const dataEncResult = JSON.parse(await encryptAesGcm(bytesToBase64(rowBytes), contentKeyBase64));
    if (!dataEncResult.success) {
        throw new Error(`Data encryption failed: ${dataEncResult.error}`);
    }

    // Sign the encrypted data
    const signResult = JSON.parse(signWithCachedKey(keyId, dataEncResult.ciphertextBase64));
    if (!signResult.success) {
        throw new Error(`Signing failed: ${signResult.error}`);
    }

    // Get sender's public key
    const pubKeysResult = JSON.parse(getPublicKeys(keyId));
    if (!pubKeysResult.success) {
        throw new Error(`Failed to get public keys: ${pubKeysResult.error}`);
    }

    // Wrap content key per recipient
    const recipientEnvelopes: Record<string, Uint8Array> = {};
    for (const recipientPk of recipientX25519Pks) {
        const wrapResult = JSON.parse(await encryptAsymmetricAesGcm(contentKeyBase64, recipientPk));
        if (!wrapResult.success) {
            throw new Error(`Key wrapping failed: ${wrapResult.error}`);
        }
        // Pack ECIES result: [ephPkLen(1) | ephPk | nonceLen(1) | nonce | ciphertext]
        const ephPk = base64ToBytes(wrapResult.ephemeralPublicKeyBase64);
        const wrappedCt = base64ToBytes(wrapResult.ciphertextBase64);
        const wrappedNonce = base64ToBytes(wrapResult.nonceBase64);
        const wrapped = new Uint8Array(1 + ephPk.length + 1 + wrappedNonce.length + wrappedCt.length);
        wrapped[0] = ephPk.length;
        wrapped.set(ephPk, 1);
        wrapped[1 + ephPk.length] = wrappedNonce.length;
        wrapped.set(wrappedNonce, 2 + ephPk.length);
        wrapped.set(wrappedCt, 2 + ephPk.length + wrappedNonce.length);
        recipientEnvelopes[recipientPk] = wrapped;
    }

    // Pack outer envelope as MessagePack array
    const outerEnvelope = [
        'SWBV2E',
        pubKeysResult.ed25519PublicKeyBase64,
        base64ToBytes(signResult.signatureBase64),
        recipientEnvelopes,
        base64ToBytes(headerEncResult.nonceBase64),
        base64ToBytes(headerEncResult.ciphertextBase64),
        base64ToBytes(dataEncResult.nonceBase64),
        base64ToBytes(dataEncResult.ciphertextBase64)
    ];

    return packFn(outerEnvelope);
}

// ============================================================
// ENCRYPTED IMPORT
// ============================================================

/**
 * Unpack and decrypt a SWBV2E envelope.
 * Returns the V2 header and decrypted row bytes for bulk import.
 *
 * 1. Unpack outer envelope
 * 2. Unwrap content key from recipientEnvelopes
 * 3. Verify contentSignature over encryptedData
 * 4. Decrypt header → get V2 header + permissions
 * 5. Verify permissionsSignature
 * 6. Check sender's write access
 * 7. Decrypt data → row bytes
 */
export async function encryptedImport(
    envelopeBytes: Uint8Array,
    keyId: string,
    tableName: string,
    columnNames: string[],
    unpackFn: (data: Uint8Array) => any
): Promise<{ v2Header: any[]; rowBytes: Uint8Array; permissions: PermissionMap; adminPublicKey: string }> {
    const verifyFn: VerifyFn = (data, signature, publicKey) => {
        return ed25519Verify(bytesToBase64(data), bytesToBase64(signature), publicKey);
    };

    // 1. Unpack outer envelope
    const outer = unpackFn(envelopeBytes) as any[];
    if (outer[0] !== 'SWBV2E') {
        throw new Error(`Invalid magic: expected SWBV2E, got ${outer[0]}`);
    }

    const senderPublicKey = outer[1] as string;
    const contentSignature = outer[2] as Uint8Array;
    const recipientEnvelopes = outer[3] as Record<string, Uint8Array>;
    const headerNonce = outer[4] as Uint8Array;
    const encryptedHeader = outer[5] as Uint8Array;
    const dataNonce = outer[6] as Uint8Array;
    const encryptedData = outer[7] as Uint8Array;

    // 2. Unwrap content key
    const pubKeysResult = JSON.parse(getPublicKeys(keyId));
    if (!pubKeysResult.success) {
        throw new Error('Failed to get own public keys');
    }
    const myX25519Pk = pubKeysResult.x25519PublicKeyBase64;

    const wrappedKeyBlob = recipientEnvelopes[myX25519Pk];
    if (!wrappedKeyBlob) {
        throw new Error('Delta not encrypted for this recipient');
    }

    // Unpack ECIES blob: [ephPkLen(1) | ephPk | nonceLen(1) | nonce | ciphertext]
    const ephPkLen = wrappedKeyBlob[0];
    const ephPk = wrappedKeyBlob.slice(1, 1 + ephPkLen);
    const wrapNonceLen = wrappedKeyBlob[1 + ephPkLen];
    const wrapNonce = wrappedKeyBlob.slice(2 + ephPkLen, 2 + ephPkLen + wrapNonceLen);
    const wrapCt = wrappedKeyBlob.slice(2 + ephPkLen + wrapNonceLen);

    const unwrapResult = JSON.parse(await decryptAsymmetricCachedAesGcm(
        keyId, bytesToBase64(ephPk), bytesToBase64(wrapCt), bytesToBase64(wrapNonce)
    ));
    if (!unwrapResult.success) {
        throw new Error(`Key unwrapping failed: ${unwrapResult.error}`);
    }
    const contentKeyBase64 = unwrapResult.plaintextBase64;

    // 3. Verify content signature over encrypted data
    if (!verifyContentSignature(encryptedData, contentSignature, senderPublicKey, verifyFn)) {
        throw new Error('Content signature verification failed');
    }

    // 4. Decrypt header
    const headerDecResult = JSON.parse(await decryptAesGcm(
        bytesToBase64(encryptedHeader), bytesToBase64(headerNonce), contentKeyBase64
    ));
    if (!headerDecResult.success) {
        throw new Error(`Header decryption failed: ${headerDecResult.error}`);
    }
    const innerHeader = unpackFn(base64ToBytes(headerDecResult.plaintextBase64)) as any[];

    const v2Header = innerHeader.slice(0, 10);
    const permissions = innerHeader[10] as PermissionMap;
    const permissionsSignature = innerHeader[11] as Uint8Array;
    const adminPublicKey = innerHeader[12] as string;

    // 5. Verify permissions signature
    if (!verifyPermissionsSignature(permissions, permissionsSignature, adminPublicKey, verifyFn)) {
        throw new Error('Permissions signature verification failed');
    }

    // 6. Check sender's write access
    const accessResult = checkWriteAccess(permissions, senderPublicKey, tableName, columnNames);
    if (!accessResult.allowed) {
        throw new Error(`Write access denied: ${accessResult.reason}`);
    }

    // 7. Decrypt data
    const dataDecResult = JSON.parse(await decryptAesGcm(
        bytesToBase64(encryptedData), bytesToBase64(dataNonce), contentKeyBase64
    ));
    if (!dataDecResult.success) {
        throw new Error(`Data decryption failed: ${dataDecResult.error}`);
    }

    return {
        v2Header,
        rowBytes: base64ToBytes(dataDecResult.plaintextBase64),
        permissions,
        adminPublicKey
    };
}

// ============================================================
// PERMISSION SIGNING HELPER
// ============================================================

/**
 * Sign a permission map using the cached admin key.
 */
export function signPermissionsWithCachedKey(
    permissions: PermissionMap,
    adminKeyId: string
): { permissionsSignature: Uint8Array; adminPublicKey: string } {
    const pubKeysResult = JSON.parse(getPublicKeys(adminKeyId));
    if (!pubKeysResult.success) {
        throw new Error('Failed to get admin public keys');
    }

    const permHash = hashPermissions(permissions);
    const signResult = JSON.parse(signWithCachedKey(adminKeyId, bytesToBase64(permHash)));
    if (!signResult.success) {
        throw new Error(`Permission signing failed: ${signResult.error}`);
    }

    return {
        permissionsSignature: base64ToBytes(signResult.signatureBase64),
        adminPublicKey: pubKeysResult.ed25519PublicKeyBase64
    };
}
