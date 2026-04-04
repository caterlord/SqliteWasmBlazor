/**
 * Permission types and verification for encrypted delta sync.
 *
 * Permission model: default = full readwrite. Only diffs stored:
 * - "TableName": "readonly"              — whole table readonly
 * - "TableName.Column": "readwrite"      — column override within readonly table
 * - {} = full access (default)
 *
 * Permissions are plaintext, signed by admin, visible to all participants.
 */

import { sha256 } from '@noble/hashes/sha256';

// ============================================================
// TYPES
// ============================================================

/** Permission diff for a single participant. Key = "Table" or "Table.Column", value = "readonly" | "readwrite". */
export type PermissionDiff = Record<string, string>;

/** Map of ed25519 public key (Base64) → permission diff. */
export type PermissionMap = Record<string, PermissionDiff>;

/** Full encrypted delta envelope. */
export interface EncryptedDeltaEnvelope {
    ciphertext: Uint8Array;
    nonce: Uint8Array;
    contentSignature: Uint8Array;
    senderPublicKey: string;                          // Base64 Ed25519
    recipientEnvelopes: Record<string, Uint8Array>;   // Base64 x25519pk → wrappedKey
    permissions: PermissionMap;
    permissionsSignature: Uint8Array;
    adminPublicKey: string;                           // Base64 Ed25519
}

/** Result of a write access check. */
export interface AccessCheckResult {
    allowed: boolean;
    reason?: string;
}

/** Signature verification function (injected — real or mock). */
export type VerifyFn = (data: Uint8Array, signature: Uint8Array, publicKey: string) => boolean;

/** Signing function (injected — real or mock). */
export type SignFn = (data: Uint8Array, keyIdentity: string) => Uint8Array;

// ============================================================
// PERMISSION HASHING (deterministic canonical form)
// ============================================================

/**
 * Compute a deterministic SHA-256 hash of a PermissionMap.
 * Keys are sorted alphabetically for canonical ordering.
 */
export function hashPermissions(permissions: PermissionMap): Uint8Array {
    const encoder = new TextEncoder();
    const parts: Uint8Array[] = [];

    // Sort outer keys (participant public keys)
    const sortedPks = Object.keys(permissions).sort();

    for (const pk of sortedPks) {
        parts.push(encoder.encode(pk));

        const diff = permissions[pk];
        const sortedDiffKeys = Object.keys(diff).sort();

        for (const key of sortedDiffKeys) {
            parts.push(encoder.encode(key));
            parts.push(encoder.encode(diff[key]));
        }
    }

    // Concatenate all parts
    const totalLength = parts.reduce((sum, p) => sum + p.length, 0);
    const combined = new Uint8Array(totalLength);
    let offset = 0;
    for (const part of parts) {
        combined.set(part, offset);
        offset += part.length;
    }

    return sha256(combined);
}

// ============================================================
// SIGNATURE VERIFICATION
// ============================================================

/**
 * Verify the content signature on a delta's ciphertext.
 */
export function verifyContentSignature(
    ciphertext: Uint8Array,
    contentSignature: Uint8Array,
    senderPublicKey: string,
    verifyFn: VerifyFn
): boolean {
    return verifyFn(ciphertext, contentSignature, senderPublicKey);
}

/**
 * Verify the admin's signature on the permissions.
 */
export function verifyPermissionsSignature(
    permissions: PermissionMap,
    permissionsSignature: Uint8Array,
    adminPublicKey: string,
    verifyFn: VerifyFn
): boolean {
    const permHash = hashPermissions(permissions);
    return verifyFn(permHash, permissionsSignature, adminPublicKey);
}

/**
 * Sign a PermissionMap with the admin's key.
 * Returns the signature and the admin's public key.
 */
export function signPermissions(
    permissions: PermissionMap,
    adminIdentity: string,
    signFn: SignFn,
    adminPublicKey: string
): { permissionsSignature: Uint8Array; adminPublicKey: string } {
    const permHash = hashPermissions(permissions);
    const permissionsSignature = signFn(permHash, adminIdentity);
    return { permissionsSignature, adminPublicKey };
}

// ============================================================
// WRITE ACCESS CHECK
// ============================================================

/**
 * Check whether a sender is allowed to write to the given table/columns.
 *
 * Logic:
 * 1. Sender must be in the permissions map
 * 2. Default (empty diff) = full readwrite access
 * 3. "Table": "readonly" → no writes to that table (unless column overrides)
 * 4. "Table.Column": "readwrite" → that specific column IS writable even if table is readonly
 * 5. Columns not overridden on a readonly table → rejected
 */
export function checkWriteAccess(
    permissions: PermissionMap,
    senderEd25519Pk: string,
    tableName: string,
    columnNames: string[]
): AccessCheckResult {
    // Sender must be in permissions
    if (!(senderEd25519Pk in permissions)) {
        return { allowed: false, reason: `Sender '${senderEd25519Pk}' not in permissions` };
    }

    const diff = permissions[senderEd25519Pk];

    // Empty diff = full access
    if (Object.keys(diff).length === 0) {
        return { allowed: true };
    }

    // Check table-level permission
    const tablePermission = diff[tableName];

    if (tablePermission === 'readonly') {
        // Table is readonly — check each column for overrides
        for (const col of columnNames) {
            const colKey = `${tableName}.${col}`;
            const colPermission = diff[colKey];

            if (colPermission !== 'readwrite') {
                return {
                    allowed: false,
                    reason: `Column '${col}' on table '${tableName}' is readonly for sender`
                };
            }
        }
        // All columns have readwrite overrides
        return { allowed: true };
    }

    // No table-level restriction = allowed (default is readwrite)
    return { allowed: true };
}
