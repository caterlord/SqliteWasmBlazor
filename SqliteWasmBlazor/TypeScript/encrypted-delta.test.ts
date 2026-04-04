import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import {
    storeKeys, getPublicKeys, clearAllKeys, generateRandomBytes,
    ed25519Verify, signWithCachedKey
} from './crypto-layer';
import {
    hashPermissions, verifyContentSignature, verifyPermissionsSignature,
    checkWriteAccess, type PermissionMap, type EncryptedDeltaEnvelope, type VerifyFn
} from './crypto-permissions';
import {
    encryptedExport, encryptedImport, signPermissionsWithCachedKey
} from './encrypted-delta';

// ============================================================
// TEST HELPERS
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

const verifyFn: VerifyFn = (data, signature, publicKey) => {
    return ed25519Verify(bytesToBase64(data), bytesToBase64(signature), publicKey);
};

// Key IDs for test identities
const ALICE_KEY = 'alice';
const BOB_KEY = 'bob';
const TOM_KEY = 'tom';

// Public keys populated in beforeAll
let aliceEd25519Pk: string;
let aliceX25519Pk: string;
let bobEd25519Pk: string;
let bobX25519Pk: string;
let tomEd25519Pk: string;
let tomX25519Pk: string;

// Sample V2 payload
const TEST_V2_BYTES = new TextEncoder().encode('{"header":"SWBV2","rows":[["milk",2,3.50,false]]}');

beforeAll(async () => {
    // Store keys for all three identities (random seeds instead of PRF)
    const aliceSeed = generateRandomBytes(32);
    const bobSeed = generateRandomBytes(32);
    const tomSeed = generateRandomBytes(32);

    const aliceResult = JSON.parse(await storeKeys(ALICE_KEY, aliceSeed, null));
    const bobResult = JSON.parse(await storeKeys(BOB_KEY, bobSeed, null));
    const tomResult = JSON.parse(await storeKeys(TOM_KEY, tomSeed, null));

    aliceEd25519Pk = aliceResult.ed25519PublicKeyBase64;
    aliceX25519Pk = aliceResult.x25519PublicKeyBase64;
    bobEd25519Pk = bobResult.ed25519PublicKeyBase64;
    bobX25519Pk = bobResult.x25519PublicKeyBase64;
    tomEd25519Pk = tomResult.ed25519PublicKeyBase64;
    tomX25519Pk = tomResult.x25519PublicKeyBase64;
});

afterAll(() => {
    clearAllKeys();
});

// ============================================================
// PERMISSION HASH TESTS
// ============================================================

describe('Permission hashing', () => {
    it('is deterministic', () => {
        const perms: PermissionMap = {
            'pk-a': {},
            'pk-b': { 'Table': 'readonly' }
        };
        const hash1 = hashPermissions(perms);
        const hash2 = hashPermissions(perms);
        expect(bytesToBase64(hash1)).toBe(bytesToBase64(hash2));
    });

    it('different inputs produce different hashes', () => {
        const perms1: PermissionMap = { 'pk-a': {} };
        const perms2: PermissionMap = { 'pk-a': { 'Table': 'readonly' } };
        const hash1 = hashPermissions(perms1);
        const hash2 = hashPermissions(perms2);
        expect(bytesToBase64(hash1)).not.toBe(bytesToBase64(hash2));
    });

    it('key order does not affect hash', () => {
        const perms1: PermissionMap = { 'pk-a': {}, 'pk-b': {} };
        const perms2: PermissionMap = { 'pk-b': {}, 'pk-a': {} };
        const hash1 = hashPermissions(perms1);
        const hash2 = hashPermissions(perms2);
        expect(bytesToBase64(hash1)).toBe(bytesToBase64(hash2));
    });
});

// ============================================================
// WRITE ACCESS CHECK TESTS
// ============================================================

describe('checkWriteAccess', () => {
    const permissions: PermissionMap = {
        [aliceEd25519Pk ?? 'alice']: {},
        [bobEd25519Pk ?? 'bob']: {},
        [tomEd25519Pk ?? 'tom']: {
            'ShoppingItems': 'readonly',
            'ShoppingItems.IsBought': 'readwrite'
        }
    };

    // Rebuild permissions with actual keys (beforeAll runs before tests, not before describe)
    function getPerms(): PermissionMap {
        return {
            [aliceEd25519Pk]: {},
            [bobEd25519Pk]: {},
            [tomEd25519Pk]: {
                'ShoppingItems': 'readonly',
                'ShoppingItems.IsBought': 'readwrite'
            }
        };
    }

    it('default {} = full access', () => {
        const result = checkWriteAccess(getPerms(), aliceEd25519Pk, 'ShoppingItems', ['Name', 'Price', 'IsBought']);
        expect(result.allowed).toBe(true);
    });

    it('bob has full access (empty diff)', () => {
        const result = checkWriteAccess(getPerms(), bobEd25519Pk, 'ShoppingItems', ['Name', 'Quantity']);
        expect(result.allowed).toBe(true);
    });

    it('readonly table rejects write', () => {
        const result = checkWriteAccess(getPerms(), tomEd25519Pk, 'ShoppingItems', ['Price']);
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('readonly');
    });

    it('column override allows write on readonly table', () => {
        const result = checkWriteAccess(getPerms(), tomEd25519Pk, 'ShoppingItems', ['IsBought']);
        expect(result.allowed).toBe(true);
    });

    it('non-overridden column on readonly table rejected', () => {
        const result = checkWriteAccess(getPerms(), tomEd25519Pk, 'ShoppingItems', ['Name']);
        expect(result.allowed).toBe(false);
    });

    it('mix of allowed and disallowed columns rejected', () => {
        const result = checkWriteAccess(getPerms(), tomEd25519Pk, 'ShoppingItems', ['IsBought', 'Price']);
        expect(result.allowed).toBe(false);
    });

    it('unknown sender rejected', () => {
        const result = checkWriteAccess(getPerms(), 'unknown-pk', 'ShoppingItems', ['Name']);
        expect(result.allowed).toBe(false);
        expect(result.reason).toContain('not in permissions');
    });

    it('no columns = read-only check on readonly table passes', () => {
        const result = checkWriteAccess(getPerms(), tomEd25519Pk, 'ShoppingItems', []);
        expect(result.allowed).toBe(true);
    });

    it('unknown table with default perms = allowed', () => {
        const result = checkWriteAccess(getPerms(), aliceEd25519Pk, 'OtherTable', ['Col']);
        expect(result.allowed).toBe(true);
    });
});

// ============================================================
// PERMISSION SIGNING TESTS
// ============================================================

describe('Permission signing', () => {
    function getPerms(): PermissionMap {
        return {
            [aliceEd25519Pk]: {},
            [bobEd25519Pk]: {},
            [tomEd25519Pk]: { 'ShoppingItems': 'readonly', 'ShoppingItems.IsBought': 'readwrite' }
        };
    }

    it('sign + verify roundtrip', () => {
        const perms = getPerms();
        const { permissionsSignature, adminPublicKey } = signPermissionsWithCachedKey(perms, ALICE_KEY);
        const valid = verifyPermissionsSignature(perms, permissionsSignature, adminPublicKey, verifyFn);
        expect(valid).toBe(true);
    });

    it('tampered permissions fail verification', () => {
        const perms = getPerms();
        const { permissionsSignature, adminPublicKey } = signPermissionsWithCachedKey(perms, ALICE_KEY);

        // Tamper: give Tom full access
        perms[tomEd25519Pk] = {};

        const valid = verifyPermissionsSignature(perms, permissionsSignature, adminPublicKey, verifyFn);
        expect(valid).toBe(false);
    });

    it('wrong admin key fails verification', () => {
        const perms = getPerms();
        const { permissionsSignature } = signPermissionsWithCachedKey(perms, ALICE_KEY);

        // Verify against Bob's key instead of Alice's
        const valid = verifyPermissionsSignature(perms, permissionsSignature, bobEd25519Pk, verifyFn);
        expect(valid).toBe(false);
    });
});

// ============================================================
// CONTENT SIGNATURE TESTS
// ============================================================

describe('Content signature', () => {
    it('valid signature passes', () => {
        const data = new Uint8Array([1, 2, 3, 4, 5]);
        const signResult = JSON.parse(signWithCachedKey(ALICE_KEY, bytesToBase64(data)));
        const signature = base64ToBytes(signResult.signatureBase64);

        const valid = verifyContentSignature(data, signature, aliceEd25519Pk, verifyFn);
        expect(valid).toBe(true);
    });

    it('tampered data fails', () => {
        const data = new Uint8Array([1, 2, 3, 4, 5]);
        const signResult = JSON.parse(signWithCachedKey(ALICE_KEY, bytesToBase64(data)));
        const signature = base64ToBytes(signResult.signatureBase64);

        const tampered = new Uint8Array([1, 2, 3, 4, 6]);
        const valid = verifyContentSignature(tampered, signature, aliceEd25519Pk, verifyFn);
        expect(valid).toBe(false);
    });

    it('wrong sender key fails', () => {
        const data = new Uint8Array([1, 2, 3, 4, 5]);
        const signResult = JSON.parse(signWithCachedKey(ALICE_KEY, bytesToBase64(data)));
        const signature = base64ToBytes(signResult.signatureBase64);

        const valid = verifyContentSignature(data, signature, bobEd25519Pk, verifyFn);
        expect(valid).toBe(false);
    });
});

// ============================================================
// FULL PIPELINE TESTS (Alice's Shopping List scenario)
// ============================================================

describe('Full encrypted delta pipeline', () => {
    function getPerms(): PermissionMap {
        return {
            [aliceEd25519Pk]: {},
            [bobEd25519Pk]: {},
            [tomEd25519Pk]: { 'ShoppingItems': 'readonly', 'ShoppingItems.IsBought': 'readwrite' }
        };
    }

    function buildEnvelope(
        exportResult: Awaited<ReturnType<typeof encryptedExport>>,
        permissions: PermissionMap,
        adminKeyId: string
    ): EncryptedDeltaEnvelope {
        const { permissionsSignature, adminPublicKey } = signPermissionsWithCachedKey(permissions, adminKeyId);
        return {
            ciphertext: exportResult.ciphertext,
            nonce: exportResult.nonce,
            contentSignature: exportResult.contentSignature,
            senderPublicKey: exportResult.senderPublicKey,
            recipientEnvelopes: exportResult.recipientEnvelopes,
            permissions,
            permissionsSignature,
            adminPublicKey
        };
    }

    it('export encrypts + signs + wraps for 3 recipients', async () => {
        const result = await encryptedExport(
            TEST_V2_BYTES, ALICE_KEY,
            [aliceX25519Pk, bobX25519Pk, tomX25519Pk]
        );

        expect(result.ciphertext.length).toBeGreaterThan(0);
        expect(result.nonce.length).toBe(12); // AES-GCM nonce
        expect(result.contentSignature.length).toBe(64); // Ed25519 signature
        expect(result.senderPublicKey).toBe(aliceEd25519Pk);
        expect(Object.keys(result.recipientEnvelopes)).toHaveLength(3);
    });

    it('Alice (admin) can decrypt', async () => {
        const exportResult = await encryptedExport(
            TEST_V2_BYTES, ALICE_KEY,
            [aliceX25519Pk, bobX25519Pk, tomX25519Pk]
        );

        const envelope = buildEnvelope(exportResult, getPerms(), ALICE_KEY);
        const v2Bytes = await encryptedImport(envelope, ALICE_KEY, 'ShoppingItems', ['Name', 'Price']);

        expect(v2Bytes).toEqual(TEST_V2_BYTES);
    });

    it('Bob (full access) can decrypt', async () => {
        const exportResult = await encryptedExport(
            TEST_V2_BYTES, ALICE_KEY,
            [aliceX25519Pk, bobX25519Pk, tomX25519Pk]
        );

        const envelope = buildEnvelope(exportResult, getPerms(), ALICE_KEY);
        const v2Bytes = await encryptedImport(envelope, BOB_KEY, 'ShoppingItems', ['Name', 'Quantity']);

        expect(v2Bytes).toEqual(TEST_V2_BYTES);
    });

    it('Tom can decrypt when writing allowed columns (IsBought)', async () => {
        const exportResult = await encryptedExport(
            TEST_V2_BYTES, TOM_KEY,
            [aliceX25519Pk, bobX25519Pk, tomX25519Pk]
        );

        const perms = getPerms();
        const envelope = buildEnvelope(exportResult, perms, ALICE_KEY);

        // Tom writes IsBought column — allowed
        const v2Bytes = await encryptedImport(envelope, ALICE_KEY, 'ShoppingItems', ['IsBought']);
        expect(v2Bytes).toEqual(TEST_V2_BYTES);
    });

    it('Tom rejected when writing Price column', async () => {
        const exportResult = await encryptedExport(
            TEST_V2_BYTES, TOM_KEY,
            [aliceX25519Pk, bobX25519Pk, tomX25519Pk]
        );

        const perms = getPerms();
        const envelope = buildEnvelope(exportResult, perms, ALICE_KEY);

        // Tom writes Price — rejected (readonly, no override)
        await expect(
            encryptedImport(envelope, ALICE_KEY, 'ShoppingItems', ['Price'])
        ).rejects.toThrow('Write access denied');
    });

    it('tampered ciphertext fails signature verification', async () => {
        const exportResult = await encryptedExport(
            TEST_V2_BYTES, ALICE_KEY,
            [aliceX25519Pk, bobX25519Pk]
        );

        const perms = getPerms();
        const envelope = buildEnvelope(exportResult, perms, ALICE_KEY);

        // Tamper ciphertext
        envelope.ciphertext[0] ^= 0xFF;

        await expect(
            encryptedImport(envelope, BOB_KEY, 'ShoppingItems', ['Name'])
        ).rejects.toThrow('Content signature verification failed');
    });

    it('wrong recipient cannot unwrap', async () => {
        // Export only for Alice and Bob — Tom is excluded
        const exportResult = await encryptedExport(
            TEST_V2_BYTES, ALICE_KEY,
            [aliceX25519Pk, bobX25519Pk]
        );

        const perms = getPerms();
        const envelope = buildEnvelope(exportResult, perms, ALICE_KEY);

        await expect(
            encryptedImport(envelope, TOM_KEY, 'ShoppingItems', ['IsBought'])
        ).rejects.toThrow('not encrypted for this recipient');
    });

    it('admin transfer: new admin signs permissions', async () => {
        // Alice exports data
        const exportResult = await encryptedExport(
            TEST_V2_BYTES, ALICE_KEY,
            [aliceX25519Pk, bobX25519Pk]
        );

        const perms: PermissionMap = {
            [aliceEd25519Pk]: {},
            [bobEd25519Pk]: {}
        };

        // Bob signs permissions as new admin
        const { permissionsSignature: bobSig, adminPublicKey: bobAdminPk } =
            signPermissionsWithCachedKey(perms, BOB_KEY);

        // Old admin (Alice) signature should NOT verify with Bob's key
        const { permissionsSignature: aliceSig } = signPermissionsWithCachedKey(perms, ALICE_KEY);
        expect(verifyPermissionsSignature(perms, aliceSig, bobAdminPk, verifyFn)).toBe(false);

        // Bob's signature verifies with Bob as admin
        expect(verifyPermissionsSignature(perms, bobSig, bobAdminPk, verifyFn)).toBe(true);

        // Build envelope with Bob as admin
        const envelope: EncryptedDeltaEnvelope = {
            ...exportResult,
            permissions: perms,
            permissionsSignature: bobSig,
            adminPublicKey: bobAdminPk
        };

        const v2Bytes = await encryptedImport(envelope, ALICE_KEY, 'ShoppingItems', ['Name']);
        expect(v2Bytes).toEqual(TEST_V2_BYTES);
    });
});
