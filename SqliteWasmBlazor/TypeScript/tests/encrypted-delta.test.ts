import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { pack, unpack } from 'msgpackr';
import {
    storeKeys, getPublicKeys, clearAllKeys, generateRandomBytes,
    ed25519Verify, signWithCachedKey
} from '../crypto/crypto-layer';
import {
    hashPermissions, verifyContentSignature, verifyPermissionsSignature,
    checkWriteAccess, type PermissionMap, type VerifyFn
} from '../crypto/crypto-permissions';
import {
    encryptedExport, encryptedImport, signPermissionsWithCachedKey
} from '../crypto/encrypted-delta';

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

const ALICE_KEY = 'alice';
const BOB_KEY = 'bob';
const TOM_KEY = 'tom';

let aliceEd25519Pk: string;
let aliceX25519Pk: string;
let bobEd25519Pk: string;
let bobX25519Pk: string;
let tomEd25519Pk: string;
let tomX25519Pk: string;

// Sample V2 header and row data
const TEST_V2_HEADER = [
    'SWBV2', 'hash123', 'TodoItem', null,
    new Date().toISOString(), 2, 1, 'TodoItems',
    [['Id', 'TEXT', 'Guid'], ['Title', 'TEXT', 'String'], ['IsCompleted', 'INTEGER', 'Boolean']],
    'Id'
];

const TEST_ROW_1 = ['id-1', 'Buy milk', 0];
const TEST_ROW_2 = ['id-2', 'Buy eggs', 1];
const TEST_ROW_BYTES = new Uint8Array([
    ...pack(TEST_ROW_1),
    ...pack(TEST_ROW_2)
]);

beforeAll(async () => {
    const aliceResult = JSON.parse(await storeKeys(ALICE_KEY, generateRandomBytes(32), null));
    const bobResult = JSON.parse(await storeKeys(BOB_KEY, generateRandomBytes(32), null));
    const tomResult = JSON.parse(await storeKeys(TOM_KEY, generateRandomBytes(32), null));

    aliceEd25519Pk = aliceResult.ed25519PublicKeyBase64;
    aliceX25519Pk = aliceResult.x25519PublicKeyBase64;
    bobEd25519Pk = bobResult.ed25519PublicKeyBase64;
    bobX25519Pk = bobResult.x25519PublicKeyBase64;
    tomEd25519Pk = tomResult.ed25519PublicKeyBase64;
    tomX25519Pk = tomResult.x25519PublicKeyBase64;
});

afterAll(() => { clearAllKeys(); });

// ============================================================
// PERMISSION TESTS
// ============================================================

describe('Permission hashing', () => {
    it('is deterministic', () => {
        const perms: PermissionMap = { 'pk-a': {}, 'pk-b': { 'Table': 'readonly' } };
        expect(bytesToBase64(hashPermissions(perms))).toBe(bytesToBase64(hashPermissions(perms)));
    });

    it('different inputs produce different hashes', () => {
        const p1: PermissionMap = { 'pk-a': {} };
        const p2: PermissionMap = { 'pk-a': { 'Table': 'readonly' } };
        expect(bytesToBase64(hashPermissions(p1))).not.toBe(bytesToBase64(hashPermissions(p2)));
    });

    it('key order does not affect hash', () => {
        const p1: PermissionMap = { 'pk-a': {}, 'pk-b': {} };
        const p2: PermissionMap = { 'pk-b': {}, 'pk-a': {} };
        expect(bytesToBase64(hashPermissions(p1))).toBe(bytesToBase64(hashPermissions(p2)));
    });
});

describe('checkWriteAccess', () => {
    function getPerms(): PermissionMap {
        return {
            [aliceEd25519Pk]: {},
            [bobEd25519Pk]: {},
            [tomEd25519Pk]: { 'TodoItems': 'readonly', 'TodoItems.IsCompleted': 'readwrite' }
        };
    }

    it('default {} = full access', () => {
        expect(checkWriteAccess(getPerms(), aliceEd25519Pk, 'TodoItems', ['Title', 'IsCompleted']).allowed).toBe(true);
    });

    it('readonly table rejects write', () => {
        const r = checkWriteAccess(getPerms(), tomEd25519Pk, 'TodoItems', ['Title']);
        expect(r.allowed).toBe(false);
    });

    it('column override allows write on readonly table', () => {
        expect(checkWriteAccess(getPerms(), tomEd25519Pk, 'TodoItems', ['IsCompleted']).allowed).toBe(true);
    });

    it('unknown sender rejected', () => {
        expect(checkWriteAccess(getPerms(), 'unknown', 'TodoItems', ['Title']).allowed).toBe(false);
    });
});

describe('Permission signing', () => {
    function getPerms(): PermissionMap {
        return {
            [aliceEd25519Pk]: {},
            [bobEd25519Pk]: {},
            [tomEd25519Pk]: { 'TodoItems': 'readonly', 'TodoItems.IsCompleted': 'readwrite' }
        };
    }

    it('sign + verify roundtrip', () => {
        const perms = getPerms();
        const { permissionsSignature, adminPublicKey } = signPermissionsWithCachedKey(perms, ALICE_KEY);
        expect(verifyPermissionsSignature(perms, permissionsSignature, adminPublicKey, verifyFn)).toBe(true);
    });

    it('tampered permissions fail', () => {
        const perms = getPerms();
        const { permissionsSignature, adminPublicKey } = signPermissionsWithCachedKey(perms, ALICE_KEY);
        perms[tomEd25519Pk] = {};
        expect(verifyPermissionsSignature(perms, permissionsSignature, adminPublicKey, verifyFn)).toBe(false);
    });

    it('wrong admin key fails', () => {
        const perms = getPerms();
        const { permissionsSignature } = signPermissionsWithCachedKey(perms, ALICE_KEY);
        expect(verifyPermissionsSignature(perms, permissionsSignature, bobEd25519Pk, verifyFn)).toBe(false);
    });
});

describe('Content signature', () => {
    it('valid signature passes', () => {
        const data = new Uint8Array([1, 2, 3, 4, 5]);
        const sig = base64ToBytes(JSON.parse(signWithCachedKey(ALICE_KEY, bytesToBase64(data))).signatureBase64);
        expect(verifyContentSignature(data, sig, aliceEd25519Pk, verifyFn)).toBe(true);
    });

    it('tampered data fails', () => {
        const data = new Uint8Array([1, 2, 3, 4, 5]);
        const sig = base64ToBytes(JSON.parse(signWithCachedKey(ALICE_KEY, bytesToBase64(data))).signatureBase64);
        expect(verifyContentSignature(new Uint8Array([1, 2, 3, 4, 6]), sig, aliceEd25519Pk, verifyFn)).toBe(false);
    });

    it('wrong sender key fails', () => {
        const data = new Uint8Array([1, 2, 3, 4, 5]);
        const sig = base64ToBytes(JSON.parse(signWithCachedKey(ALICE_KEY, bytesToBase64(data))).signatureBase64);
        expect(verifyContentSignature(data, sig, bobEd25519Pk, verifyFn)).toBe(false);
    });
});

// ============================================================
// SWBV2E FULL PIPELINE TESTS
// ============================================================

describe('SWBV2E encrypted delta pipeline', () => {
    function getPerms(): PermissionMap {
        return {
            [aliceEd25519Pk]: {},
            [bobEd25519Pk]: {},
            [tomEd25519Pk]: { 'TodoItems': 'readonly', 'TodoItems.IsCompleted': 'readwrite' }
        };
    }

    async function buildEnvelope(senderKeyId: string, recipients: string[], perms: PermissionMap) {
        const { permissionsSignature, adminPublicKey } = signPermissionsWithCachedKey(perms, ALICE_KEY);
        return encryptedExport(
            TEST_V2_HEADER, TEST_ROW_BYTES, senderKeyId,
            recipients, perms, permissionsSignature, adminPublicKey,
            pack
        );
    }

    it('export produces valid SWBV2E binary', async () => {
        const bytes = await buildEnvelope(ALICE_KEY, [aliceX25519Pk, bobX25519Pk, tomX25519Pk], getPerms());
        const outer = unpack(bytes) as any[];
        expect(outer[0]).toBe('SWBV2E');
        expect(outer[1]).toBe(aliceEd25519Pk); // sender
        expect(outer[2]).toBeInstanceOf(Uint8Array); // contentSignature
        expect(Object.keys(outer[3])).toHaveLength(3); // 3 recipients
    });

    it('Alice (admin) can decrypt', async () => {
        const bytes = await buildEnvelope(ALICE_KEY, [aliceX25519Pk, bobX25519Pk], getPerms());
        const result = await encryptedImport(bytes, ALICE_KEY, 'TodoItems', ['Title'], unpack);

        expect(result.v2Header[0]).toBe('SWBV2');
        expect(result.v2Header[7]).toBe('TodoItems');
        expect(result.rowBytes).toEqual(TEST_ROW_BYTES);
        expect(result.permissions).toEqual(getPerms());
    });

    it('Bob (full access) can decrypt', async () => {
        const bytes = await buildEnvelope(ALICE_KEY, [aliceX25519Pk, bobX25519Pk], getPerms());
        const result = await encryptedImport(bytes, BOB_KEY, 'TodoItems', ['Title'], unpack);
        expect(result.rowBytes).toEqual(TEST_ROW_BYTES);
    });

    it('Tom can write IsCompleted', async () => {
        const bytes = await buildEnvelope(TOM_KEY, [aliceX25519Pk, tomX25519Pk], getPerms());
        const result = await encryptedImport(bytes, ALICE_KEY, 'TodoItems', ['IsCompleted'], unpack);
        expect(result.rowBytes).toEqual(TEST_ROW_BYTES);
    });

    it('Tom rejected writing Title', async () => {
        const bytes = await buildEnvelope(TOM_KEY, [aliceX25519Pk, tomX25519Pk], getPerms());
        await expect(
            encryptedImport(bytes, ALICE_KEY, 'TodoItems', ['Title'], unpack)
        ).rejects.toThrow('Write access denied');
    });

    it('tampered ciphertext fails signature', async () => {
        const bytes = await buildEnvelope(ALICE_KEY, [aliceX25519Pk, bobX25519Pk], getPerms());
        const outer = unpack(bytes) as any[];
        // Tamper encrypted data
        (outer[7] as Uint8Array)[0] ^= 0xFF;
        const tampered = pack(outer);
        await expect(
            encryptedImport(tampered, BOB_KEY, 'TodoItems', ['Title'], unpack)
        ).rejects.toThrow('Content signature verification failed');
    });

    it('wrong recipient cannot unwrap', async () => {
        const bytes = await buildEnvelope(ALICE_KEY, [aliceX25519Pk, bobX25519Pk], getPerms());
        await expect(
            encryptedImport(bytes, TOM_KEY, 'TodoItems', ['IsCompleted'], unpack)
        ).rejects.toThrow('not encrypted for this recipient');
    });

    it('admin transfer: new admin signs permissions', async () => {
        const perms: PermissionMap = { [aliceEd25519Pk]: {}, [bobEd25519Pk]: {} };

        // Bob signs permissions as new admin
        const { permissionsSignature: bobSig, adminPublicKey: bobAdminPk } =
            signPermissionsWithCachedKey(perms, BOB_KEY);

        const bytes = await encryptedExport(
            TEST_V2_HEADER, TEST_ROW_BYTES, ALICE_KEY,
            [aliceX25519Pk, bobX25519Pk],
            perms, bobSig, bobAdminPk, pack
        );

        // Alice can decrypt and sees Bob as admin
        const result = await encryptedImport(bytes, ALICE_KEY, 'TodoItems', ['Title'], unpack);
        expect(result.adminPublicKey).toBe(bobEd25519Pk);
    });
});
