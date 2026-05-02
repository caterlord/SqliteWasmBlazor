// Registry that maps OPFS paths to per-DB ChaCha20-Poly1305 keys for the
// PRF-keyed VFS. A path is "encrypted" iff it has an entry here.
//
// The registry is populated before the DB is opened (so xOpen can pick up
// the key) and cleared on close (clearBytes wipes the buffer first).

import { clearBytes } from '@sqlitewasmblazor/crypto-core';

const pathToKey = new Map<string, Uint8Array>();

// Transfers ownership of `key` to the registry. If the path already has a
// live key, the new key is wiped and rejected so a file handle cannot keep
// using an old buffer that the registry no longer owns.
export function registerKeyForPath(path: string, key: Uint8Array): void {
    const existing = pathToKey.get(path);
    if (existing !== undefined) {
        if (existing !== key) {
            clearBytes(key);
        }
        throw new Error(
            `Encryption key is already registered for ${path}; clear it before registering a new key.`
        );
    }
    pathToKey.set(path, key);
}

export function getKeyForPath(path: string): Uint8Array | undefined {
    return pathToKey.get(path);
}

export function clearKeyForPath(path: string): void {
    const key = pathToKey.get(path);
    if (key !== undefined) {
        clearBytes(key);
        pathToKey.delete(path);
    }
}

export function isPathEncrypted(path: string): boolean {
    return pathToKey.has(path);
}
