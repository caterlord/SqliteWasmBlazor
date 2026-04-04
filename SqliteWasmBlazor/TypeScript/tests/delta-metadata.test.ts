import { describe, it, expect } from 'vitest';
import {
    extractWriteTable, extractInsertColumns, extractUpdateColumns,
    enforceWritePermission
} from '../crypto/delta-metadata';
import { type PermissionMap, hashPermissions } from '../crypto/crypto-permissions';

// Note: We can't test the full DB persistence in vitest (no SQLite in Node).
// Those paths are tested via Playwright integration tests.
// Here we test the pure logic: SQL parsing and permission enforcement.

// ============================================================
// SQL PARSING TESTS
// ============================================================

describe('extractWriteTable', () => {
    it('detects INSERT INTO', () => {
        expect(extractWriteTable('INSERT INTO "ShoppingItems" ("Id", "Name") VALUES (?, ?)')).toBe('ShoppingItems');
    });

    it('detects INSERT OR REPLACE', () => {
        expect(extractWriteTable('INSERT OR REPLACE INTO "ShoppingItems" ("Id") VALUES (?)')).toBe('ShoppingItems');
    });

    it('detects UPDATE', () => {
        expect(extractWriteTable('UPDATE "ShoppingItems" SET "Name" = ? WHERE "Id" = ?')).toBe('ShoppingItems');
    });

    it('detects DELETE FROM', () => {
        expect(extractWriteTable('DELETE FROM "ShoppingItems" WHERE "Id" = ?')).toBe('ShoppingItems');
    });

    it('returns null for SELECT', () => {
        expect(extractWriteTable('SELECT * FROM "ShoppingItems"')).toBeNull();
    });

    it('returns null for PRAGMA', () => {
        expect(extractWriteTable('PRAGMA journal_mode = WAL')).toBeNull();
    });

    it('returns null for CREATE TABLE', () => {
        expect(extractWriteTable('CREATE TABLE IF NOT EXISTS "Foo" (id INTEGER)')).toBeNull();
    });

    it('handles unquoted table names', () => {
        expect(extractWriteTable('INSERT INTO ShoppingItems (Id) VALUES (?)')).toBe('ShoppingItems');
    });

    it('handles leading whitespace', () => {
        expect(extractWriteTable('  INSERT INTO "Items" ("Id") VALUES (?)')).toBe('Items');
    });
});

describe('extractInsertColumns', () => {
    it('extracts quoted columns', () => {
        const cols = extractInsertColumns('INSERT INTO "ShoppingItems" ("Id", "Name", "Price") VALUES (?, ?, ?)');
        expect(cols).toEqual(['Id', 'Name', 'Price']);
    });

    it('extracts unquoted columns', () => {
        const cols = extractInsertColumns('INSERT INTO Items (Id, Name) VALUES (?, ?)');
        expect(cols).toEqual(['Id', 'Name']);
    });

    it('returns empty for no columns clause', () => {
        const cols = extractInsertColumns('INSERT INTO Items VALUES (?, ?)');
        expect(cols).toEqual([]);
    });
});

describe('extractUpdateColumns', () => {
    it('extracts SET columns', () => {
        const cols = extractUpdateColumns('UPDATE "ShoppingItems" SET "Name" = ?, "Price" = ? WHERE "Id" = ?');
        expect(cols).toEqual(['Name', 'Price']);
    });

    it('handles unquoted columns', () => {
        const cols = extractUpdateColumns('UPDATE Items SET Name = ?, IsBought = ? WHERE Id = ?');
        expect(cols).toEqual(['Name', 'IsBought']);
    });
});

// ============================================================
// WRITE ENFORCEMENT TESTS
// ============================================================

// enforceWritePermission uses an internal cache. We can't set it directly
// without the DB, but we can test the function returns null when no cache exists.

describe('enforceWritePermission (no cache)', () => {
    it('returns null when no metadata cached for database', () => {
        const result = enforceWritePermission('uncached-db', 'INSERT INTO "Foo" ("Id") VALUES (?)');
        expect(result).toBeNull();
    });

    it('returns null for SELECT even with no cache', () => {
        const result = enforceWritePermission('uncached-db', 'SELECT * FROM "Foo"');
        expect(result).toBeNull();
    });
});

// ============================================================
// HASH PERMISSIONS (imported from crypto-permissions, tested here for coverage)
// ============================================================

describe('hashPermissions consistency', () => {
    it('empty permissions produce consistent hash', () => {
        const perms: PermissionMap = {};
        const h1 = hashPermissions(perms);
        const h2 = hashPermissions(perms);
        expect(h1).toEqual(h2);
    });

    it('single entry produces 32-byte hash', () => {
        const perms: PermissionMap = { 'pk-a': { 'Table': 'readonly' } };
        const hash = hashPermissions(perms);
        expect(hash.length).toBe(32);
    });
});
