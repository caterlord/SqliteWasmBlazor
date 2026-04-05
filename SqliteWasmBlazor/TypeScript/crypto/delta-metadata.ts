/**
 * Delta metadata persistence for the worker.
 *
 * Manages the _deltaMetadata table (JSON key-value store) in each encrypted database.
 * Caches metadata in memory for fast access during permission enforcement.
 *
 * Keys:
 * - "permissions"      → PermissionMap JSON (who can write what)
 * - "adminPublicKey"   → Base64 Ed25519 trust chain root
 * - "myPublicKey"      → Base64 Ed25519 of current user (for sender lookup)
 * - "encryptedTables"  → JSON array of table names needing column encryption (Phase 3)
 */

import { type PermissionMap, checkWriteAccess, type AccessCheckResult } from './crypto-permissions';

// ============================================================
// TYPES
// ============================================================

export interface DeltaMetadataCache {
    permissions: PermissionMap | null;
    adminPublicKey: string | null;
    myPublicKey: string | null;
    encryptedTables: string[] | null;
}

// Per-database metadata cache
const metadataCache = new Map<string, DeltaMetadataCache>();

// ============================================================
// TABLE MANAGEMENT
// ============================================================

const CREATE_TABLE_SQL = `CREATE TABLE IF NOT EXISTS _deltaMetadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
)`;

/**
 * Ensure the _deltaMetadata table exists in the database.
 */
export function ensureMetadataTable(db: any): void {
    db.exec(CREATE_TABLE_SQL);
}

// ============================================================
// PERSISTENCE (read/write to SQLite)
// ============================================================

/**
 * Load all metadata from the _deltaMetadata table into the in-memory cache.
 * Called on database open.
 */
export function loadMetadata(db: any, dbName: string): void {
    const cache: DeltaMetadataCache = {
        permissions: null,
        adminPublicKey: null,
        myPublicKey: null,
        encryptedTables: null,
    };

    // Check if table exists
    const tableCheck = db.exec({
        sql: `SELECT name FROM sqlite_master WHERE type='table' AND name='_deltaMetadata'`,
        returnValue: 'resultRows',
        rowMode: 'array'
    });

    if (!tableCheck || tableCheck.length === 0) {
        metadataCache.set(dbName, cache);
        return;
    }

    // Load all rows
    const rows = db.exec({
        sql: `SELECT key, value FROM _deltaMetadata`,
        returnValue: 'resultRows',
        rowMode: 'array'
    }) as [string, string][];

    if (rows) {
        for (const [key, value] of rows) {
            switch (key) {
                case 'permissions':
                    cache.permissions = JSON.parse(value) as PermissionMap;
                    break;
                case 'adminPublicKey':
                    cache.adminPublicKey = value;
                    break;
                case 'myPublicKey':
                    cache.myPublicKey = value;
                    break;
                case 'encryptedTables':
                    cache.encryptedTables = JSON.parse(value) as string[];
                    break;
            }
        }
    }

    metadataCache.set(dbName, cache);
}

function getOrCreateCache(dbName: string): DeltaMetadataCache {
    let cache = metadataCache.get(dbName);
    if (!cache) {
        cache = { permissions: null, adminPublicKey: null, myPublicKey: null, encryptedTables: null };
        metadataCache.set(dbName, cache);
    }
    return cache;
}

/**
 * Write a single metadata key-value pair to the database and update the cache.
 */
export function setMetadata(db: any, dbName: string, key: string, value: string): void {
    ensureMetadataTable(db);

    db.exec({
        sql: `INSERT OR REPLACE INTO _deltaMetadata (key, value) VALUES (?, ?)`,
        bind: [key, value]
    });

    // Update cache
    const cache = getOrCreateCache(dbName);
    switch (key) {
        case 'permissions':
            cache.permissions = JSON.parse(value) as PermissionMap;
            break;
        case 'adminPublicKey':
            cache.adminPublicKey = value;
            break;
        case 'myPublicKey':
            cache.myPublicKey = value;
            break;
        case 'encryptedTables':
            cache.encryptedTables = JSON.parse(value) as string[];
            break;
    }
}

/**
 * Update permissions and admin public key from an incoming delta.
 * Writes to DB and updates cache atomically.
 */
export function updatePermissionsFromDelta(
    db: any,
    dbName: string,
    permissions: PermissionMap,
    adminPublicKey: string
): void {
    ensureMetadataTable(db);

    db.exec("BEGIN");
    try {
        db.exec({
            sql: `INSERT OR REPLACE INTO _deltaMetadata (key, value) VALUES (?, ?)`,
            bind: ['permissions', JSON.stringify(permissions)]
        });
        db.exec({
            sql: `INSERT OR REPLACE INTO _deltaMetadata (key, value) VALUES (?, ?)`,
            bind: ['adminPublicKey', adminPublicKey]
        });
        db.exec("COMMIT");
    } catch (error) {
        try { db.exec("ROLLBACK"); } catch { /* ignore */ }
        throw error;
    }

    // Update cache
    const cache = getOrCreateCache(dbName);
    cache.permissions = permissions;
    cache.adminPublicKey = adminPublicKey;
}

/**
 * Get the cached metadata for a database.
 */
export function getMetadataCache(dbName: string): DeltaMetadataCache | null {
    return metadataCache.get(dbName) ?? null;
}

/**
 * Clear cached metadata when a database is closed.
 */
export function clearMetadataCache(dbName: string): void {
    metadataCache.delete(dbName);
}

// ============================================================
// WRITE ENFORCEMENT
// ============================================================

/** Regex patterns for common EF Core SQL write operations */
const INSERT_PATTERN = /^\s*INSERT\s+(?:OR\s+\w+\s+)?INTO\s+"?(\w+)"?/i;
const UPDATE_PATTERN = /^\s*UPDATE\s+"?(\w+)"?/i;
const DELETE_PATTERN = /^\s*DELETE\s+FROM\s+"?(\w+)"?/i;

/**
 * Extract the target table name from a SQL write statement.
 * Returns null for non-write statements (SELECT, PRAGMA, CREATE, etc.).
 */
export function extractWriteTable(sql: string): string | null {
    const insertMatch = sql.match(INSERT_PATTERN);
    if (insertMatch) {
        return insertMatch[1];
    }

    const updateMatch = sql.match(UPDATE_PATTERN);
    if (updateMatch) {
        return updateMatch[1];
    }

    const deleteMatch = sql.match(DELETE_PATTERN);
    if (deleteMatch) {
        return deleteMatch[1];
    }

    return null;
}

/**
 * Extract column names from an INSERT statement.
 * Returns empty array if columns can't be parsed (enforcement falls back to table-level).
 */
export function extractInsertColumns(sql: string): string[] {
    // Match: INSERT INTO "Table" ("Col1", "Col2", ...) VALUES
    const match = sql.match(/INSERT\s+(?:OR\s+\w+\s+)?INTO\s+"?\w+"?\s*\(([^)]+)\)/i);
    if (!match) {
        return [];
    }

    return match[1]
        .split(',')
        .map(col => col.trim().replace(/"/g, ''));
}

/**
 * Extract column names from an UPDATE SET clause.
 * Returns empty array if columns can't be parsed.
 */
export function extractUpdateColumns(sql: string): string[] {
    // Match: UPDATE "Table" SET "Col1" = ?, "Col2" = ?
    const setMatch = sql.match(/SET\s+(.+?)(?:\s+WHERE\s|$)/i);
    if (!setMatch) {
        return [];
    }

    const assignments = setMatch[1].split(',');
    return assignments
        .map(a => a.trim().split(/\s*=\s*/)[0].replace(/"/g, '').trim())
        .filter(col => col.length > 0);
}

/**
 * Enforce write permissions for a SQL statement.
 * Returns null if allowed, or an AccessCheckResult with rejection reason.
 *
 * Skips enforcement for:
 * - Internal tables (_deltaMetadata, sqlite_*)
 * - Non-write statements (SELECT, PRAGMA, etc.)
 * - Databases without cached permissions
 */
export function enforceWritePermission(dbName: string, sql: string): AccessCheckResult | null {
    const cache = metadataCache.get(dbName);
    if (!cache || !cache.permissions || !cache.myPublicKey) {
        return null; // No permissions set — enforcement not active
    }

    const tableName = extractWriteTable(sql);
    if (tableName === null) {
        return null; // Not a write statement
    }

    // Skip internal/system tables
    if (tableName.startsWith('_') || tableName.startsWith('sqlite_') || tableName === 'ef_migrations') {
        return null;
    }

    // Extract columns for granular check
    let columns: string[] = [];
    if (sql.match(/^\s*INSERT/i)) {
        columns = extractInsertColumns(sql);
    } else if (sql.match(/^\s*UPDATE/i)) {
        columns = extractUpdateColumns(sql);
    }
    // DELETE = table-level check only (empty columns)

    const result = checkWriteAccess(cache.permissions, cache.myPublicKey, tableName, columns);
    if (!result.allowed) {
        return result;
    }

    return null; // Allowed
}
