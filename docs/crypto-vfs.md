# PRF-keyed Encryption VFS

At-rest encryption for SqliteWasmBlazor databases stored in OPFS. Every
SQLite page is encrypted with ChaCha20-Poly1305 using a 32-byte key
supplied by the caller (typically PRF-derived via BlazorPRF's
`DeriveDomainKeyAsync`). Non-encrypted consumers are unaffected — the
same VFS falls through to byte-for-byte vendor SAHPool behavior when
no key is registered.

## Why

OPFS stores files in a browser-origin directory on disk in plaintext.
Full-disk encryption covers the stolen-laptop case; it does not cover
cloud backups that capture the browser profile, forensic recovery of
deleted fragments, or a running/unlocked machine. Encrypting at the VFS
layer closes those gaps — the OPFS file is opaque ciphertext whenever
the device is not actively holding the key.

## Threat model

| Attacker capability                           | Defended |
|-----------------------------------------------|----------|
| Read OPFS files offline (stolen disk, backup) | Yes      |
| Modify OPFS files (byte flips in ciphertext)  | Yes — AEAD auth fails loudly |
| Swap pages within a DB                        | Yes — AAD binds `slotIndex` |
| Swap pages between two DBs under same key     | Yes — AAD binds `dbPath`    |
| Roll back entire OPFS to earlier snapshot     | **No** — see "known limitations" |
| Same-origin in-page script (XSS, dep compromise) | **No** — see "known limitations" |
| Live-process memory dump                      | Partial — see "known limitations" |

The design target is *local file confidentiality*: a device that is at
rest or whose user is not actively unlocking the DB reveals nothing
useful from its OPFS directory. In-session and in-browser threats are
handled by higher layers (CryptoSync permissions, content security
policy, code review).

## Primitives and standards

| Role                          | Primitive                        | Standard / reference |
|-------------------------------|----------------------------------|---------------------|
| Page AEAD                     | ChaCha20-Poly1305                | RFC 8439            |
| Nonce source                  | `crypto.getRandomValues` (CSPRNG)| Web Crypto          |
| Key length                    | 256 bits (32 bytes)              | —                   |
| Nonce length                  | 96 bits (12 bytes)               | per RFC 8439        |
| AEAD tag                      | 128 bits (16 bytes)              | per RFC 8439        |

All crypto flows through `@blazorprf/crypto-core`, which wraps
`@awasm/noble` (WASM-SIMD implementations by Paul Miller) on the
symmetric + hash + KDF side and `@noble/curves` on the ECC side. The
"single crypto provider" rule means there is exactly one implementation
of each primitive in the bundle, and cross-implementation drift is
caught by BouncyCastle-backed xUnit tests that exercise the same test
vectors.

## Architectural approach

The vendor `opfs-sahpool` VFS shipped in `@sqlite.org/sqlite-wasm` keeps
its per-file state in ES private fields and exposes no subclassing or
delegation hook. Rather than patch the upstream package, we forked the
VFS into our own TypeScript module at
`SqliteWasmBlazor/TypeScript/worker/vfs-prf/sahpool-prf-vfs.ts`,
registered it under the same name (`opfs-sahpool`) and the same
directory (`/databases/`), and added conditional encryption in `xRead`,
`xWrite`, `xOpen`, and `xClose`. A single VFS serves both modes:

- **Key registered for path** → offset-remapping ChaCha20-Poly1305: each
  4096-byte logical page that SQLite writes expands to a 4124-byte
  physical slot on disk (ciphertext 4096 + nonce 12 + tag 16). The VFS
  translates every logical offset SQLite passes into a physical offset
  on the SAH, so the same scheme covers main DB, WAL frames, rollback
  journals, and temp files uniformly.
- **No key registered** → straight pass-through to the `SyncAccessHandle`,
  byte-for-byte identical to vendor.

## Page envelope

SQLite sees 4096-byte pages with `reserved_bytes=0` — it uses the full
page for content and is never told about the crypto envelope. The VFS
expands each 4096-byte logical block into a 4124-byte physical slot on
disk:

```
Logical view (what SQLite reads/writes):   [ 4096 ][ 4096 ][ 4096 ] …

Physical on disk (after SAHPool header):
┌─────────────────────────────────────┬──────────┬──────────┐
│       ciphertext  (4096 bytes)      │ nonce 12 │  tag 16  │
└─────────────────────────────────────┴──────────┴──────────┘
         ^ one 4124-byte physical slot per logical 4096-byte page
         ^ AEAD plaintext = the full 4096-byte page view
         ^ Page 1: SQLite-format-3 magic lives at plaintext offset 0 — ciphertext on disk
```

Offset translation (logical → physical, relative to `HEADER_OFFSET_DATA`):

```
slotIndex   = logicalOffset >> 12                 (∕ 4096)
physical    = slotIndex * 4124 + (logicalOffset mod 4096)
```

`xFileSize` divides the SAH size by 4124 and multiplies by 4096 to
report the logical size SQLite expects; `xTruncate` does the reverse.
The SAHPool per-file 4096-byte header region at file offset 0 is outside
the encrypted region and still holds the vendor's path/flags/digest
metadata.

Because the envelope applies uniformly to any byte offset the VFS sees,
WAL frames (`[24B frame header][4096B page]` at unaligned offsets) and
rollback journals are encrypted by exactly the same slot scheme without
needing any SQLite-level awareness. This is what enables
`journal_mode=WAL` on encrypted DBs.

Plaintext DBs (no key registered) use the same SAH layout as vendor: no
remapping, no nonce/tag tail, full 4096-byte pages at their natural
offsets, and the SQLite-format-3 magic at offset 0 of the file.

## AAD binding

Every AEAD call uses an Associated Authenticated Data parameter that
binds the ciphertext to its context:

```
AAD = "prf-vfs-v1|" + dbPath + "|" + slotIndex(LE u32)
```

- **version prefix** (`prf-vfs-v1|`) — lets us evolve the envelope
  without cross-version confusion.
- **dbPath** — prevents ciphertext swap between two DBs under the same
  key. Page 5 of DB `a.db` cannot be pasted into DB `b.db` at slot 5.
- **slotIndex** — prevents page reordering within the same DB.

File-type (MAIN_DB vs WAL vs JOURNAL) is deliberately *not* in the AAD.
SQLite's crash-recovery writes journal bytes back into the main DB at
the same offsets; binding the file-type would break replay.

## Nonce strategy

Random 96-bit nonce per write via `crypto.getRandomValues`, persisted
next to the ciphertext in the slot's 28-byte physical tail. Over 2^32 writes
under a single key the collision probability is ~2^-32 ≈ 10^-10 (one in
ten billion); over a year of aggressive PWA usage (~2^30 writes) it is
effectively zero.

Deterministic nonces derived from (key, offset) were considered and
**ruled out**: SQLite overwrites the same offset with different content
on every commit, which would produce a (key, nonce) reuse — a
catastrophic failure mode for ChaCha20-Poly1305 that leaks the Poly1305
auth key. Random per-write nonce is the only safe scheme at the VFS
layer.

## Key lifecycle (direct key path)

```
Caller supplies 32-byte key (PRF-derived, or otherwise)
   │
   ▼
SqliteWasmConnection.EncryptionKey = key
   │
   │  (EF opens connection)
   ▼
SqliteWasmConnection.OpenAsync
   │   → bridge.OpenDatabaseAsync(db, encryptionKey)
   ▼
SqliteWasmWorkerBridge (C#)
   │   VfsKeyHeader { Version=1, Key=bytes, AadVersion="v1" }
   │   MessagePack serialize → SendBinaryToWorker(bytes, metadataJson)
   │   finally: ZeroMemory(serializedBytes); header.Clear()
   ▼
[postMessage → binaryPayload]
   │
   ▼
Worker 'open' handler
   │   unpackVfsKeyHeader(bytes) → validates version + aad version
   │   registerKeyForPath(dbPath, key)  ← module-level Map<path, key>
   │   new poolUtil.OpfsSAHPoolDb(dbPath)
   │   PRAGMA page_size=4096; journal_mode=WAL
   ▼
VFS xOpen: file.key = getKeyForPath(path)
   │
   ▼
Every xRead/xWrite: ChaCha20-Poly1305 per slot with AAD
   │
   │  (on worker close)
   ▼
clearKeyForPath(dbPath) → clearBytes(key); Map.delete
```

Zeroization touchpoints:
- C# `VfsKeyHeader.Clear()` zeros the object's internal byte[].
- C# `CryptographicOperations.ZeroMemory(serializedBytes)` zeros the
  MessagePack-serialized buffer after the `postMessage` returns.
- Worker `clearBytes(key)` zeros the registry entry on close.
- Worker `plaintextScratch.fill(0)` zeros the per-op plaintext scratch
  after every `encryptedRead` / `encryptedWrite`.

## Key lifecycle (PRF / DomainKeys path)

The recommended flow for app-supplied keys: derive the 32-byte VFS key
from a WebAuthn PRF credential via BlazorPRF's `DeriveDomainKeyAsync`,
register it directly into the worker key registry, then open the DB
without a key envelope. Raw key bytes never touch a managed `byte[]`
that survives an `await`. See `BlazorPRF/Docs/DomainKeysImplementationGuide.md`
for the canonical contract; the SqliteWasmBlazor side is just a sink.

```
WebAuthn PRF ceremony (one user gesture per session)
   │  → PrfService.DeriveKeysDiscoverableAsync (or DeriveKeysAsync)
   │    → SecureKeyCache.Store("prf-seed:{salt}", seed)
   ▼
PrfService.DeriveDomainKeyAsync("sqlite-vfs:{dbName}",
                                "blazorprf/sqlite-vfs/v1|{dbName}")
   │   → HKDF-SHA256(seed, info=context, len=32)
   │   → SecureKeyCache.Store("prf-domain:sqlite-vfs:{dbName}", derived)
   │   ← PrfResult<string>.Value = cache handle
   ▼
SecureKeyCache.UseKey(handle, span =>
{
    // span = ReadOnlySpan<byte> over unmanaged memory; valid only for
    // the synchronous callback. Bridge consumes it before any await.
    installTask = bridge.InstallEncryptionKeyAsync(dbName, span);
})
await installTask;
   │
   │   bridge: VfsKeyHeader { Version=1, Key=span.ToArray(), AadVersion="v1" }
   │           MessagePack serialize → postMessage(type='registerEncryptionKey')
   │           finally: ZeroMemory(envelope); header.Clear()
   ▼
Worker 'registerEncryptionKey' handler
   │   unpackVfsKeyHeader → 32-byte key
   │   registerKeyForPath(/databases/{dbName}, key)
   ▼
EF resolves DbContextFactory<TContext>
   │   → SqliteWasmConnection.OpenAsync (no EncryptionKey set)
   │   → bridge sends plain 'open' (no binaryPayload)
   ▼
Worker 'open' handler
   │   isPathEncrypted({dbPath}) === true (registry hit)
   │   → encrypted PRAGMAs, xOpen reads getKeyForPath
```

Expiry: subscribe to `IPrfService.KeyExpired`, filter on the domain
handle (and `prf-key:{salt}` for full-session expiry), and call
`bridge.ClearEncryptionKeyAsync(dbName)` to drop the worker mirror.
Re-derivation needs a fresh user gesture — gate the page UI behind
`PrfService.HasCachedKeys()` (or `PrfModel.HasKeys` if the consumer
adopts BlazorPRF.UI's reactive model).

A working end-to-end demo lives at `SqliteWasmBlazor.TestApp/Pages/PrfVfsTest.razor`.

## SQLite storage pragmas on encrypted DBs

| PRAGMA              | Value      | Why                                                              |
|---------------------|------------|------------------------------------------------------------------|
| `page_size`         | 4096       | Matches the VFS slot size (`SECTOR_SIZE`). Any other size would desync slot boundaries. |
| `journal_mode`      | `WAL`      | Offset-remap encrypts WAL frames with the same envelope as main DB — full crash recovery. |
| `locking_mode`      | `exclusive`| Single-writer, consistent with SAHPool's single-tab semantics.   |
| `synchronous`       | `FULL`     | Durable commits (the usual trade-off).                           |

`reserved_bytes` is **not** configured (stays at 0) — SQLite sees full
4096-byte pages and the AEAD envelope lives in the 28-byte physical tail
the VFS adds transparently.

Non-encrypted DBs keep the existing WAL-based configuration.

## Auto-detection on import

`ImportDatabaseAsync` auto-detects ciphertext vs plaintext by
inspecting the first 16 bytes:

- `"SQLite format 3\0"` present → plain SQLite file, normal path with
  the byte-18 WAL-mode patch.
- Magic absent → opaque ciphertext of a PRF-VFS-encrypted DB; both the
  header validation and the byte-18 patch are skipped because they
  would corrupt the AEAD tag at slot 0.

Garbage bytes that are neither a valid SQLite file nor ciphertext will
land in OPFS and fail on the next open (either `SQLITE_NOTADB` if no
key is registered, or `SQLITE_IOERR` if one is and AEAD auth fails).

## Mode-mismatch behaviour

- Plain DB opened **with** a key → first `xRead` of page 1 fails AEAD
  auth → `xRead` returns `SQLITE_IOERR` → `SqliteException` at the
  caller. No plaintext leaks through error paths.
- Encrypted DB opened **without** a key → VFS takes pass-through; SQLite
  sees random bytes where the format-3 header should be → `SQLITE_NOTADB`
  → `SqliteException` at the caller.

Both are exercised by the TestApp's `VFS_ModeMismatch` integration test.

## Test coverage

Three layers:

1. **Integration (envelope)** — `SqliteWasmBlazor/TypeScript/worker/vfs-prf/__tests__/envelope.test.ts`
   (vitest): page-level AEAD round-trip, wrong key, AAD swap detection,
   tamper detection, nonce uniqueness, physical slot layout.
2. **Cross-library** — `SqliteWasmBlazor.CryptoSync.Tests/PrfVfsEnvelopeTests.cs`
   (xUnit + BouncyCastle): AAD bytes produced in C# match the worker's
   construction, BouncyCastle's ChaCha20-Poly1305 produces byte-identical
   output for shared inputs with `@awasm/noble`, `VfsKeyHeader`
   serializes and zeroizes as declared.
3. **End-to-end (browser)** — `SqliteWasmBlazor.TestApp` under the "VFS
   Encryption" category: full SQL round-trips through real OPFS SAHPool,
   on-disk-ciphertext verification, plain pass-through regression,
   wrong-key failure, tamper detection, mode mismatch, physical-slot
   layout invariant (`VFS_PhysicalLayout`: exported size = N × 4124),
   perf smoke.

## Known limitations

### Rollback to an earlier snapshot (accepted)

A local-file attacker (backup restore, forensic substitution, malware
with filesystem access) can replace the OPFS directory with an earlier
snapshot of the same DB. Every page decrypts correctly: same key, same
AAD at each slot, same salt in the header region. The user sees stale
state — a revoked permission row still present, a deleted secret still
there. The AAD does not bind any monotonic epoch that could catch the
rollback because no tamper-evident storage is available on the web
platform to hold that epoch.

Mitigation requires *external state the attacker cannot roll back with
the file*: a server-stored version counter, a sync-peer's latest epoch,
or hardware tamper-evident storage. For a CryptoSync-connected device
the practical mitigation is that a peer eventually delivers newer
deltas that will not apply to the replayed local state — but there is
an exploitable window until the next sync.

### Same-origin in-page attacker (out of scope)

An attacker running inside the browsing-context origin (XSS,
compromised npm dependency, malicious extension with host permissions)
does not need the encryption key. They query through the existing
worker bridge like any other code and receive plaintext rows. No
file-level encryption scheme can defend against this — the threat is
handled one layer up by CSP hardening, dependency review, and the
worker's permission-enforcement logic.

### Live-process memory dump (partial)

While the worker holds a key, the 32-byte key bytes and any page
currently being processed are present in WASM linear memory. Defense
in depth:

- `plaintextScratch` is zero-filled after every page op (so the
  "recently accessed page" exposure window is sub-microsecond, not
  hours).
- Keys are held only for the DB's open lifetime and wiped with
  `clearBytes` on close.
- The MessagePack envelope buffers that carried keys from C# are
  zeroed after `postMessage` returns.

A complete heap dump of the running worker still exposes currently-
mounted keys; the platform offers no user-space enclave to hide them.

### WAL / `.db-shm` on disk (accepted)

`journal_mode=WAL` puts the WAL file (`*.db-wal`) and shared-memory
index (`*.db-shm`) in OPFS alongside the main DB. Every byte — including
WAL frame headers and shared-memory page indices — goes through the
offset-remap envelope, so the disk contents are ciphertext under the
same AEAD. This is strictly better than SQLCipher on the WAL side
(SQLCipher leaves 24-byte WAL frame headers in plaintext, exposing
page numbers and commit markers).

Net: more files exist on disk than under a hypothetical
`journal_mode=MEMORY` scheme (the WAL and SHM now live in OPFS), but
every byte is authenticated ciphertext, so the crash-safety tradeoff
favors this design.

### Key rotation (future work)

Changing the DB's encryption key requires re-encrypting every page
under the new key. Not yet implemented — current flows are wipe +
recreate. Tracked as a follow-up `rotateVfsKey(old, new)` worker
operation.

### Multi-tab concurrency (unchanged from vendor)

Same constraints as vendor SAHPool: single writer per origin. The
encryption layer does not introduce new concurrency concerns.

## Defense-in-depth summary

| Layer                                         | Status |
|-----------------------------------------------|--------|
| AEAD cipher (ChaCha20-Poly1305)               | ✓      |
| Random per-write nonce                        | ✓      |
| AAD binds dbPath + slotIndex                  | ✓      |
| Envelope versioning (VfsKeyHeader)            | ✓      |
| C# serialized-buffer zeroization              | ✓      |
| Worker plaintext-scratch zeroization          | ✓      |
| Worker key-registry wipe on close             | ✓      |
| journal_mode=WAL with encrypted WAL frames    | ✓      |
| Cross-library test vectors (BC ↔ awasm)       | ✓      |
| Rollback protection                           | ✗ (out of scope, needs external state) |
| Key rotation                                  | ✗ (future work)    |
| Same-origin script protection                 | ✗ (not possible at this layer) |

## Code references

- `SqliteWasmBlazor/TypeScript/worker/vfs-prf/sahpool-prf-vfs.ts` — forked SAHPool VFS with conditional ChaCha20-Poly1305.
- `SqliteWasmBlazor/TypeScript/worker/vfs-prf/aad.ts` — AAD byte-layout builder.
- `SqliteWasmBlazor/TypeScript/worker/vfs-prf/key-registry.ts` — per-path key lifecycle.
- `SqliteWasmBlazor/TypeScript/worker/sqlite-worker.ts` — `openDatabase` entry point, `unpackVfsKeyHeader`.
- `SqliteWasmBlazor/Services/VfsKeyHeader.cs` — C# envelope with `Clear()` zeroization.
- `SqliteWasmBlazor/Services/SqliteWasmWorkerBridge.cs` — `OpenDatabaseAsync(db, key, ct)`.
- `SqliteWasmBlazor/Ado/SqliteWasmConnection.cs` — `EncryptionKey` property.
- `SqliteWasmBlazor/Extensions/SqliteWasmDbContextOptionsExtensions.cs` — `UseSqliteWasm(cs, key)` helper.
- `BlazorPRF.Crypto/TypeScript/packages/crypto-core/src/chacha20Poly1305.ts` — AEAD wrapper over `@awasm/noble`.
