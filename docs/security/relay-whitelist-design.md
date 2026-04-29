# Delta Relay Whitelist — Design

_Drafted 2026-04-29. Ratified design, ready to implement. Closes the C-1 cluster from `docs/security/relay-audit.md` (POST unauthenticated, fan-out unbounded, no GC) and makes user revocation effective at the network layer._

---

## 1. Goals

- Make user revocation effective at the relay (not just at the crypto layer).
- Bound DoS to whitelisted-pubkey holders (raises the cost from "any network attacker" to "any device that ever held a valid CryptoSync identity").
- Eliminate per-recipient metadata in `relay.db`.
- Keep the relay stateless except for the whitelist + delta queue. **No user accounts, no group state, no key derivation server-side.**
- Preserve the friendly-handoff property: a revoked user's other devices can still pull (briefly) so they learn they've been revoked.

## 2. Non-goals

- **Group membership at the relay.** Groups are crypto-only — key rotation handles group revocation, the relay never sees group structure. Whitelist tracks **users**, not group members.
- **Multi-admin per deployment.** One system admin, one identity, hardwired at the deployment level. Admin device loss = operator-level recovery (edit PHP config), not protocol-level recovery. (Future enhancement: signed key bundle in the PRF/WebAuthn flow — captured in §10.)
- **Multi-device whitelist entries.** Exportable passkeys (iCloud Keychain / Google Password Manager / FIDO2 device transfer) put the same Ed25519 identity on every device a user owns. One whitelist entry per user, regardless of device count.
- **Sender→recipient access control.** The whitelist is binary (member of deployment or not). Per-pair routing is a separable feature; not in this design.

## 3. Threat model delta

| | Current relay | This design |
|---|---|---|
| Relay state | Zero keys, no users | One pubkey-hash list + version counter |
| Auth on POST | None | Sender Ed25519 sig, sender hash on whitelist as `active` |
| Auth on GET | Recipient pubkey sig (today) | Same + pubkey hash on whitelist as `active` or non-expired `revoked` |
| Effect of crypto-layer revocation at the network | None — revoked user can still flood relay | After whitelist push: revoked user can pull for `READ_GRACE_SECONDS` then loses all access |
| Metadata stored in `relay.db` | Recipient pubkey per delta + deltas | Hashed pubkeys in whitelist, **no recipient pubkey on deltas** (broadcast model, see §5) |
| Stays honest-but-curious? | Yes | Yes — relay must additionally not lie about whitelist contents, but lying only achieves what an unauthenticated relay achieves today (no new attack power) |

Net result: strictly more secure than today against availability attacks, strictly less metadata leakage on disk, no change to confidentiality/integrity guarantees.

## 4. Static deployment config

PHP file, mode `0600`, owned by the PHP user, outside the web root. Loaded once per request via `require_once`.

```php
// relay-config.php  (NOT in web root)
return [
    'deployment_salt'    => '<base64 of 32 random bytes>',
    'admin_pubkey_hash'  => '<sha256(deployment_salt || systemAdmin.Ed25519PubKey), hex>',
    'read_grace_seconds' => 604800,                    // 7 days
    'max_body_bytes'     => 1048576,                   // 1 MB POST cap
    'rate_limit_window'  => 60,                        // seconds
    'rate_limit_count'   => 60,                        // per source IP
];
```

**Bootstrap procedure:** operator runs `cryptosync-relay-init <admin-pubkey-base64>` (a small CLI, separate from the relay itself) which generates a fresh `deployment_salt`, computes `admin_pubkey_hash`, and writes `relay-config.php`. Operator-protected from there on.

**Admin recovery:** if the admin device is lost, operator runs `cryptosync-relay-init` again with a new admin pubkey. This is destructive to the deployment's continuity (clients re-pair from scratch) but it's an explicit domain decision, not a protocol failure.

## 5. Schema

```sql
-- The whitelist. Pinned admin can update; clients are checked against it.
CREATE TABLE whitelist (
    pubkey_hash       TEXT PRIMARY KEY,            -- sha256(salt || pubkey), hex
    status            TEXT NOT NULL,               -- 'active' | 'revoked'
    revoked_at        INTEGER,                     -- NULL when active; unix seconds when revoked
    added_at          INTEGER NOT NULL
);

-- Single meta row tracks the version (replay defense for whitelist updates).
CREATE TABLE whitelist_meta (
    id                INTEGER PRIMARY KEY,         -- always 1
    current_version   INTEGER NOT NULL             -- monotonic; rejects stale updates
);
INSERT INTO whitelist_meta (id, current_version) VALUES (1, 0);

-- Broadcast delta queue. ONE row per envelope, no per-recipient rows.
CREATE TABLE deltas (
    cursor            INTEGER PRIMARY KEY AUTOINCREMENT,
    envelope          BLOB NOT NULL,
    created_at        INTEGER NOT NULL
);
CREATE INDEX idx_deltas_cursor ON deltas (cursor);
```

The change from today: `deltas.recipient_pubkey` is gone. Every whitelisted client polls a single global stream; their crypto layer (per-row AEAD + batch Ed25519 + permission resolver) drops envelopes addressed to keys they don't hold.

## 6. Endpoints

### 6.1 `POST /api/whitelist` — admin-only, signed by hardwired admin pubkey

**Request:**

```json
{
  "version":             42,                          // monotonic, must be > current_version
  "members": [
    { "pubkey_hash": "<hex>", "status": "active" },
    { "pubkey_hash": "<hex>", "status": "revoked", "revoked_at": 1714329600 }
  ],
  "admin_pubkey":        "<base64 Ed25519 pub>",      // verified against ADMIN_PUBKEY_HASH
  "admin_signature":     "<base64 Ed25519 sig over canonical>"
}
```

**Canonical signing input:**

```
"whitelist-v1|" + version + "|" +
join("|", sort([m.pubkey_hash + ":" + m.status + ":" + (m.revoked_at ?? "0") for m in members]))
```

Sort lex-ascending by `pubkey_hash` so the canonical is order-independent.

**Verification at relay:**

1. `sha256(deployment_salt || base64decode(admin_pubkey)) == ADMIN_PUBKEY_HASH` (else 401)
2. `version > whitelist_meta.current_version` (else 409)
3. `sodium_crypto_sign_verify_detached(admin_signature, canonical, admin_pubkey)` (else 401)
4. Atomically: `BEGIN; DELETE FROM whitelist; INSERT each member; UPDATE whitelist_meta.current_version; COMMIT.`

**Response:**

```json
{ "version": 42, "member_count": 17 }
```

### 6.2 `POST /api/delta` — sender-authenticated, must be whitelisted as `active`

**Request:**

```
Headers:  X-Timestamp: <unix seconds>
          X-Sender-PubKey: <base64 Ed25519>
          X-Sender-Sig: <base64 Ed25519 sig over "deltapost-v1|" + ts + "|" + sha256(envelope)>
Body:     { "envelope": "<base64>" }
```

**Verification:**

1. `|now - X-Timestamp| < 300` (else 401)
2. `body length < max_body_bytes` (else 413)
3. `sha256(salt || decode(X-Sender-PubKey))` looked up in `whitelist`; status must be `'active'` (else 403)
4. Signature verifies (else 401)
5. Insert one row into `deltas`. Single transaction. Returns `{ "cursor": <new cursor> }`.

### 6.3 `GET /api/delta?since=N` — pubkey-authenticated, whitelisted with read access

**Request:** unchanged from today's `?recipient=PK&since=N` plus `X-Timestamp` / `X-Sig`, **except `recipient` is renamed `pubkey`** for clarity (it's no longer a recipient routing key — it's the puller identifying themselves).

**Verification:**

1. `|now - X-Timestamp| < 300` (else 401)
2. Sig verifies over `"deltaget-v1|" + ts + "|" + pubkey` (else 401)
3. Hash lookup: `pubkey_hash = sha256(salt || decode(pubkey))`. Allowed if:
   - `status = 'active'`, OR
   - `status = 'revoked'` AND `now - revoked_at < READ_GRACE_SECONDS`
   (else 403)
4. `SELECT cursor, envelope FROM deltas WHERE cursor > :since ORDER BY cursor ASC LIMIT 100`

**Response:** unchanged — `{ cursor, envelopes: [...] }`.

## 7. Revocation lifecycle

System admin's revocation flow is two atomic operations on the admin device:

```
1. Local: crypto-layer rotation (key rotation if member of any group;
                                 mark TrustedContact as deleted).
2. Remote: POST /api/whitelist with the revoked user's hash flipped to
           status='revoked', revoked_at=now, version=current+1.
```

Time after step 2:

| Phase | Duration | POST | GET |
|---|---|---|---|
| Active | up to step 2 | OK | OK |
| Grace (revoked-but-readable) | `READ_GRACE_SECONDS` (7 days) | denied | OK |
| Expired | after grace | denied | denied |

The grace window is what lets the revoked user's other devices pull system-table updates that say "you've been revoked," surface a UI message, allow data export, and wipe the local DB cleanly. Domain-friendly handoff, not a security weakness — the revoked user's local data was already plaintext to them.

A whitelist entry never disappears (we don't `DELETE`); it just transitions `active → revoked → (still revoked, now expired)`. This keeps `current_version` monotonic across re-additions if the same user is re-invited (bumps to a new fresh entry).

## 8. Bootstrap flows

### 8.1 First admin push (deployment day-0)

After operator runs `cryptosync-relay-init`, the admin device's first sync action is:

```
1. CryptoSyncBootstrap.InitializeAdminAsync runs locally.
   Derives Ed25519 keypair from PRF.
2. POST /api/whitelist with version=1, members=[{admin_hash, active}].
   Signed by admin's Ed25519 priv.
3. Relay verifies admin_pubkey_hash matches the hardwired one,
   accepts the push.
```

From this point the admin can POST/GET deltas like any other client.

### 8.2 New user invitation (per `project_invitation_flow.md`)

The Stage 4 invitation flow uses an ephemeral X25519 transport keypair derived from the OOB shared secret. That transport keypair needs whitelist access for the bootstrap window.

```
Admin: CreateInvitationAsync       → push whitelist update with
                                     {transport_pubkey_hash, active}
Invitee: RespondToInvitationAsync  → signs response using transport keypair,
                                     POST /api/delta succeeds because
                                     transport pubkey is whitelisted
Admin: PromoteInvitationAsync      → push whitelist update with
                                     {transport_hash → revoked, real_hash → active}
```

Transport-keypair lifetime at the relay = invitation expiry window (typically minutes). Implementation note: admin's local revocation of the transport keypair on promotion must trigger the second whitelist push, same way regular revocation does.

## 9. Operational hardening (server-side, independent of protocol)

These are deployment-time concerns the relay operator must handle. Not part of the protocol but listed here so the design is complete in context.

- `relay.db` and `relay-config.php` mode `0600`, owned by PHP user.
- nginx/Apache config: `client_max_body_size 1m`, per-IP rate-limit (`limit_req_zone`), `Server:` header stripped, no `server_tokens`.
- `php.ini`: `expose_php=Off`, `display_errors=Off`, `log_errors=On` to a file outside web root.
- TLS 1.3 only, HSTS, no HTTP fallback.
- Structured logging: `(timestamp, source_ip_truncated, route, status, pubkey_hash_short, body_bytes)`. Rotate logs, short retention (e.g. 30 days), encrypted off-host backup if compliance needs it.
- Monitor: alert when disk > 70%, when whitelist-push 401s spike (signal: stolen admin pubkey forgery attempt), when POST 403s spike (signal: revoked-user retry storm).
- Daily `relay.db` dump to encrypted off-host storage. Restoration is fine because clients are idempotent (cursor monotonicity protects against lost-and-restored deltas; receivers absorb duplicates via shadow-row UPSERT).

These items also close findings W-1 (`__DIR__` leak in `index.php` — just remove that file), W-2 (open CORS — accepted policy now that auth gates POST), and I-1 (`X-Powered-By` — `expose_php=Off`).

## 10. Future enhancements

Captured here so the design's load-bearing assumptions are visible:

- **Signed admin key bundle.** Today, losing the admin device means operator-level recovery (re-init the relay). A future enhancement to the PRF/WebAuthn flow could let the admin pre-generate a recovery key bundle (signed by the current admin pubkey, stored offline by the user — paper backup, hardware token). Recovery would be: operator updates `ADMIN_PUBKEY_HASH` in `relay-config.php` to the bundle's pubkey, deployment continues without re-pairing all clients. **Domain concern, not protocol concern** — the bundle's signature semantics matter to clients only insofar as the new admin can sign whitelist updates, which is purely a hardwired-config question. Not blocking this design.

- **Dual-DB and private contacts.** When `twin-streams-flowing-codd.md` lands, private-DB contacts shouldn't appear in the public deployment's whitelist. Three options to evaluate at that time:
  1. Per-DB whitelist scope (one whitelist per DB, two columns or two `relay.db` files).
  2. Private-DB uses peer-to-peer transport instead of the relay.
  3. Public-DB whitelist also covers private-DB members (simplest, but exposes private-contact existence to the public-DB admin).

  Decision deferred until the dual-DB design lands.

- **Per-pair routing (sender→recipient ACL).** Today the whitelist is binary (member or not). A future enhancement could let the admin push `(sender_hash, recipient_hash, allowed)` triples. Not needed for current threat model — receivers' AEAD already drops unauthorized envelopes — but would tighten metadata leak (relay would learn fewer relationship facts).

- **Sender-rate-limiting on whitelist entries.** Today rate-limiting is operator-side (per IP). A future enhancement could add per-pubkey-hash rate-limit at the relay layer, since the whitelist now provides stable identifiers. Useful if a single whitelisted device is compromised and abused.

## 11. Migration from current relay

This is a breaking protocol change. Migration plan:

1. **Ship the new schema + endpoints alongside the old.** Same `relay.db`, new tables, new routes (`/api/whitelist`, modified POST/GET).
2. **Roll out client support.** New `HttpSyncTransport` reads `relay-config.php`-published config (or app-side equivalent), signs POST, validates GET response shape unchanged.
3. **Operator runs `cryptosync-relay-init` and the admin device pushes the initial whitelist.** Until this happens the relay refuses all requests (except the whitelist push from the hardwired admin).
4. **Drop the old POST/GET routes.** No backward compatibility window — this is a security upgrade, not a feature evolution.

Estimated effort: PHP relay rewrite (small file, ≤300 lines), C# client changes (`HttpSyncTransport` + a new `WhitelistPushService`), wiring `WhitelistPushService` into `LeaveService.LeaveGroupAsync`, `GroupService.RemoveMemberAsync`, `ContactInvitationService.PromoteInvitationAsync`, and a live-relay integration test. Roughly the same surface as Phase 2 + Phase 1 combined.

---

## Implementation order (recommendation)

1. **PHP first.** Rewrite `delta-relay.php` against the new schema; ship `cryptosync-relay-init` CLI. Test via curl + `sodium_*` with synthetic keys before any C# change.
2. **C# `WhitelistPushService`.** New service with `PushAsync(IReadOnlyList<WhitelistMember>)`, signs via `DeclarationSigner` with the admin's Ed25519 priv, posts to `/api/whitelist`. Unit tests against a stub HTTP handler (mirror `HttpSyncTransportTests` shape).
3. **`HttpSyncTransport` upgrade.** Replace recipient-list POST with single-envelope POST + sender sig header. Existing receive cursor is unchanged (just reads from a single broadcast stream now).
4. **Hooks.** Wire `WhitelistPushService` into `LeaveService.LeaveGroupAsync`, `GroupService.RemoveMemberAsync`, `ContactInvitationService.{CreateInvitation, PromoteInvitation}Async`. Each becomes "do the local thing, then push the updated whitelist."
5. **Integration test.** Live PHP relay reachable at `http://delta-relay.test/api/delta`; full end-to-end with two actors, one revocation, grace-window expiry.

Each step is independently shippable and reviewable.
