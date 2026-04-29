<?php
/**
 * Delta relay deployment configuration.
 *
 * Copy this file to relay-config.php and lock it down:
 *
 *   cp relay-config.example.php relay-config.php
 *   php cryptosync-relay-init.php <admin-pubkey-base64>
 *   chmod 0600 relay-config.php
 *
 * relay-config.php must NEVER be web-accessible. The Valet driver and
 * .htaccess in this directory deny direct HTTP access; verify after deploy
 * with: curl -I https://your-host/relay-config.php  (expect 403/404).
 *
 * Fields are documented inline below. The cryptosync-relay-init.php CLI
 * generates `deployment_salt` and `admin_pubkey_hash` for you; the rest are
 * operator-tunable.
 */
return [
    // Base64-encoded 32 random bytes. Used to hash pubkeys before storing
    // them in the whitelist. Generated once by cryptosync-relay-init.php.
    'deployment_salt'    => '<base64 of 32 random bytes — set by cryptosync-relay-init>',

    // Hex sha256(deployment_salt || systemAdmin.Ed25519PubKey). The relay
    // accepts whitelist pushes only from this admin identity. Set by
    // cryptosync-relay-init.php from the admin pubkey passed on its CLI.
    'admin_pubkey_hash'  => '<hex sha256 — set by cryptosync-relay-init>',

    // How long a revoked-but-still-whitelisted device may keep reading
    // (GET /api/delta) so it can pick up its own revocation notice. POSTs
    // are denied immediately when status flips to 'revoked'.
    //
    // 604800 = 7 days. Lower it (e.g. 2) for time-window integration tests.
    'read_grace_seconds' => 604800,

    // Maximum POST body size in bytes. Bounded delta envelopes — the V2
    // crypto envelope plus base64 overhead fits comfortably under 1 MB even
    // for large groups. Larger inputs are rejected with 413 before any DB
    // touch.
    'max_body_bytes'     => 1048576,

    // Per-source-IP rate limit. Operator-side defense; whitelist-aware
    // limiting per pubkey-hash is a future enhancement (see roadmap).
    'rate_limit_window'  => 60,    // seconds
    'rate_limit_count'   => 60,    // requests per window per source IP

    // Soft fragmentation threshold: when the count of unpinned rows in
    // `deltas` exceeds this, GET /api/delta responses include
    // "gc_requested": true. The flag is purely informational — only the
    // deployment admin can act on it (via a fresh pin POST that purges
    // priors and stores a new compacted seed). Non-admin clients ignore
    // the hint. The relay never autonomously deletes rows.
    //
    // Tune by storage budget vs. admin attention cadence: lower = admin
    // is nudged sooner, higher = admin is left alone longer. 1000 rows is
    // a reasonable default for V2 envelopes (~8-128 KB each).
    'gc_threshold_rows'  => 1000,
];
