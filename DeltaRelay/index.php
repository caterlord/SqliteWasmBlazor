<?php
/**
 * Public landing for the delta relay deployment.
 *
 * Intentionally minimal — no environment introspection, no version
 * disclosure. The API lives at /api/delta and /api/whitelist; see
 * docs/security/relay-whitelist-design.md for the wire contract.
 */
header('Content-Type: text/plain; charset=utf-8');
echo "Delta Relay\n";
