<?php
/**
 * Delta relay — opaque envelope buffer indexed by recipient pubkey.
 *
 * Endpoints:
 *   POST /api/delta
 *     body: {"recipientPublicKeys":["base64-Ed25519",...],"envelope":"base64"}
 *     stores one row per recipient. No auth (abuse protection only:
 *     body-size cap).
 *
 *   GET /api/delta?recipient=PK&since=CURSOR
 *     headers: X-Timestamp (unix seconds),
 *              X-Sig (base64 Ed25519 sig over "{timestamp}|{recipient}")
 *     returns: {"cursor":N,"envelopes":[{"cursor":N,"envelope":"base64"},...]}
 *     verifier key = `recipient` from query (stateless, +/-300s window).
 *
 * Storage: ./relay.db (SQLite). Single table:
 *   deltas(cursor INTEGER PK AUTOINCREMENT, recipient_pubkey TEXT,
 *          envelope BLOB, created_at INTEGER)
 *   index (recipient_pubkey, cursor).
 *
 * Server-side keys: zero. The relay never inspects payloads — every
 * confidentiality / integrity guarantee comes from the V2 envelope crypto.
 */
ini_set('html_errors', '0');

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Sig, X-Timestamp');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

const RECEIVE_WINDOW_SECONDS = 300;
const MAX_ENVELOPES_PER_FETCH = 100;

function jsonOut(int $status, array $body): void
{
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($body, JSON_UNESCAPED_SLASHES);
    exit;
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo !== null) {
        return $pdo;
    }
    $pdo = new PDO('sqlite:' . __DIR__ . '/relay.db');
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS deltas (
            cursor INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_pubkey TEXT NOT NULL,
            envelope BLOB NOT NULL,
            created_at INTEGER NOT NULL
        )'
    );
    $pdo->exec(
        'CREATE INDEX IF NOT EXISTS idx_recipient_cursor
         ON deltas(recipient_pubkey, cursor)'
    );
    return $pdo;
}

$path = trim($_GET['path'] ?? '', '/');
$method = $_SERVER['REQUEST_METHOD'];

if ($path !== 'delta') {
    jsonOut(404, ['error' => 'unknown route']);
}

if ($method === 'POST') {
    $raw = file_get_contents('php://input');
    $req = json_decode($raw, true);
    if (!is_array($req)
        || !is_array($req['recipientPublicKeys'] ?? null)
        || !is_string($req['envelope'] ?? null)) {
        jsonOut(400, ['error' => 'expected {recipientPublicKeys:[],envelope:base64}']);
    }
    $envelope = base64_decode($req['envelope'], true);
    if ($envelope === false) {
        jsonOut(400, ['error' => 'envelope is not valid base64']);
    }
    $recipients = $req['recipientPublicKeys'];
    if (count($recipients) === 0) {
        jsonOut(400, ['error' => 'recipientPublicKeys is empty']);
    }

    $now = time();
    $pdo = db();
    $stmt = $pdo->prepare(
        'INSERT INTO deltas (recipient_pubkey, envelope, created_at)
         VALUES (:pk, :env, :ts)'
    );
    $pdo->beginTransaction();
    try {
        foreach ($recipients as $pk) {
            if (!is_string($pk) || $pk === '') {
                throw new RuntimeException('recipient must be non-empty string');
            }
            $stmt->execute([
                ':pk' => $pk,
                ':env' => $envelope,
                ':ts' => $now,
            ]);
        }
        $pdo->commit();
    } catch (Throwable $e) {
        $pdo->rollBack();
        jsonOut(400, ['error' => $e->getMessage()]);
    }
    jsonOut(200, ['stored' => count($recipients)]);
}

if ($method === 'GET') {
    $recipient = $_GET['recipient'] ?? '';
    $since = (int)($_GET['since'] ?? 0);
    if ($recipient === '') {
        jsonOut(400, ['error' => 'recipient query param required']);
    }

    $ts = $_SERVER['HTTP_X_TIMESTAMP'] ?? '';
    $sigB64 = $_SERVER['HTTP_X_SIG'] ?? '';
    if ($ts === '' || $sigB64 === '') {
        jsonOut(401, ['error' => 'missing X-Timestamp or X-Sig']);
    }
    if (!ctype_digit((string)$ts)
        || abs(time() - (int)$ts) > RECEIVE_WINDOW_SECONDS) {
        jsonOut(401, ['error' => 'timestamp outside +/-' . RECEIVE_WINDOW_SECONDS . 's window']);
    }

    $sig = base64_decode($sigB64, true);
    $pubKey = base64_decode($recipient, true);
    if ($sig === false || $pubKey === false
        || strlen($sig) !== 64 || strlen($pubKey) !== 32) {
        jsonOut(401, ['error' => 'invalid signature or pubkey encoding']);
    }
    if (!sodium_crypto_sign_verify_detached($sig, "$ts|$recipient", $pubKey)) {
        jsonOut(401, ['error' => 'signature verification failed']);
    }

    $stmt = db()->prepare(
        'SELECT cursor, envelope FROM deltas
         WHERE recipient_pubkey = :pk AND cursor > :since
         ORDER BY cursor ASC LIMIT :lim'
    );
    $stmt->bindValue(':pk', $recipient, PDO::PARAM_STR);
    $stmt->bindValue(':since', $since, PDO::PARAM_INT);
    $stmt->bindValue(':lim', MAX_ENVELOPES_PER_FETCH, PDO::PARAM_INT);
    $stmt->execute();

    $envelopes = [];
    $maxCursor = $since;
    foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
        $cursor = (int)$row['cursor'];
        $envelopes[] = [
            'cursor' => $cursor,
            'envelope' => base64_encode($row['envelope']),
        ];
        if ($cursor > $maxCursor) {
            $maxCursor = $cursor;
        }
    }
    jsonOut(200, ['cursor' => $maxCursor, 'envelopes' => $envelopes]);
}

jsonOut(405, ['error' => 'method not allowed']);
