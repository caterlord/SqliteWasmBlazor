<?php
/**
 * cryptosync-relay-init — one-time deployment bootstrap.
 *
 * Generates a fresh deployment_salt, computes admin_pubkey_hash from the
 * supplied admin Ed25519 pubkey, and writes relay-config.php from the
 * relay-config.example.php template.
 *
 * Usage:
 *   php cryptosync-relay-init.php <admin-pubkey-base64> [--force]
 *
 * <admin-pubkey-base64> must decode to exactly 32 bytes (Ed25519 public key).
 *
 * --force overwrites an existing relay-config.php (admin device replacement
 * or deployment reset). This is destructive: clients re-pair from scratch.
 *
 * After running, lock the file down:
 *   chmod 0600 relay-config.php
 *
 * This script is NOT web-accessible — both the Valet driver and .htaccess
 * deny direct HTTP access. Confirm after deploy with:
 *   curl -I https://your-host/cryptosync-relay-init.php  # expect 403/404
 */

if (php_sapi_name() !== 'cli') {
    http_response_code(404);
    exit;
}

function fail(string $message, int $code = 1): never
{
    fwrite(STDERR, $message . PHP_EOL);
    exit($code);
}

$args = array_slice($argv, 1);
$force = false;
$adminPubB64 = null;

foreach ($args as $a) {
    if ($a === '--force') {
        $force = true;
        continue;
    }
    if ($a === '--help' || $a === '-h') {
        echo "Usage: php cryptosync-relay-init.php <admin-pubkey-base64> [--force]\n";
        exit(0);
    }
    if ($adminPubB64 !== null) {
        fail("Unexpected extra argument: '$a'. Use --help for usage.");
    }
    $adminPubB64 = $a;
}

if ($adminPubB64 === null) {
    fail('Missing admin pubkey. Usage: php cryptosync-relay-init.php <admin-pubkey-base64> [--force]');
}

$adminPubBytes = base64_decode($adminPubB64, true);
if ($adminPubBytes === false || strlen($adminPubBytes) !== 32) {
    fail('Admin pubkey must be base64 encoding of exactly 32 bytes (Ed25519).');
}

$configPath = __DIR__ . '/relay-config.php';
$templatePath = __DIR__ . '/relay-config.example.php';

if (!is_file($templatePath)) {
    fail("Template missing: $templatePath");
}
if (is_file($configPath) && !$force) {
    fail("relay-config.php already exists. Re-run with --force to overwrite (destructive — clients re-pair from scratch).");
}

$saltBytes = random_bytes(32);
$saltB64 = base64_encode($saltBytes);
$adminHashHex = hash('sha256', $saltBytes . $adminPubBytes);

$template = file_get_contents($templatePath);
if ($template === false) {
    fail("Failed to read template: $templatePath");
}

$rendered = str_replace(
    [
        "'<base64 of 32 random bytes — set by cryptosync-relay-init>'",
        "'<hex sha256 — set by cryptosync-relay-init>'",
    ],
    [
        var_export($saltB64, true),
        var_export($adminHashHex, true),
    ],
    $template
);

if ($rendered === $template) {
    fail('Template substitution did not match expected placeholders. Has relay-config.example.php been edited?');
}

$tmpPath = $configPath . '.tmp.' . getmypid();
if (file_put_contents($tmpPath, $rendered, LOCK_EX) === false) {
    fail("Failed to write temporary config: $tmpPath");
}
if (!chmod($tmpPath, 0600)) {
    @unlink($tmpPath);
    fail("Failed to chmod 0600 on $tmpPath");
}
if (!rename($tmpPath, $configPath)) {
    @unlink($tmpPath);
    fail("Failed to move temporary config into place: $configPath");
}

echo "Wrote $configPath (mode 0600).\n";
echo "  deployment_salt   = $saltB64\n";
echo "  admin_pubkey_hash = $adminHashHex\n";
echo "\n";
echo "Next:\n";
echo "  - Verify the admin pubkey matches the device that will push the first whitelist.\n";
echo "  - Confirm relay-config.php is not web-accessible:\n";
echo "      curl -I https://your-host/relay-config.php  # expect 403 or 404\n";
