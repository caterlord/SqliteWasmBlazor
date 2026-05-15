<?php

use Valet\Drivers\BasicValetDriver;

class LocalValetDriver extends BasicValetDriver
{
    /**
     * Filenames that must never be served over HTTP — config / CLI scripts /
     * raw DB. Stored as a leading-slash form to match URI prefix tests.
     */
    private const DENY_PREFIXES = [
        '/relay.db',
        '/relay-config.php',
        '/relay-config.example.php',
        '/cryptosync-relay-init.php',
    ];

    public function serves(string $sitePath, string $siteName, string $uri): bool
    {
        return true;
    }

    public function isStaticFile(string $sitePath, string $siteName, string $uri)
    {
        if (self::isDenied($uri)) {
            return false;
        }

        if (file_exists($sitePath . $uri) && is_file($sitePath . $uri)) {
            return $sitePath . $uri;
        }

        return false;
    }

    public function frontControllerPath(string $sitePath, string $siteName, string $uri): ?string
    {
        if (self::isDenied($uri)) {
            http_response_code(403);
            header('Content-Type: application/json');
            echo json_encode(['error' => 'Forbidden']);
            exit;
        }

        // Route /api/* to delta-relay.php
        if (preg_match('#^/api/(.*)$#', $uri, $matches)) {
            $_GET['path'] = $matches[1];
            return $sitePath . '/delta-relay.php';
        }

        if (file_exists($sitePath . '/index.php')) {
            return $sitePath . '/index.php';
        }

        return null;
    }

    private static function isDenied(string $uri): bool
    {
        foreach (self::DENY_PREFIXES as $prefix) {
            if (str_starts_with($uri, $prefix)) {
                return true;
            }
        }
        return false;
    }
}
