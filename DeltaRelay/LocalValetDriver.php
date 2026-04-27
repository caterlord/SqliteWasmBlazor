<?php

use Valet\Drivers\BasicValetDriver;

class LocalValetDriver extends BasicValetDriver
{
    public function serves(string $sitePath, string $siteName, string $uri): bool
    {
        return true;
    }

    public function isStaticFile(string $sitePath, string $siteName, string $uri)
    {
        // Deny direct access to the SQLite envelope store
        if (str_starts_with($uri, '/relay.db')) {
            return false;
        }

        if (file_exists($sitePath . $uri) && is_file($sitePath . $uri)) {
            return $sitePath . $uri;
        }

        return false;
    }

    public function frontControllerPath(string $sitePath, string $siteName, string $uri): ?string
    {
        // Deny direct access to the SQLite envelope store
        if (str_starts_with($uri, '/relay.db')) {
            http_response_code(403);
            die(json_encode(['error' => 'Forbidden']));
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
}
