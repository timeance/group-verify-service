<?php
declare(strict_types=1);

namespace app\support;

/**
 * Validates the server-side Geetest API endpoint.
 *
 * The public API is intentionally small so installation and administration
 * code can share the same SSRF boundary without duplicating URL parsing.
 */
final class GeetestEndpoint
{
    private const DEFAULT_ENDPOINT = 'https://gcaptcha4.geetest.com';

    /**
     * Return true only for HTTPS origins that are in the fixed official list
     * or in the server-local GEETEST_ALLOWED_ORIGINS/config allowlist.
     */
    public static function isAllowed(string $endpoint): bool
    {
        $origin = self::normalizeOrigin($endpoint);
        if ($origin === null) {
            return false;
        }

        foreach (self::configuredOrigins() as $configured) {
            if (self::normalizeOrigin($configured) === $origin) {
                return true;
            }
        }

        return false;
    }

    public static function defaultEndpoint(): string
    {
        return self::DEFAULT_ENDPOINT;
    }

    private static function configuredOrigins(): array
    {
        $origins = [self::DEFAULT_ENDPOINT];

        if (function_exists('config')) {
            try {
                $configured = config('geetest.allowed_origins', []);
                if (is_array($configured)) {
                    $origins = array_merge($origins, $configured);
                }
            } catch (\Throwable $e) {
                // Static checks and early bootstrap may not have ThinkPHP config.
            }
        }

        $raw = function_exists('env')
            ? env('GEETEST_ALLOWED_ORIGINS', '')
            : getenv('GEETEST_ALLOWED_ORIGINS');
        foreach (preg_split('/[\\s,]+/', trim((string)($raw ?: ''))) ?: [] as $origin) {
            if (trim((string)$origin) !== '') {
                $origins[] = trim((string)$origin);
            }
        }

        return array_values(array_unique(array_map('strval', $origins)));
    }

    private static function normalizeOrigin(string $endpoint): ?string
    {
        $parts = parse_url(trim($endpoint));
        if (!is_array($parts)) {
            return null;
        }

        if (strtolower((string)($parts['scheme'] ?? '')) !== 'https') {
            return null;
        }

        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            return null;
        }

        $host = strtolower(rtrim((string)($parts['host'] ?? ''), '.'));
        if ($host === '' || filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) === false) {
            return null;
        }

        $port = $parts['port'] ?? null;
        if ($port !== null && (!is_int($port) || $port < 1 || $port > 65535)) {
            return null;
        }

        $path = (string)($parts['path'] ?? '');
        if ($path !== '' && $path !== '/') {
            return null;
        }

        return 'https://' . $host . ($port !== null ? ':' . $port : '');
    }
}
