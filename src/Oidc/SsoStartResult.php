<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * The result of `ssoStart` (wire schema `OidcStartResponse`, CONTRACT.md §12.1).
 *
 * There is deliberately **no nonce**: on the federation path the nonce never leaves the
 * server (§12.1 note 7). Round-trip {@see self::$state} into `ssoComplete` unmodified —
 * the server stores it single-use with a 10-minute TTL and recovers the whole login
 * context from it.
 */
final class SsoStartResult
{
    /**
     * @param string $authorizeUrl  The upstream IdP authorization URL to redirect the browser to.
     * @param string $state         Single-use CSRF state to round-trip back into `ssoComplete` unmodified.
     * @param int    $expiresInSecs Remaining TTL of the server-side state row, in seconds (600 = 10 min).
     */
    public function __construct(
        public readonly string $authorizeUrl,
        public readonly string $state,
        public readonly int $expiresInSecs,
    ) {
    }
}
