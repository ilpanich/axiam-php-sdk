<?php

declare(strict_types=1);

namespace Axiam\Sdk\Webauthn;

use Axiam\Sdk\Core\Sensitive;

/**
 * A completed authentication ceremony (CONTRACT.md §24.3).
 *
 * The tokens are also adopted by the client that produced this value — the server sets the
 * `axiam_access` / `axiam_refresh` / `axiam_csrf` cookie triple alongside them — so a caller
 * who only wants to be signed in can ignore every property here.
 */
final readonly class WebauthnLoginResult
{
    /**
     * @param Sensitive $accessToken  The new access token (§24.5).
     * @param Sensitive $refreshToken The new refresh token (§24.5).
     * @param string    $sessionId    The session this ceremony established.
     * @param int       $expiresIn    The access token's lifetime in seconds.
     */
    public function __construct(
        public Sensitive $accessToken,
        public Sensitive $refreshToken,
        public string $sessionId,
        public int $expiresIn,
    ) {
    }
}
