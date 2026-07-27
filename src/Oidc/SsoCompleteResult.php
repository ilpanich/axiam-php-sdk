<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * The result of `ssoComplete` (wire schema `SsoLoginSuccessResponse`, CONTRACT.md
 * §12.1). Carries **no token material** — the session arrives as `Set-Cookie`, so the §4
 * cookie jar (shared by every `AxiamClient` Guzzle transport) is what actually captures
 * it (§12.1 note 6).
 */
final class SsoCompleteResult
{
    /**
     * @param string $userId      The provisioned/linked user's UUID.
     * @param string $sessionId   The established session's UUID.
     * @param int    $expiresIn   Session/access-token lifetime in seconds.
     * @param string $redirectUri The post-login destination that was stored during `ssoStart`.
     */
    public function __construct(
        public readonly string $userId,
        public readonly string $sessionId,
        public readonly int $expiresIn,
        public readonly string $redirectUri,
    ) {
    }
}
