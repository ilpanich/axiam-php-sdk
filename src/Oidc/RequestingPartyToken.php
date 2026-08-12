<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\Sensitive;

/**
 * The result of the UMA ticket grant (CONTRACT.md §20.1).
 *
 * **There is no `$refreshToken` property, and that is deliberate** (§20.2 rule 5).
 * The grant issues none, so an RPT cannot outlive the ticket that authorised it; an
 * application that wants a fresh one re-runs the grant. This result never enters the
 * §9 single-flight refresh guard — there is nothing to refresh.
 */
final class RequestingPartyToken
{
    /**
     * @param Sensitive $accessToken The RPT itself (§20.6 secret).
     * @param string $tokenType Always `Bearer`.
     * @param int $expiresIn `min(claimToken remaining, server ceiling, 300 s)`.
     */
    public function __construct(
        public readonly Sensitive $accessToken,
        public readonly string $tokenType,
        public readonly int $expiresIn,
    ) {
    }
}
