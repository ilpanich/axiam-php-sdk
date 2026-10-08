<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\Sensitive;

/**
 * `CibaInitiateResponse` (CONTRACT.md §33.2) — what {@see OidcClient::cibaInitiate()} returns.
 *
 * **It proves nothing about the user** (§33.3 rule 4): AXIAM answers a hint that names nobody,
 * a locked user and a real one identically, and the only signal that a user did not answer is
 * `expired_token`.
 */
final class CibaInitiateResponse
{
    /**
     * @param Sensitive $authReqId  The request's id at the token endpoint — a bearer credential
     *                              for the grant (§33.5). Never parse or length-check it.
     * @param int       $expiresIn  The request's lifetime in seconds — authoritative (§33.7 rule 4).
     * @param int       $interval   The minimum seconds between token requests: the response's
     *                              value, or 5 when it was absent or zero (§33.7 rule 2).
     * @param float     $receivedAt When the response was received (seconds, on the clock passed
     *                              to `cibaInitiate`); `cibaAwait`'s deadline is this plus `expiresIn`.
     */
    public function __construct(
        public readonly Sensitive $authReqId,
        public readonly int $expiresIn,
        public readonly int $interval,
        public readonly float $receivedAt,
    ) {
    }
}
