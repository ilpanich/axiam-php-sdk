<?php

declare(strict_types=1);

namespace Axiam\Sdk\Amqp;

/**
 * A VERIFIED answer to one {@see AuthzRequester::check()} (CONTRACT.md §8).
 *
 * `$allowed` is `true` only for a response that verified under the tenant subkey and was bound
 * to this requester's tenant and to the request it sent — or, with
 * `allowUnsignedResponses: true`, for a response that carried no signature at all (see
 * `$unsigned`). Never an allow for anything else: a response that fails verification is
 * discarded, it does not complete the request.
 */
final class AuthzDecision
{
    /**
     * @param bool        $allowed    The decision.
     * @param string|null $reason     The server's human-readable reason, `null` when absent.
     * @param string|null $reasonCode The machine-readable code (`allowed`, `no_grant`,
     *        `denied_by_rule`, `tenant_suspended`, …), `null` when absent. A code this SDK does
     *        not know is surfaced verbatim (§11.2 rule 9).
     * @param bool        $unsigned   `true` when the response carried no `hmac_signature` and
     *        was admitted only because `allowUnsignedResponses` is set.
     */
    public function __construct(
        public readonly bool $allowed,
        public readonly ?string $reason = null,
        public readonly ?string $reasonCode = null,
        public readonly bool $unsigned = false,
    ) {
    }
}
