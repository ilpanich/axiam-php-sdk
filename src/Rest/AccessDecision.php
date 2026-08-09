<?php

declare(strict_types=1);

namespace Axiam\Sdk\Rest;

/**
 * The full outcome of an access check, including the CONTRACT.md §11 rule 9
 * `reason_code`.
 *
 * {@see AuthzRestClient::checkAccess()} and {@see AuthzRestClient::batchCheck()} return
 * bare `bool`s that predate this field and cannot carry it; use
 * {@see AuthzRestClient::checkAccessDecision()} /
 * {@see AuthzRestClient::batchCheckDecisions()} when the distinction matters.
 */
final class AccessDecision
{
    /**
     * @param bool $allowed Whether the checked action is permitted. **This property alone carries the outcome** — `$reasonCode` explains it and never contradicts it.
     * @param string|null $reason The server's human-readable explanation, when it sent one.
     * @param string|null $reasonCode {@see ReasonCode::ALLOWED}, {@see ReasonCode::NO_GRANT} or {@see ReasonCode::DENIED_BY_RULE}.
     *
     *   **The two refusals mean opposite things to the person on the other end.**
     *   `no_grant` says *ask an admin for access*; `denied_by_rule` says *an admin has
     *   already decided*. An application that cannot tell them apart sends users to raise
     *   tickets that will be refused — which is why the contract forbids collapsing them
     *   into a bare `false`.
     *
     *   `null` when the server omits the field, so a newer SDK against an older server
     *   degrades rather than failing. An unrecognised value is surfaced verbatim and never
     *   changes `$allowed` — which is why this is a `string` rather than an enum.
     */
    public function __construct(
        public readonly bool $allowed,
        public readonly ?string $reason,
        public readonly ?string $reasonCode,
    ) {
    }
}
