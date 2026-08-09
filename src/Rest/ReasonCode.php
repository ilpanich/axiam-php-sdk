<?php

declare(strict_types=1);

namespace Axiam\Sdk\Rest;

/**
 * The three `reason_code` values CONTRACT.md §11 rule 9 defines.
 *
 * Class constants rather than a backed `enum`, so an unrecognised server value is still a
 * valid {@see AccessDecision::$reasonCode} and reaches the caller — an enum's
 * `from()`/`tryFrom()` would force the SDK to throw on, or drop, what it cannot name.
 */
final class ReasonCode
{
    /** An allow grant matched and no deny did. */
    public const ALLOWED = 'allowed';

    /** Nothing matched — default deny. *Ask an admin for access.* */
    public const NO_GRANT = 'no_grant';

    /** An explicit deny rule matched and overrode any allow. *An admin has already decided.* */
    public const DENIED_BY_RULE = 'denied_by_rule';

    private function __construct()
    {
    }
}
