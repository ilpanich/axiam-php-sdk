<?php

declare(strict_types=1);

namespace Axiam\Sdk\Ssf;

/**
 * The six event types AXIAM transmits and the two SSF stream events (CONTRACT.md §32.6), as
 * named constants. Event types are open: a SET of another type still verifies, and
 * {@see SecurityEvent::$eventType} carries it verbatim.
 */
final class SsfEventTypes
{
    /** CAEP session revoked. */
    public const SESSION_REVOKED = 'https://schemas.openid.net/secevent/caep/event-type/session-revoked';

    /** CAEP credential change. */
    public const CREDENTIAL_CHANGE = 'https://schemas.openid.net/secevent/caep/event-type/credential-change';

    /** CAEP assurance level change. */
    public const ASSURANCE_LEVEL_CHANGE = 'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change';

    /** RISC account disabled. */
    public const ACCOUNT_DISABLED = 'https://schemas.openid.net/secevent/risc/event-type/account-disabled';

    /** RISC account enabled. */
    public const ACCOUNT_ENABLED = 'https://schemas.openid.net/secevent/risc/event-type/account-enabled';

    /** RISC account purged. */
    public const ACCOUNT_PURGED = 'https://schemas.openid.net/secevent/risc/event-type/account-purged';

    /** SSF verification. */
    public const VERIFICATION = 'https://schemas.openid.net/secevent/ssf/event-type/verification';

    /** SSF stream updated. */
    public const STREAM_UPDATED = 'https://schemas.openid.net/secevent/ssf/event-type/stream-updated';

    private function __construct()
    {
    }
}
