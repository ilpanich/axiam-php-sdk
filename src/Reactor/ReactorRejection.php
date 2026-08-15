<?php

declare(strict_types=1);

namespace Axiam\Sdk\Reactor;

use Axiam\Sdk\Core\AxiamException;

/**
 * A reactor delivery or handler answer this SDK refuses (CONTRACT.md §22.3,
 * §22.4).
 *
 * Every instance results in **no reply being published**, which hands the outcome
 * to the registration's `failure_policy` (§22.8) — never to a synthesized
 * `allow`. An SDK that answered `allow` on behalf of a handler that crashed would
 * have overridden the operator's `fail_closed` setting from inside the library.
 *
 * {@see self::reason()} is drawn from a fixed vocabulary that mirrors §22.4's
 * rejection table, so a reactor's own metrics line up with the server's audit
 * records. The message never carries the received or expected MAC, the signing
 * key, or the event payload.
 */
final class ReactorRejection extends AxiamException
{
    /** `key_version` is below the replay-protected floor of 2 (§22.4 row 4). */
    public const KEY_VERSION_TOO_OLD = 'key_version_too_old';

    /** The MAC is missing or wrong (§22.4 row 6). */
    public const BAD_SIGNATURE = 'bad_signature';

    /** `issued_at` is outside ±300 s, in either direction (§22.4 row 5). */
    public const STALE = 'stale';

    /** The nonce has already been seen inside the freshness window (§8 v2). */
    public const REPLAY = 'replay';

    /** The event names another tenant (§22.4 row 2). */
    public const TENANT_MISMATCH = 'tenant_mismatch';

    /**
     * The event name is outside the §22.5 registry — which is also how the §22.7
     * hot-path exclusion is refused, since those operations are in no registry.
     */
    public const UNKNOWN_EVENT = 'unknown_event';

    /** The body is not a decodable reactor event. */
    public const MALFORMED = 'malformed';

    /**
     * `require_mfa` was answered on an event other than `login.post_auth` (§22.4
     * row 7). Refused client-side rather than sent: the server would refuse it
     * too, before even looking at the decision.
     */
    public const REQUIRE_MFA_NOT_SUPPORTED = 'require_mfa_not_supported';

    /**
     * A `mutate` answer with no patch entries (§22.4 row 10,
     * `malformed_mutation`). There is nothing to gain by putting it on the wire.
     */
    public const MALFORMED_MUTATION = 'malformed_mutation';

    /** The handler threw, or could not decide. */
    public const HANDLER_ERROR = 'handler_error';

    /** The dispatch window closed before a reply could be signed (§22.3). */
    public const DEADLINE_PASSED = 'deadline_passed';

    /**
     * @param string $reason One of the class constants above — a category, never a
     *                       value from the message.
     */
    public function __construct(private readonly string $reason, string $message)
    {
        parent::__construct($message);
    }

    /**
     * The fixed-vocabulary rejection category. Safe to log: it is a category name,
     * not a MAC, a key or a payload.
     */
    public function reason(): string
    {
        return $this->reason;
    }
}
