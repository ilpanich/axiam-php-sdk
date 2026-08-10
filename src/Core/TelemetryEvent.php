<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

/**
 * A telemetry event (CONTRACT.md §19).
 *
 * PHP has no `sealed` keyword, so the closed-hierarchy guarantee §19.2 rule 3
 * relies on is carried structurally instead: every subclass is `final`, with a
 * fixed list of `readonly` promoted properties and no free-form array. There is
 * nowhere to put a token in a payload bound for a metrics backend.
 *
 * Hooks are invoked on the calling path, so a sink must not block: §19.2 rule 4
 * makes buffering the caller's job so they can pick the policy. Every mature
 * metrics library already buffers.
 *
 * @see RequestStartEvent
 * @see RequestEndEvent
 * @see RetryEvent
 * @see RefreshEvent
 */
abstract class TelemetryEvent
{
    /** Outcome: the call returned a usable response. */
    public const OUTCOME_SUCCESS = 'success';

    /** Outcome: the call failed, at any layer. */
    public const OUTCOME_FAILURE = 'failure';

    /** Refresh role: this caller performed the refresh. */
    public const REFRESH_LEADER = 'leader';

    /** Refresh role: this caller waited on another's refresh. */
    public const REFRESH_FOLLOWER = 'follower';
}
