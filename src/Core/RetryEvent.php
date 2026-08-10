<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

/**
 * Emitted before each §16 retry wait (CONTRACT.md §19).
 *
 * §16.5 requires this: a retried-then-succeeded operation is otherwise invisible
 * — the caller sees a slow success and no signal that the server is failing.
 * That silence is the standing objection to automatic retry.
 */
final class RetryEvent extends TelemetryEvent
{
    /**
     * @param string $operation Canonical operation name.
     * @param int    $attempt   The attempt that just failed.
     * @param float  $delayMs   The wait about to be taken, after jitter and any
     *                          `Retry-After`.
     * @param string $reason    A redacted failure description; never carries a token.
     */
    public function __construct(
        public readonly string $operation,
        public readonly int $attempt,
        public readonly float $delayMs,
        public readonly string $reason,
    ) {
    }
}
