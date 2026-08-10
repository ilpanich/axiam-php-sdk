<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

/**
 * Emitted after a call completes, success or failure (CONTRACT.md §19).
 */
final class RequestEndEvent extends TelemetryEvent
{
    /**
     * @param string   $operation    Canonical operation name.
     * @param string   $method       HTTP method.
     * @param string   $pathTemplate The route constant; see {@see RequestStartEvent}.
     * @param int      $attempt      The attempt this event closes.
     * @param int|null $status       HTTP status, or null when no response arrived.
     * @param float    $durationMs   Wall-clock duration of this attempt, in milliseconds.
     * @param string   $outcome      One of {@see TelemetryEvent}'s `OUTCOME_*` constants.
     */
    public function __construct(
        public readonly string $operation,
        public readonly string $method,
        public readonly string $pathTemplate,
        public readonly int $attempt,
        public readonly ?int $status,
        public readonly float $durationMs,
        public readonly string $outcome,
    ) {
    }
}
