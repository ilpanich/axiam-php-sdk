<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

/**
 * Emitted around a §9 single-flight refresh (CONTRACT.md §19).
 */
final class RefreshEvent extends TelemetryEvent
{
    /**
     * @param string $role       One of {@see TelemetryEvent}'s `REFRESH_*` constants.
     * @param float  $durationMs How long the refresh, or the wait for one, took.
     */
    public function __construct(
        public readonly string $role,
        public readonly float $durationMs,
    ) {
    }
}
