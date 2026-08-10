<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

/**
 * Emitted at construction, once per caller-supplied setting the SDK clamped
 * (CONTRACT.md §19.1, §19.2 rule 6).
 *
 * Two places in the contract require clamping rather than rejecting: §16.1's
 * attempt cap, base delay and delay cap, and §17.1 rule 2's memo TTL. Both
 * clamps are right — rejecting would break a caller whose configuration was
 * merely optimistic, and honoring would let one client become the herd §16
 * exists to prevent. Doing it *silently* is the part that is wrong.
 *
 * An operator who set a 60-second memo TTL believes they have one. They have
 * five seconds, and their staleness reasoning is off by a factor of twelve with
 * nothing anywhere to say so. This event is what makes the clamp discoverable at
 * the only moment it can be acted on.
 *
 * It is **not** emitted for a value already within its limit: an event that
 * fires when nothing happened trains its reader to ignore it.
 */
final class ConfigClampedEvent extends TelemetryEvent
{
    /**
     * @param string $setting           The setting's name, e.g. `decisionMemoTtlMs`.
     * @param string $requested         The value the caller asked for, rendered.
     * @param string $effective         The value actually in force, rendered.
     * @param string $contractReference The §-reference for the limit, e.g. `§17.1 rule 2`.
     */
    public function __construct(
        public readonly string $setting,
        public readonly string $requested,
        public readonly string $effective,
        public readonly string $contractReference,
    ) {
    }
}
