<?php

declare(strict_types=1);

namespace Axiam\Sdk\Ssf;

/**
 * Remembers the `jti`s an {@see SsfReceiver} already accepted (CONTRACT.md §32.7 step 9).
 *
 * Pluggable so a receiver running several processes can share one store (a PHP-FPM pool does
 * not share memory: {@see InMemoryReplayStore} protects one long-running process only).
 */
interface ReplayStore
{
    /**
     * Record `$jti` for `$windowSeconds` and return `true`, or return `false` without recording
     * when it is already held. MUST be atomic: two concurrent calls with one `jti` must not both
     * see `true` (a shared store implements this with an atomic add, e.g. Redis `SET NX EX`).
     */
    public function checkAndRecord(string $jti, int $windowSeconds): bool;
}
