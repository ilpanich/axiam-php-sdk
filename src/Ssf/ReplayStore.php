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
     *
     * **Fail closed** (CONTRACT.md §32.7 step 9, §34.2 P4): a store that cannot answer — its
     * backend unreachable, a timeout — MUST throw, and never return `true`. The exception is
     * no verdict on the SET: `verifySet()` raises it as a {@see \Axiam\Sdk\Core\NetworkError}
     * with the exception chained as its cause (an SDK error thrown here passes through
     * unchanged; CONTRACT.md §2), and `poll()` asks the store nothing more for that batch and
     * leaves that SET unjudged and unrecorded (§34.2 P1, P3).
     *
     * @throws \Throwable when the store cannot answer.
     */
    public function checkAndRecord(string $jti, int $windowSeconds): bool;
}
