<?php

declare(strict_types=1);

namespace Axiam\Sdk\Ssf;

/**
 * The default {@see ReplayStore}: one process's memory, entries expiring after the window.
 */
final class InMemoryReplayStore implements ReplayStore
{
    /** @var array<string,int> jti => expiry (seconds since the epoch) */
    private array $seen = [];

    /** @var callable(): int */
    private $clock;

    /** @param (callable(): int)|null $clock The current time in seconds; `time()` when omitted. */
    public function __construct(?callable $clock = null)
    {
        $this->clock = $clock ?? static fn (): int => time();
    }

    /** {@inheritDoc} */
    public function checkAndRecord(string $jti, int $windowSeconds): bool
    {
        $now = ($this->clock)();
        $this->seen = array_filter($this->seen, static fn (int $expires): bool => $expires > $now);
        if (isset($this->seen[$jti])) {
            return false;
        }
        $this->seen[$jti] = $now + $windowSeconds;

        return true;
    }
}
