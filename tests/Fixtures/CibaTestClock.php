<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Fixtures;

use Axiam\Sdk\Oidc\CibaClock;

/**
 * A clock that never sleeps: `sleep()` advances `now()` and records the wait.
 */
final class CibaTestClock implements CibaClock
{
    /** @var list<int> */
    public array $sleeps = [];

    public function __construct(public float $now = 1000.0)
    {
    }

    /** The current fake time. */
    public function now(): float
    {
        return $this->now;
    }

    /** Advances the fake time and records the wait. */
    public function sleep(int $seconds): void
    {
        $this->sleeps[] = $seconds;
        $this->now += $seconds;
    }
}
