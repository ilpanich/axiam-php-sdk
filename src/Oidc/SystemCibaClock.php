<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * The real {@see CibaClock}: `microtime(true)` and `sleep()`.
 */
final class SystemCibaClock implements CibaClock
{
    /** {@inheritDoc} */
    public function now(): float
    {
        return microtime(true);
    }

    /** {@inheritDoc} */
    public function sleep(int $seconds): void
    {
        if ($seconds > 0) {
            sleep($seconds);
        }
    }
}
