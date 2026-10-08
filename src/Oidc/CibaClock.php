<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * The clock {@see OidcClient::cibaAwait()} waits on — injectable so the §33.7 schedule is
 * testable without sleeping.
 */
interface CibaClock
{
    /** The current time, in seconds (fractional allowed). */
    public function now(): float;

    /** Wait `$seconds`. */
    public function sleep(int $seconds): void;
}
