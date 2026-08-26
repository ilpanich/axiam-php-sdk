<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management;

use Axiam\Sdk\Core\NetworkError;

/**
 * `400`/`422` on the §27 management surface — CONTRACT.md §27.4 rule 7.
 *
 * Extends {@see NetworkError}, inherited from §2's own `400` row. That placement has one
 * consequence worth naming: §16's retry helper retries {@see NetworkError}, so without
 * care a body the server has already rejected would be sent three times. §27.4 rule 8
 * (only `GET` is retried) and the `retryable` predicate on
 * {@see \Axiam\Sdk\Core\RetryPolicy::execute()} are what stop that.
 */
final class ValidationError extends NetworkError
{
    /**
     * @param string           $message Human-readable summary of the rejection.
     * @param list<FieldError> $fields  Per-field complaints; empty when the server sent none.
     */
    public function __construct(string $message, public readonly array $fields = [])
    {
        parent::__construct($message);
    }
}
