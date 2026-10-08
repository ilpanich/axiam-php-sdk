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
     * @param string           $message       Human-readable summary of the rejection.
     * @param list<FieldError> $fields        Per-field complaints; empty when the server sent none.
     * @param string|null      $serverMessage The server's own `message` member, verbatim, when
     *                                        its body carried one — it names the field and the
     *                                        rule (§29.4, §30.4). For a person to read: its
     *                                        wording may change, so never parse it. `null` for a
     *                                        local refusal and for a body without one.
     */
    public function __construct(
        string $message,
        public readonly array $fields = [],
        public readonly ?string $serverMessage = null,
    ) {
        parent::__construct($message);
    }
}
