<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management;

/**
 * One field-level complaint from a `400`/`422` validation body (CONTRACT.md §27.4
 * rule 7).
 *
 * Carried by {@see ValidationError} so a caller can point at the offending input
 * rather than re-parsing the server's message text.
 */
final class FieldError
{
    /**
     * @param string $field   Dotted path to the rejected field, as the server named it
     *                        (e.g. `metadata.owner`).
     * @param string $message The server's complaint about that field.
     */
    public function __construct(
        public readonly string $field,
        public readonly string $message,
    ) {
    }
}
