<?php

declare(strict_types=1);

namespace Axiam\Sdk\Account;

/**
 * The OPAQUE policy for the account a reset token belongs to (CONTRACT.md §25.1).
 */
final readonly class PasswordResetContext
{
    /**
     * @param array<string,mixed>|null $opaque The tenant's §23 parameters when it has OPAQUE
     *   enabled, and `null` when it does not — in which case the plaintext path is allowed.
     *   The block is forwarded to the §23 helpers untouched: this SDK does not model, validate
     *   or re-encode it.
     */
    public function __construct(
        public ?array $opaque = null,
    ) {
    }
}
