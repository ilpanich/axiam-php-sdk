<?php

declare(strict_types=1);

namespace Axiam\Sdk\Account;

use Axiam\Sdk\Core\Sensitive;

/**
 * Arguments to `AxiamClient::confirmPasswordReset()` (CONTRACT.md §25.1).
 */
final readonly class PasswordResetConfirmation
{
    /**
     * @param Sensitive|string         $token       The single-use token from the reset mail.
     *   Accepted bare as well as wrapped, like every other §12/§20 secret input: a caller
     *   typically has it as a raw string out of a mail link.
     * @param Sensitive|string         $newPassword The replacement password.
     * @param string                   $tenantId    The tenant the account belongs to. A **body**
     *   field: this is not an `/oauth2` endpoint, so §12.1 rule 2's query-parameter convention
     *   does not reach it.
     * @param array<string,mixed>|null $opaque      The §23 registration record, for a tenant
     *   whose `passwordResetContext()` reported an OPAQUE policy. `null` on the plaintext path.
     */
    public function __construct(
        public Sensitive|string $token,
        public Sensitive|string $newPassword,
        public string $tenantId,
        public ?array $opaque = null,
    ) {
    }
}
