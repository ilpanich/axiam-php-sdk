<?php

declare(strict_types=1);

namespace Axiam\Sdk\Account;

/**
 * Arguments to `AxiamClient::requestPasswordReset()` (CONTRACT.md §25.1).
 *
 * The workspace fields are all optional: unset, they are filled from the client's own
 * configured identity, which is what almost every caller wants.
 */
final readonly class PasswordResetRequest
{
    /**
     * @param string      $email      The address to send the reset mail to.
     * @param string|null $orgSlug    An organization override.
     * @param string|null $tenantId   A tenant override, in UUID form.
     * @param string|null $tenantSlug A tenant override, in slug form.
     */
    public function __construct(
        public string $email,
        public ?string $orgSlug = null,
        public ?string $tenantId = null,
        public ?string $tenantSlug = null,
    ) {
    }
}
