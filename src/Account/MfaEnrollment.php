<?php

declare(strict_types=1);

namespace Axiam\Sdk\Account;

use Axiam\Sdk\Core\Sensitive;

/**
 * A TOTP factor offered but not yet active (CONTRACT.md §25.1).
 *
 * **Both halves are {@see Sensitive}, and the second one is why.** The `otpauth://` URI
 * *contains* the secret: wrapping the bare secret and then logging the URI leaks exactly the
 * same bytes (§25.3).
 */
final readonly class MfaEnrollment
{
    /**
     * @param Sensitive $secretBase32 The shared TOTP secret. Anyone holding it can generate
     *   valid codes for this account indefinitely.
     * @param Sensitive $totpUri `otpauth://totp/…?secret=<secretBase32>` — the string an
     *   authenticator app scans out of a QR code.
     */
    public function __construct(
        public Sensitive $secretBase32,
        public Sensitive $totpUri,
    ) {
    }
}
