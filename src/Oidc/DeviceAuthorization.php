<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\Sensitive;

/**
 * The `DeviceAuthorizationResponse` — what the device shows its user, plus the
 * `device_code` it polls with (CONTRACT.md §14.1).
 *
 * `$deviceCode` is {@see Sensitive} (§14.5): a bearer credential for the lifetime of the
 * grant. `$userCode` deliberately is **not** — it exists to be read aloud and typed by a
 * human, and wrapping it would defeat the one thing it is for. Neither may be logged;
 * displaying the user code is the caller's job.
 */
final class DeviceAuthorization
{
    /**
     * @param Sensitive $deviceCode The device's polling credential (§14.5 secret).
     * @param string $userCode The short code the human types into the verification page.
     * @param string $verificationUri Where the human goes to enter `$userCode`.
     * @param string|null $verificationUriComplete The verification URI with the user code already embedded, when the server sent one — prefer it when the device can render a QR code. Never synthesised by concatenation when absent (§14.3): its format is the server's to choose.
     * @param int $expiresIn Seconds until the grant expires. Polling stops here (§14.2 rule 4).
     * @param int $interval Seconds between polls, from the response, defaulted to 5 when the server omitted it (§14.2 rule 2).
     */
    public function __construct(
        public readonly Sensitive $deviceCode,
        public readonly string $userCode,
        public readonly string $verificationUri,
        public readonly ?string $verificationUriComplete,
        public readonly int $expiresIn,
        public readonly int $interval,
    ) {
    }
}
