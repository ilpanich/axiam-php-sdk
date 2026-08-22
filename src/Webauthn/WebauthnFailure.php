<?php

declare(strict_types=1);

namespace Axiam\Sdk\Webauthn;

/**
 * A ceremony failure a caller can say something useful about (CONTRACT.md §24.6b rule 5).
 *
 * This SDK ships no linked-API helper — PHP runs on a server, which has no authenticator, and
 * §24.6b rule 2 forbids emulating one — but the classification is still required of it: the
 * browser half of a PHP relying party catches a `DOMException` and relays its name, and it has
 * the same five outcomes and the same reason to want one vocabulary for them.
 */
enum WebauthnFailure: string
{
    /**
     * Covers **both** an explicit refusal and a silent timeout.
     *
     * The WebAuthn spec deliberately refuses to distinguish them, because telling a website
     * which one happened leaks whether an authenticator was present. It must not be recovered
     * by timing the call.
     */
    case Cancelled = 'cancelled';

    /**
     * The authenticator already holds a credential for this account and refused to silently
     * mint a second — the exclusion list working, not a failure. The only classification whose
     * remedy is "use a different device".
     */
    case AlreadyRegistered = 'already_registered';

    /** An explicitly aborted ceremony. */
    case Timeout = 'timeout';

    /** This device or browser cannot run the ceremony. */
    case Unsupported = 'unsupported';

    /** Everything else. */
    case Unknown = 'unknown';

    /**
     * Map a platform ceremony error name to its canonical classification.
     *
     * Every platform reports a ceremony failure as one opaque type whose only machine-readable
     * part is a name, so a browser can relay just that name and a PHP relying party turns it
     * into the same five outcomes. Anything unrecognised is {@see self::Unknown} rather than a
     * throw — a classifier that can fail is one more thing for an error handler to handle.
     */
    public static function classify(?string $name): self
    {
        return match (strtolower(trim($name ?? ''))) {
            'notallowederror', 'canceled', 'cancelled' => self::Cancelled,
            'invalidstateerror' => self::AlreadyRegistered,
            'aborterror', 'timeout' => self::Timeout,
            'notsupportederror', 'securityerror' => self::Unsupported,
            default => self::Unknown,
        };
    }

    /**
     * Copy for this failure, safe to show a user.
     *
     * The {@see self::Cancelled} string deliberately does not accuse anyone of cancelling: the
     * same classification covers a silent timeout, and the spec will not say which happened.
     */
    public function message(): string
    {
        return match ($this) {
            self::Cancelled => 'The request was cancelled or timed out. You can try again.',
            self::AlreadyRegistered => 'This device is already registered on your account. '
                . 'Try a different device, or remove the existing one first.',
            self::Timeout => 'The request timed out before it completed. Please try again.',
            self::Unsupported => 'This browser or device cannot be used for passkeys. '
                . 'Try a different browser, or use another sign-in method.',
            self::Unknown => 'Something went wrong. Please try again.',
        };
    }
}
