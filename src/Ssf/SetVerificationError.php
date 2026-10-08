<?php

declare(strict_types=1);

namespace Axiam\Sdk\Ssf;

use Axiam\Sdk\Core\AuthError;

/**
 * A Security Event Token refused by {@see SsfReceiver::verifySet()} (CONTRACT.md §32.7) — an
 * {@see AuthError}, as §32.7 requires, carrying the step that failed as a typed
 * {@see SetFailureReason}. {@see AuthError::getReason()} returns the same code as a string.
 *
 * The message names the rule, never a claim value or the token.
 */
final class SetVerificationError extends AuthError
{
    /**
     * @param SetFailureReason $failureReason Which verification step refused the SET.
     * @param string           $detail        A fixed description of the rule that failed.
     */
    public function __construct(public readonly SetFailureReason $failureReason, string $detail)
    {
        parent::__construct(
            sprintf('SET refused (%s): %s (CONTRACT.md §32.7)', $failureReason->value, $detail),
            reason: $failureReason->value,
        );
    }
}
