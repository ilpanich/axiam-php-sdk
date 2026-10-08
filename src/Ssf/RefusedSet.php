<?php

declare(strict_types=1);

namespace Axiam\Sdk\Ssf;

/**
 * One SET a poll returned that {@see SsfReceiver::verifySet()} refused.
 */
final class RefusedSet
{
    /**
     * @param string           $jti    The key the transmitter returned the SET under.
     * @param SetFailureReason $reason Why it was refused — pass {@see SetErr::fromReason()} of it
     *                                 in the next poll's `setErrs`.
     */
    public function __construct(
        public readonly string $jti,
        public readonly SetFailureReason $reason,
    ) {
    }
}
