<?php

declare(strict_types=1);

namespace Axiam\Sdk\Srp;

/**
 * The two proofs an SRP exchange produces (CONTRACT.md §23.2).
 *
 * {@see self::$clientProof} goes on the verify request. {@see self::$expectedServerProof} stays
 * here and is compared against the response's `server_proof`: that comparison is the half of SRP
 * that authenticates the *server*, and §23.3 rule 6 makes it mandatory.
 */
final class SrpProofs
{
    public function __construct(
        /** `M1`, lowercase hex. */
        public readonly string $clientProof,
        /** The `M2` the server must return. */
        public readonly string $expectedServerProof,
    ) {
    }
}
