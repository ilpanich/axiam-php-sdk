<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Auth\JwksVerifier;
use Axiam\Sdk\Auth\PresentedProofs;
use PHPUnit\Framework\TestCase;

/**
 * CONTRACT.md §10.1 rule 9 extended for DPoP (contract 1.16).
 */
final class TokenBindingTest extends TestCase
{
    private const THUMB = 'bwcK0esC3yEWCTuAFrDPBqZ_hvIn0UbmJKlSjMbGZKM';
    private const JKT = '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I';
    private const OTHER_JKT = 'sBjflhaR2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    /**
     * Build a claim set carrying the given `cnf`, or none at all.
     *
     * @param array<string,string>|null $cnf The confirmation, or null for unbound.
     *
     * @return array<string,mixed> The claim set.
     */
    private static function claims(?array $cnf): array
    {
        return $cnf === null ? ['sub' => 'u'] : ['sub' => 'u', 'cnf' => $cnf];
    }

    /**
     * THE POSITIVE REGRESSION TEST, and the one this change is most likely to break:
     * an unbound token must still pass with no certificate and no proof. The likeliest
     * wrong implementation of rule 9 is one that starts demanding evidence from every
     * caller.
     */
    public function testUnboundTokenIsAcceptedWithNoProofsAtAll(): void
    {
        self::assertTrue(
            JwksVerifier::verifyTokenBinding(self::claims(null), PresentedProofs::none())
        );
        // ...and proofs it never asked for do not make it invalid.
        self::assertTrue(
            JwksVerifier::verifyTokenBinding(
                self::claims(null),
                new PresentedProofs(self::THUMB, self::JKT)
            )
        );
    }

    /**
     * A DPoP-bound token accepts the matching key.
     */
    public function testDpopBoundTokenAcceptsTheMatchingKey(): void
    {
        self::assertTrue(
            JwksVerifier::verifyTokenBinding(
                self::claims(['jkt' => self::JKT]),
                PresentedProofs::dpop(self::JKT)
            )
        );
    }

    /**
     * A DPoP-bound token is refused with no proof, or with a proof by another key.
     */
    public function testDpopBoundTokenIsRejectedWithoutAProofOrWithTheWrongKey(): void
    {
        self::assertFalse(
            JwksVerifier::verifyTokenBinding(
                self::claims(['jkt' => self::JKT]),
                PresentedProofs::none()
            )
        );
        self::assertFalse(
            JwksVerifier::verifyTokenBinding(
                self::claims(['jkt' => self::JKT]),
                PresentedProofs::dpop(self::OTHER_JKT)
            )
        );
    }

    /**
     * A certificate-bound token still behaves exactly as it did before contract 1.16.
     */
    public function testCertificateBoundTokenIsUnchanged(): void
    {
        $claims = self::claims(['x5t#S256' => self::THUMB]);

        self::assertTrue(
            JwksVerifier::verifyTokenBinding($claims, PresentedProofs::certificate(self::THUMB))
        );
        self::assertFalse(JwksVerifier::verifyTokenBinding($claims, PresentedProofs::none()));
        self::assertFalse(
            JwksVerifier::verifyTokenBinding($claims, PresentedProofs::certificate(self::OTHER_JKT))
        );
    }

    /**
     * BOTH NAMED IS A CONJUNCTION. An operator who turned on two constraints asked for
     * two; satisfying the more convenient one is not compliance. Each half is asserted
     * to fail alone, because "check whichever we can" is the likeliest wrong
     * implementation.
     */
    public function testCnfNamingBothMethodsRequiresBoth(): void
    {
        $both = self::claims(['x5t#S256' => self::THUMB, 'jkt' => self::JKT]);

        self::assertTrue(
            JwksVerifier::verifyTokenBinding($both, new PresentedProofs(self::THUMB, self::JKT))
        );

        self::assertFalse(
            JwksVerifier::verifyTokenBinding($both, PresentedProofs::certificate(self::THUMB))
        );
        self::assertFalse(
            JwksVerifier::verifyTokenBinding($both, PresentedProofs::dpop(self::JKT))
        );
    }

    /**
     * An empty `cnf` names nothing checkable and is refused, not read as unbound. Over
     * gRPC this is also how proto3 delivers an empty `CnfClaim` message, which is why
     * §10.3 rule 3 spells it out separately.
     */
    public function testEmptyCnfIsRefusedRatherThanReadAsUnbound(): void
    {
        self::assertFalse(
            JwksVerifier::verifyTokenBinding(self::claims([]), PresentedProofs::none())
        );
    }

    /**
     * A nested `cnf` arriving as stdClass — which is what firebase/php-jwt decodes
     * JSON objects to — is handled, not rejected. An is_array()-only check would
     * reject every legitimately bound token, which is rule 9's failure mode inverted.
     */
    public function testCnfArrivingAsStdClassIsHandled(): void
    {
        $cnf = new \stdClass();
        $cnf->jkt = self::JKT;

        self::assertTrue(
            JwksVerifier::verifyTokenBinding(
                ['sub' => 'u', 'cnf' => $cnf],
                PresentedProofs::dpop(self::JKT)
            )
        );
    }

    /**
     * The narrow entry point refuses a DPoP-bound token rather than ignoring the `jkt`
     * it cannot check. That refusal is what lets it stay in the API without becoming a
     * downgrade path.
     */
    public function testCertificateOnlyEntryPointRefusesDpopAndBothBoundTokens(): void
    {
        foreach ([null, self::THUMB] as $presented) {
            self::assertFalse(
                JwksVerifier::verifyCertificateBinding(self::claims(['jkt' => self::JKT]), $presented)
            );
        }

        self::assertFalse(
            JwksVerifier::verifyCertificateBinding(
                self::claims(['x5t#S256' => self::THUMB, 'jkt' => self::JKT]),
                self::THUMB
            )
        );
    }
}
