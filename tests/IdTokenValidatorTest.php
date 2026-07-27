<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Oidc\IdTokenValidator;
use PHPUnit\Framework\TestCase;

/**
 * Direct unit coverage of {@see IdTokenValidator} — the pure §12.4 rules 3–6 logic
 * (issuer/audience/time/nonce), exercised here without going through a full
 * `AxiamClient::oidcExchange()` round trip (that integration path is covered by
 * {@see \Axiam\Sdk\Tests\OidcExchangeTest}'s one-test-per-reason-code suite).
 */
final class IdTokenValidatorTest extends TestCase
{
    /** @return array<string,mixed> */
    private function validClaims(): array
    {
        return [
            'iss' => 'https://api.test',
            'sub' => 'user-1',
            'aud' => 'my-app',
            'exp' => 2000000000,
            'iat' => 1000000000,
            'nonce' => 'the-nonce',
        ];
    }

    public function testHappyPathReturnsClaimsUnchanged(): void
    {
        $claims = IdTokenValidator::checkClaims(
            $this->validClaims(),
            issuer: 'https://api.test',
            clientId: 'my-app',
            nonce: 'the-nonce',
            nowSec: 1500000000,
        );

        self::assertSame('user-1', $claims['sub']);
    }

    public function testResolveClockSkewDefaultsToMaximumWhenNull(): void
    {
        self::assertSame(IdTokenValidator::MAX_CLOCK_SKEW_SEC, IdTokenValidator::resolveClockSkewSec(null));
    }

    public function testResolveClockSkewClampsAboveTheMaximum(): void
    {
        self::assertSame(IdTokenValidator::MAX_CLOCK_SKEW_SEC, IdTokenValidator::resolveClockSkewSec(999));
    }

    public function testResolveClockSkewClampsBelowZero(): void
    {
        self::assertSame(0, IdTokenValidator::resolveClockSkewSec(-10));
    }

    public function testCheckClaimsWithNullClockSkewUsesTheDefault(): void
    {
        // Calling checkClaims() directly (bypassing OidcClient, which always resolves
        // clockSkewSec before calling this) exercises resolveClockSkewSec()'s own
        // null-input branch.
        $claims = IdTokenValidator::checkClaims(
            $this->validClaims(),
            issuer: 'https://api.test',
            clientId: 'my-app',
            nonce: 'the-nonce',
            clockSkewSec: null,
            nowSec: 1500000000,
        );

        self::assertSame('user-1', $claims['sub']);
    }

    public function testFailureBuildsAuthErrorWithReasonAndMessage(): void
    {
        $error = IdTokenValidator::failure(IdTokenValidator::REASON_INVALID_ISSUER, 'the details');

        self::assertInstanceOf(AuthError::class, $error);
        self::assertSame(IdTokenValidator::REASON_INVALID_ISSUER, $error->getReason());
        self::assertStringContainsString('invalid_issuer', $error->getMessage());
        self::assertStringContainsString('the details', $error->getMessage());
    }

    public function testMissingExpClaimIsTokenExpired(): void
    {
        $claims = $this->validClaims();
        unset($claims['exp']);

        try {
            IdTokenValidator::checkClaims($claims, 'https://api.test', 'my-app', 'the-nonce', nowSec: 1500000000);
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertSame(IdTokenValidator::REASON_TOKEN_EXPIRED, $e->getReason());
        }
    }

    public function testMissingIatClaimIsTokenExpired(): void
    {
        $claims = $this->validClaims();
        unset($claims['iat']);

        try {
            IdTokenValidator::checkClaims($claims, 'https://api.test', 'my-app', 'the-nonce', nowSec: 1500000000);
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertSame(IdTokenValidator::REASON_TOKEN_EXPIRED, $e->getReason());
        }
    }

    public function testIatInTheFutureIsTokenExpired(): void
    {
        $claims = array_merge($this->validClaims(), ['iat' => 1600000000]);

        try {
            IdTokenValidator::checkClaims($claims, 'https://api.test', 'my-app', 'the-nonce', nowSec: 1500000000);
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertSame(IdTokenValidator::REASON_TOKEN_EXPIRED, $e->getReason());
        }
    }

    public function testNbfInTheFutureIsTokenExpired(): void
    {
        $claims = array_merge($this->validClaims(), ['nbf' => 1600000000]);

        try {
            IdTokenValidator::checkClaims($claims, 'https://api.test', 'my-app', 'the-nonce', nowSec: 1500000000);
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertSame(IdTokenValidator::REASON_TOKEN_EXPIRED, $e->getReason());
        }
    }

    public function testConstantTimeEqualsIsCaseSensitiveExactMatch(): void
    {
        self::assertTrue(IdTokenValidator::constantTimeEquals('abc', 'abc'));
        self::assertFalse(IdTokenValidator::constantTimeEquals('abc', 'abd'));
        self::assertFalse(IdTokenValidator::constantTimeEquals('abc', 'ABC'));
    }

    /**
     * {@see IdTokenValidator} is a static-only utility class with a private,
     * deliberately-empty constructor (mirroring {@see \Axiam\Sdk\Oidc\Pkce}) — this
     * proves it is genuinely never instantiated as an object with state, while still
     * exercising the (trivial) constructor body for completeness.
     */
    public function testCannotBeInstantiatedPublicly(): void
    {
        $reflection = new \ReflectionClass(IdTokenValidator::class);
        $constructor = $reflection->getConstructor();
        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->setAccessible(true);
        $constructor->invoke($instance);
        self::assertInstanceOf(IdTokenValidator::class, $instance);
    }
}
