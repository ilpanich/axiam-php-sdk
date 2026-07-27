<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Oidc\Pkce;
use PHPUnit\Framework\TestCase;

/**
 * CONTRACT.md §12.1 rule 3: "Every SDK MUST include the RFC 7636 Appendix B test
 * vector as a unit test." Plus §12.1 rule 1's entropy/uniqueness requirements and the
 * S256-only guarantee (`plain` is unreachable anywhere in this SDK).
 */
final class OidcPkceTest extends TestCase
{
    /** RFC 7636 Appendix B: the canonical verifier -> challenge vector every SDK must carry. */
    public function testRfc7636AppendixBVector(): void
    {
        $verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

        self::assertSame('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', Pkce::computeCodeChallenge($verifier));
    }

    public function testCodeChallengeMethodIsS256Only(): void
    {
        self::assertSame('S256', Pkce::CODE_CHALLENGE_METHOD_S256);
    }

    // --- §12.1 rule 1: state/nonce >= 128 bits, base64url unpadded --------------------

    public function testRandomUrlSafeTokenHasNoPadding(): void
    {
        $token = Pkce::randomUrlSafeToken();

        self::assertStringNotContainsString('=', $token);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $token);
    }

    public function testRandomUrlSafeTokenDefaultEntropyIsAtLeast128Bits(): void
    {
        // 32 CSPRNG bytes (256 bits) base64url-encoded, unpadded -> 43 characters.
        self::assertSame(43, strlen(Pkce::randomUrlSafeToken()));
    }

    public function testRandomUrlSafeTokenCallsAreUnique(): void
    {
        $tokens = array_map(static fn () => Pkce::randomUrlSafeToken(), range(1, 25));

        self::assertCount(25, array_unique($tokens), 'every generated state/nonce must be unique');
    }

    public function testMinimumEntropyOf16BytesIsHonoured(): void
    {
        // §12.1 rule 1's floor: 16 bytes (128 bits) is a legal (if non-default) request.
        $token = Pkce::randomUrlSafeToken(16);

        self::assertSame(22, strlen($token)); // 16 bytes -> 22 base64url chars, unpadded.
    }

    // --- §12.1 rule 2: code_verifier is 43-128 chars from the RFC 7636 unreserved set --

    public function testGeneratedCodeVerifierIsSensitiveAndUnreservedCharset(): void
    {
        $verifier = Pkce::generateCodeVerifier();

        self::assertInstanceOf(Sensitive::class, $verifier);
        $raw = $verifier->reveal();
        self::assertSame(43, strlen($raw), '32 CSPRNG bytes base64url-encode to exactly 43 characters');
        self::assertMatchesRegularExpression('/^[A-Za-z0-9\-._~]+$/', $raw);
    }

    public function testGeneratedCodeVerifiersAreUnique(): void
    {
        $verifiers = array_map(
            static fn () => Pkce::generateCodeVerifier()->reveal(),
            range(1, 10),
        );

        self::assertCount(10, array_unique($verifiers));
    }

    public function testCodeChallengeIsDeterministicForTheSameVerifier(): void
    {
        $verifier = Pkce::generateCodeVerifier()->reveal();

        self::assertSame(Pkce::computeCodeChallenge($verifier), Pkce::computeCodeChallenge($verifier));
    }

    public function testCodeChallengeIsUrlSafeAndUnpadded(): void
    {
        $challenge = Pkce::computeCodeChallenge(Pkce::generateCodeVerifier()->reveal());

        self::assertStringNotContainsString('=', $challenge);
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $challenge);
    }

    public function testBase64UrlEncodeNeverEmitsStandardBase64Characters(): void
    {
        // Bytes chosen so standard base64 would emit '+', '/', and '=' padding.
        $encoded = Pkce::base64UrlEncode("\xfb\xff\xbf");

        self::assertStringNotContainsString('+', $encoded);
        self::assertStringNotContainsString('/', $encoded);
        self::assertStringNotContainsString('=', $encoded);
    }

    /** {@see Pkce} is a static-only utility class with a private, deliberately-empty constructor. */
    public function testCannotBeInstantiatedPublicly(): void
    {
        $reflection = new \ReflectionClass(Pkce::class);
        $constructor = $reflection->getConstructor();
        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->setAccessible(true);
        $constructor->invoke($instance);
        self::assertInstanceOf(Pkce::class, $instance);
    }
}
