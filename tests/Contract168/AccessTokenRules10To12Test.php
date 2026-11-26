<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract168;

use Axiam\Sdk\Auth\JwksVerifier;
use Axiam\Sdk\Tests\Fixtures\AccessTokenFixtureTrait;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * Security audit 2026-11-14, N14 (CONTRACT.md §10.1 rules 10–12, contract 1.68): the guard
 * entry point takes ACCESS tokens only. AXIAM signs MFA challenges, MFA setup tokens and the
 * WebAuthn ceremony state with the access-token key; they carry `sub`, `tenant_id`, `iss` and
 * `exp` and no `aud`, so a verifier with no expected audience (the default) admitted them.
 *
 * Every case uses an otherwise-valid token for the configured tenant, signed by the JWKS key,
 * with no `aud`, and a verifier configured with no expected audience.
 */
final class AccessTokenRules10To12Test extends TestCase
{
    use AccessTokenFixtureTrait;

    private const TENANT = 'acme-tenant';

    private function verifier(): JwksVerifier
    {
        $jwks = (string) file_get_contents(__DIR__ . '/../Fixtures/ed25519_jwks.json'); // a ONE-key set
        $mock = new MockHandler([
            new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks'])),
            new Response(200, [], $jwks),
        ]);

        return new JwksVerifier(new Client(['handler' => HandlerStack::create($mock)]), 'https://api.test');
    }

    /** @return iterable<string, array{string}> */
    public static function refusedTyps(): iterable
    {
        yield 'generic JWT (a pre-1.67 access token)' => ['JWT'];
        yield 'MFA challenge' => ['axiam-mfa-challenge+jwt'];
        yield 'WebAuthn state' => ['axiam-webauthn-state+jwt'];
        yield 'back-channel logout token' => ['logout+jwt'];
        yield 'security event token' => ['secevent+jwt'];
        yield 'a longer type that merely contains at+jwt' => ['x-at+jwt'];
        yield 'empty' => [''];
    }

    /** @dataProvider refusedTyps */
    public function testRule10RefusesAnyTypeOtherThanAtJwt(string $typ): void
    {
        self::assertNull($this->verifier()->verify($this->mintAccessToken([], ['typ' => $typ]), self::TENANT));
    }

    public function testRule10RefusesATypThatIsNotAString(): void
    {
        self::assertNull($this->verifier()->verify($this->mintAccessToken([], ['typ' => 123]), self::TENANT));
    }

    /** @return iterable<string, array{?string}> */
    public static function acceptedTyps(): iterable
    {
        yield 'at+jwt' => ['at+jwt'];
        yield 'AT+JWT (case-insensitive)' => ['AT+JWT'];
        yield 'application/at+jwt' => ['application/at+jwt'];
        yield 'Application/AT+JWT' => ['Application/AT+JWT'];
        yield 'no typ at all' => [null];
    }

    /** @dataProvider acceptedTyps */
    public function testRule10AcceptsAtJwtInEveryRfc7515SpellingAndNoTypAtAll(?string $typ): void
    {
        $claims = $this->verifier()->verify($this->mintAccessToken([], ['typ' => $typ]), self::TENANT);

        self::assertIsArray($claims);
        self::assertSame(self::TENANT, $claims['tenant_id']);
    }

    /** @return iterable<string, array{array<string,mixed>}> */
    public static function purposeClaims(): iterable
    {
        yield 'MFA challenge' => [['purpose' => 'mfa_challenge']];
        yield 'MFA setup' => [['purpose' => 'mfa_setup']];
        yield 'WebAuthn discoverable state, nil-UUID subject' => [[
            'sub' => '00000000-0000-0000-0000-000000000000',
            'purpose' => 'webauthn_authenticate_discoverable',
        ]];
        yield 'purpose null (null is still a purpose member)' => [['purpose' => null]];
        yield 'purpose empty string' => [['purpose' => '']];
    }

    /**
     * @dataProvider purposeClaims
     *
     * @param array<string,mixed> $claims
     */
    public function testRule11RefusesAPurposeTokenWhateverItsTypSays(array $claims): void
    {
        // typ: at+jwt and a valid kid: rule 11 alone has to refuse it.
        self::assertNull($this->verifier()->verify($this->mintAccessToken($claims), self::TENANT));
        // and with no typ at all, a pre-1.67 purpose token's shape.
        self::assertNull($this->verifier()->verify($this->mintAccessToken($claims, ['typ' => null]), self::TENANT));
        // and under the generic type pre-1.67 servers gave every token.
        self::assertNull($this->verifier()->verify($this->mintAccessToken($claims, ['typ' => 'JWT']), self::TENANT));
    }

    /**
     * Rule 12. NOT a defect in this SDK: `JwksVerifier::verifyWithProofs()` has always refused a
     * header with no `kid` before any key lookup, so php-jwt's lookup-by-`kid` never sees one and
     * there is no "the only key in the set" fallback to remove. Kept as a pin.
     */
    public function testRule12RefusesAHeaderWithNoKidAgainstAOneKeyJwks(): void
    {
        $verifier = $this->verifier();
        self::assertNull($verifier->verify($this->mintAccessToken([], ['kid' => null]), self::TENANT));
        self::assertNull($verifier->verify($this->mintAccessToken([], ['kid' => '']), self::TENANT));
        // and the same token with its kid is fine, so the refusal above is the missing kid.
        self::assertIsArray($this->verifier()->verify($this->mintAccessToken(), self::TENANT));
    }

    public function testANormalAccessTokenPasses(): void
    {
        $claims = $this->verifier()->verify($this->mintAccessToken(['scope' => 'openid roles', 'roles' => ['admin']]), self::TENANT);

        self::assertIsArray($claims);
        self::assertSame('user-fixture-0001', $claims['sub']);
        self::assertSame(['admin'], $claims['roles']);
    }
}
