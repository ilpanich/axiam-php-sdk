<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract169;

use Axiam\Sdk\Auth\JwksVerifier;
use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Oidc\OidcConfiguration;
use Axiam\Sdk\Tests\Fixtures\OidcJwtFixtureTrait;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * Contract 1.69 (CONTRACT.md §12.7.3 rule 1, §12.7.6; axiam#880): the back-channel logout token
 * carries its JWKS `kid` and `verify_logout_token` selects the key by it.
 *
 * This SDK's logout path already goes through the §12.4 verifier, which has always required a
 * `kid`, so none of these tests reproduces a defect: they are the contract's required tests,
 * pinned. What they add over `OidcLogoutTest` is the SHAPE of the token: the existing tests
 * signed through a library that writes `typ: JWT`, which the server never sends on a logout
 * token. Here the header is exactly `{"alg":"EdDSA","typ":"logout+jwt","kid":"<kid>"}`, written
 * by hand, and the JWKS holds two keys with the signing key not first.
 */
final class LogoutTokenKidTest extends TestCase
{
    use OidcJwtFixtureTrait;

    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';
    private const CLIENT_ID = 'my-app';
    private const TENANT_UUID = '22222222-2222-2222-2222-222222222222';
    private const EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    private static function b64(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private function configuration(): OidcConfiguration
    {
        return new OidcConfiguration(
            issuer: self::BASE_URL,
            authorization_endpoint: self::BASE_URL . '/oauth2/authorize',
            token_endpoint: self::BASE_URL . '/oauth2/token',
            userinfo_endpoint: self::BASE_URL . '/oauth2/userinfo',
            jwks_uri: self::BASE_URL . '/oauth2/jwks',
            revocation_endpoint: self::BASE_URL . '/oauth2/revoke',
            introspection_endpoint: self::BASE_URL . '/oauth2/introspect',
            response_types_supported: ['code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['EdDSA'],
            scopes_supported: ['openid'],
            token_endpoint_auth_methods_supported: ['client_secret_post'],
            claims_supported: ['sub'],
            grant_types_supported: ['authorization_code'],
            end_session_endpoint: self::BASE_URL . '/oauth2/end_session',
            backchannel_logout_supported: true,
            backchannel_logout_session_supported: true,
        );
    }

    /** A JWKS of TWO Ed25519 keys, a rotation: an unrelated key FIRST, the signing key second. */
    private function twoKeyJwks(): string
    {
        $decoy = sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair(str_repeat("\x07", 32)));
        $keys = $this->fixtureJwks()['keys'];
        array_unshift($keys, [
            'kty' => 'OKP',
            'crv' => 'Ed25519',
            'x' => self::b64($decoy),
            'kid' => 'axiam-decoy-key',
            'use' => 'sig',
            'alg' => 'EdDSA',
        ]);

        return (string) json_encode(['keys' => $keys]);
    }

    /** @param array<int,Response> $queue */
    private function client(string $jwks, int $copies = 6): AxiamClient
    {
        return new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            oidcClientId: self::CLIENT_ID,
            oidcTenantId: self::TENANT_UUID,
            transportHandler: HandlerStack::create(new MockHandler(array_fill(0, $copies, new Response(200, [], $jwks)))),
        );
    }

    /**
     * Signs `$claims` the way the server signs a logout token: the header is written here, byte
     * for byte, and NOTHING is added by a JWT library. `$header` is the whole header object.
     *
     * @param array<string,mixed> $header
     * @param array<string,mixed> $claims
     */
    private function signWithHeader(array $header, array $claims): string
    {
        $secret = (string) base64_decode(strtr($this->fixtureKeypair()[0], '-_', '+/'), true);
        $input = self::b64((string) json_encode($header)) . '.' . self::b64((string) json_encode($claims));

        return $input . '.' . self::b64(sodium_crypto_sign_detached($input, $secret));
    }

    /** @return array<string,mixed> the server's logout-token header: exactly alg, typ, kid */
    private function serverHeader(): array
    {
        return ['alg' => 'EdDSA', 'typ' => 'logout+jwt', 'kid' => $this->fixtureKid()];
    }

    /** @return array<string,mixed> the server's logout-token claims */
    private function serverClaims(): array
    {
        $now = time();

        return [
            'iss' => self::BASE_URL,
            'aud' => self::CLIENT_ID,
            'iat' => $now,
            'exp' => $now + 120,
            'jti' => 'logout-jti-1',
            'sid' => 'session-abc',
            'sub' => 'user-1',
            'events' => [self::EVENT => new \stdClass()],
        ];
    }

    public function testAServerShapedLogoutTokenVerifiesAgainstATwoKeyJwksWithTheSigningKeyNotFirst(): void
    {
        $token = $this->signWithHeader($this->serverHeader(), $this->serverClaims());
        self::assertSame(
            '{"alg":"EdDSA","typ":"logout+jwt","kid":"' . $this->fixtureKid() . '"}',
            (string) base64_decode(strtr(explode('.', $token)[0], '-_', '+/'), true),
            'the fixture header is exactly what the server sends',
        );

        $verified = $this->client($this->twoKeyJwks())->verifyLogoutToken($token, configuration: $this->configuration());

        self::assertSame('session-abc', $verified->sid);
        self::assertSame('user-1', $verified->sub);
        self::assertSame('logout-jti-1', $verified->jti);
    }

    public function testAKidlessLogoutTokenIsRefusedAsUnknownKidAgainstAOneKeyJwksWhoseKeySignedIt(): void
    {
        $header = $this->serverHeader();
        unset($header['kid']);
        $token = $this->signWithHeader($header, $this->serverClaims());
        $oneKeyJwks = (string) file_get_contents(__DIR__ . '/../Fixtures/ed25519_jwks.json');

        try {
            $this->client($oneKeyJwks)->verifyLogoutToken($token, configuration: $this->configuration());
            self::fail('a kid-less logout token must be refused');
        } catch (AuthError $e) {
            self::assertSame('unknown_kid', $e->getReason());
        }
    }

    public function testAKidlessLogoutTokenIsAlsoRefusedAgainstATwoKeyJwks(): void
    {
        $header = $this->serverHeader();
        unset($header['kid']);

        try {
            $this->client($this->twoKeyJwks())->verifyLogoutToken(
                $this->signWithHeader($header, $this->serverClaims()),
                configuration: $this->configuration(),
            );
            self::fail('a kid-less logout token must be refused');
        } catch (AuthError $e) {
            self::assertSame('unknown_kid', $e->getReason());
        }
    }

    public function testALogoutTokenWithAnUnknownKidIsRefusedAsUnknownKid(): void
    {
        $header = $this->serverHeader();
        $header['kid'] = 'axiam-never-published';

        try {
            $this->client($this->twoKeyJwks())->verifyLogoutToken(
                $this->signWithHeader($header, $this->serverClaims()),
                configuration: $this->configuration(),
            );
            self::fail('an unknown kid must be refused');
        } catch (AuthError $e) {
            self::assertSame('unknown_kid', $e->getReason());
        }
    }

    public function testALogoutTokenSelectsItsKeyByKidNotByPosition(): void
    {
        // The token names the DECOY's kid but is signed by the other key: selecting by kid finds
        // the decoy's key and the signature fails. A verifier that tried every key would accept it.
        $header = $this->serverHeader();
        $header['kid'] = 'axiam-decoy-key';

        try {
            $this->client($this->twoKeyJwks())->verifyLogoutToken(
                $this->signWithHeader($header, $this->serverClaims()),
                configuration: $this->configuration(),
            );
            self::fail('a token signed by another key than its kid names must be refused');
        } catch (AuthError $e) {
            self::assertSame('invalid_signature', $e->getReason());
        }
    }

    public function testRules10And11StayOffTheLogoutAndIdTokenPathsWhileTheAccessGuardRefusesBoth(): void
    {
        $verifier = new JwksVerifier(
            new Client(['handler' => HandlerStack::create(new MockHandler(array_fill(0, 6, new Response(200, [], $this->twoKeyJwks()))))]),
            self::BASE_URL,
        );

        $logout = $this->signWithHeader($this->serverHeader(), $this->serverClaims());
        $now = time();
        $idToken = $this->signWithHeader(
            ['alg' => 'EdDSA', 'typ' => 'JWT', 'kid' => $this->fixtureKid()],
            ['iss' => self::BASE_URL, 'aud' => self::CLIENT_ID, 'sub' => 'user-1', 'iat' => $now, 'exp' => $now + 300, 'nonce' => 'n'],
        );

        // The verifier the access-token guard shares: the logout token (typ logout+jwt) and the
        // ID token (typ JWT) both verify on the ID-token/logout path ...
        self::assertSame('session-abc', $verifier->verifyIdTokenSignature($logout)['sid']);
        self::assertSame('user-1', $verifier->verifyIdTokenSignature($idToken)['sub']);

        // ... while the access-token guard entry point refuses both (rule 10 on the type; rule 4
        // independently, neither carries a tenant_id).
        self::assertNull($verifier->verify($logout, self::TENANT));
        self::assertNull($verifier->verify($idToken, self::TENANT));
    }
}
