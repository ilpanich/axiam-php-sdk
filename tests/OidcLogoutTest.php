<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Oidc\OidcConfiguration;
use Axiam\Sdk\Tests\Fixtures\OidcJwtFixtureTrait;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * RP-initiated and back-channel logout — CONTRACT.md §12.7.
 *
 * The §12.7.6 required tests. The `verifyLogoutToken` half carries the security weight:
 * its input arrives unsolicited, from the network, and instructs the RP to terminate a
 * session — so each rejection test names the attack it prevents rather than merely
 * asserting an error.
 */
final class OidcLogoutTest extends TestCase
{
    use OidcJwtFixtureTrait;

    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';
    private const CLIENT_ID = 'my-app';
    private const TENANT_UUID = '22222222-2222-2222-2222-222222222222';
    private const ID_TOKEN = 'the-users-id-token';
    private const LOGOUT_SID = 'session-abc';
    private const LOGOUT_JTI = 'logout-token-jti-1';
    private const BACKCHANNEL_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    private function configuration(bool $withEndSession = true): OidcConfiguration
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
            end_session_endpoint: $withEndSession ? self::BASE_URL . '/oauth2/end_session' : null,
            backchannel_logout_supported: true,
            backchannel_logout_session_supported: true,
        );
    }

    /** @param array<int,Response> $queue */
    private function client(array $queue = []): AxiamClient
    {
        return new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            oidcClientId: self::CLIENT_ID,
            oidcTenantId: self::TENANT_UUID,
            transportHandler: HandlerStack::create(new MockHandler($queue)),
        );
    }

    /**
     * A VALID logout claim set; `$overrides` breaks exactly one §12.7.3 rule. A `null`
     * value removes the claim entirely.
     *
     * @param array<string,mixed> $overrides
     * @return array<string,mixed>
     */
    private function logoutClaims(array $overrides = []): array
    {
        $now = time();
        $claims = [
            'iss' => self::BASE_URL,
            'aud' => self::CLIENT_ID,
            'iat' => $now,
            'exp' => $now + 120,
            'jti' => self::LOGOUT_JTI,
            'sid' => self::LOGOUT_SID,
            'sub' => 'user-1',
            'events' => [self::BACKCHANNEL_EVENT => new \stdClass()],
        ];

        foreach ($overrides as $key => $value) {
            if ($value === null) {
                unset($claims[$key]);
                continue;
            }
            $claims[$key] = $value;
        }

        return $claims;
    }

    /**
     * Several copies: the §12.4 verifier is allowed exactly one JWKS refetch on an
     * unknown `kid`, and a one-item queue would exhaust before the check under test
     * even ran — turning every rejection assertion into a transport error.
     *
     * @return array<int,Response>
     */
    private function jwksQueue(int $copies = 4): array
    {
        return array_fill(0, $copies, new Response(200, [], (string) json_encode($this->fixtureJwks())));
    }

    private function parseQuery(string $url): array
    {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        return $query;
    }

    // ===================================================================================
    // §12.7.2 logoutUrl
    // ===================================================================================

    public function testLogoutUrlUsesTheDiscoveredEndpoint(): void
    {
        $url = $this->client()->logoutUrl(self::ID_TOKEN, configuration: $this->configuration());

        // §12.7.2 rule 1: the endpoint comes from discovery. Code that builds
        // "{issuer}/oauth2/end_session" works against AXIAM and breaks against every
        // other OP the same application is pointed at.
        self::assertStringStartsWith(self::BASE_URL . '/oauth2/end_session', $url);
        self::assertSame(self::ID_TOKEN, $this->parseQuery($url)['id_token_hint']);
    }

    public function testLogoutUrlOmitsWhatWasNotSuppliedAndPassesStateThrough(): void
    {
        $client = $this->client();

        $bare = $this->parseQuery($client->logoutUrl(self::ID_TOKEN, configuration: $this->configuration()));
        self::assertArrayNotHasKey('post_logout_redirect_uri', $bare);
        self::assertArrayNotHasKey('state', $bare);

        $full = $this->parseQuery($client->logoutUrl(
            self::ID_TOKEN,
            postLogoutRedirectUri: 'https://app.example.com/bye',
            state: 'caller-generated-state',
            configuration: $this->configuration(),
        ));
        self::assertSame('https://app.example.com/bye', $full['post_logout_redirect_uri']);
        // §12.7.2 rule 2: the SDK never invents one, because the value only means
        // something to the caller.
        self::assertSame('caller-generated-state', $full['state']);
    }

    public function testLogoutUrlDoesNotPreValidateTheRedirect(): void
    {
        // §12.7.2 rule 3: the allow-list lives in the client's server-side registration.
        // A client-side copy would drift and reject a URI an operator had just registered.
        $url = $this->client()->logoutUrl(
            self::ID_TOKEN,
            postLogoutRedirectUri: 'https://somewhere-else.example/x',
            configuration: $this->configuration(),
        );

        self::assertSame('https://somewhere-else.example/x', $this->parseQuery($url)['post_logout_redirect_uri']);
    }

    public function testLogoutUrlErrorsWhenNoEndSessionEndpointWithoutEchoingTheIdToken(): void
    {
        try {
            $this->client()->logoutUrl(
                'super-secret-id-token',
                configuration: $this->configuration(withEndSession: false),
            );
            self::fail('expected an AuthError');
        } catch (AuthError $e) {
            self::assertStringContainsString('end_session_endpoint', $e->getMessage());
            self::assertStringNotContainsString('super-secret-id-token', $e->getMessage());
        }
    }

    // ===================================================================================
    // §12.7.3 verifyLogoutToken
    // ===================================================================================

    public function testAValidLogoutTokenSurfacesSidSubAndJti(): void
    {
        $client = $this->client($this->jwksQueue());
        $token = $this->signIdToken($this->logoutClaims());

        $verified = $client->verifyLogoutToken($token, configuration: $this->configuration());

        // Not a bare bool: the RP has to know WHICH session to end, and a verifier that
        // only says "valid" forces the caller to re-parse the token themselves with none
        // of these checks.
        self::assertSame(self::LOGOUT_SID, $verified->sid);
        self::assertSame('user-1', $verified->sub);
        self::assertSame(self::LOGOUT_JTI, $verified->jti);
    }

    public function testAnIdTokenReplayedAsALogoutTokenIsRejected(): void
    {
        // The attack rules 3 and 4 exist to stop, asserted with a real, otherwise-valid
        // ID token rather than a synthetic mutation: correctly signed by a published key,
        // right issuer and audience, unexpired. Only the missing `events` and the present
        // `nonce` distinguish it.
        $client = $this->client($this->jwksQueue());
        $now = time();
        $idToken = $this->signIdToken([
            'iss' => self::BASE_URL,
            'aud' => self::CLIENT_ID,
            'sub' => 'user-1',
            'iat' => $now,
            'exp' => $now + 300,
            'nonce' => 'the-request-nonce',
        ]);

        $this->expectException(AuthError::class);
        $client->verifyLogoutToken($idToken, configuration: $this->configuration());
    }

    /**
     * Each case names the attack the check prevents.
     *
     * @return iterable<string,array{0:array<string,mixed>,1:string}>
     */
    public static function rejectionProvider(): iterable
    {
        $now = time();

        yield 'no events — without this the method just accepts a replayed ID token' => [
            ['events' => null], 'events',
        ];
        yield 'some other event — a near-miss must not pass on a technicality' => [
            ['events' => ['http://schemas.openid.net/event/other' => []]], 'events',
        ];
        yield 'nonce present — the documented ID-token-replay signature' => [
            ['nonce' => 'n-0S6_WzA2Mj'], 'nonce',
        ];
        yield 'names neither sid nor sub — identifies nothing to end' => [
            ['sid' => null, 'sub' => null], 'identifies no session',
        ];
        yield 'another RP audience — not an instruction to this client' => [
            ['aud' => 'some-other-rp'], 'audience',
        ];
        yield 'another issuer — anyone can mint a token' => [
            ['iss' => 'https://evil.example.com'], 'issuer',
        ];
        yield 'expired — a long-lived logout token is replayable' => [
            ['exp' => $now - 600, 'iat' => $now - 700], 'expired',
        ];
        yield 'stale but unexpired — a captured delivery replayed a day later' => [
            ['iat' => $now - 86400, 'exp' => $now + 600], 'too old',
        ];
        yield 'issued in the future' => [
            ['iat' => $now + 600, 'exp' => $now + 900], 'future',
        ];
        yield 'no jti — the RP cannot dedup at-least-once redeliveries' => [
            ['jti' => null], 'jti',
        ];
    }

    /** @dataProvider rejectionProvider */
    public function testRejectionCases(array $overrides, string $expectedMessage): void
    {
        $client = $this->client($this->jwksQueue());
        $token = $this->signIdToken($this->logoutClaims($overrides));

        try {
            $client->verifyLogoutToken($token, configuration: $this->configuration());
            self::fail('expected rejection: ' . $expectedMessage);
        } catch (AuthError $e) {
            self::assertStringContainsString($expectedMessage, $e->getMessage());
        }
    }

    public function testSubOnlyIsAcceptedAndSidIsPreferred(): void
    {
        $client = $this->client($this->jwksQueue());

        $subOnly = $client->verifyLogoutToken(
            $this->signIdToken($this->logoutClaims(['sid' => null])),
            configuration: $this->configuration(),
        );
        self::assertNull($subOnly->sid);
        self::assertSame('user-1', $subOnly->sub);

        // With sid present the RP must end THAT session only — falling back to "every
        // session for sub" is over-reach the server itself refuses.
        $both = $client->verifyLogoutToken(
            $this->signIdToken($this->logoutClaims()),
            configuration: $this->configuration(),
        );
        self::assertSame(self::LOGOUT_SID, $both->sid);
    }

    public function testABadSignatureIsRejectedWithoutEchoingTheToken(): void
    {
        $client = $this->client($this->jwksQueue());
        // The signature is what makes the token a statement rather than a request.
        $token = $this->signIdTokenWithBadSignature($this->logoutClaims());

        try {
            $client->verifyLogoutToken($token, configuration: $this->configuration());
            self::fail('expected a signature failure');
        } catch (AuthError $e) {
            self::assertStringNotContainsString($token, $e->getMessage());
        }
    }

    public function testVerifyingTheSameTokenTwiceDoesNotRaise(): void
    {
        // §12.7.3 rule 7. Delivery is at-least-once with retry, so a valid token
        // legitimately arrives twice — that is a retry, not an attack. An SDK that
        // dedupped internally would have no durable store and would silently drop a real
        // second logout after a restart, so jti is surfaced for the RP to dedup on and
        // never consumed here.
        $client = $this->client($this->jwksQueue());
        $token = $this->signIdToken($this->logoutClaims());

        $first = $client->verifyLogoutToken($token, configuration: $this->configuration());
        $second = $client->verifyLogoutToken($token, configuration: $this->configuration());

        self::assertEquals($first, $second);
        self::assertSame(self::LOGOUT_JTI, $first->jti);
    }
}
