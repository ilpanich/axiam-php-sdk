<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\OAuthProtocolError;
use Axiam\Sdk\Oidc\IntrospectionResult;
use Axiam\Sdk\Oidc\OidcConfiguration;
use Axiam\Sdk\Oidc\OidcTokenSet;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * `oidcRefresh` / `loginClientCredentials` / `introspect` / `revoke` (CONTRACT.md
 * §12.1) — grant-specific form fields, the confidential-client requirement,
 * revocation idempotency, and the §9/§12.3 rule 3 single-flight-guard boundary: a 401
 * from `/oauth2/introspect` or `/oauth2/revoke` must NEVER trigger the §9 guard.
 */
final class OidcTokenOpsTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';
    private const CLIENT_ID = 'my-app';
    private const CLIENT_SECRET = 's3cr3t';
    private const TENANT_UUID = '22222222-2222-2222-2222-222222222222';

    /** Failure message for the §12.3 rule 3 / F-14 assertions below. */
    private const NO_REFRESH_MESSAGE = 'CONTRACT.md §12.3 rule 3: a 401 from an /oauth2/* endpoint must never '
        . 'reach the §9 single-flight refresh guard — the §12 transport carries no 401→refresh interceptor, '
        . 'so this MUST stay at zero /api/v1/auth/refresh calls (conformance-review F-14)';

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
            grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
        );
    }

    /** @param array<int,Response> $queue */
    private function client(array $queue, bool $withSecret = true, ?array &$history = null): AxiamClient
    {
        $mock = new MockHandler($queue);
        $stack = HandlerStack::create($mock);
        if ($history !== null) {
            $stack->push(Middleware::history($history));
        }

        return new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            oidcClientId: self::CLIENT_ID,
            oidcClientSecret: $withSecret ? self::CLIENT_SECRET : null,
            oidcTenantId: self::TENANT_UUID,
            transportHandler: $stack,
        );
    }

    // ===================================================================================
    // oidcRefresh
    // ===================================================================================

    public function testOidcRefreshHappyPathSendsRefreshTokenGrant(): void
    {
        $history = [];
        $client = $this->client([
            new Response(200, [], (string) json_encode([
                'access_token' => 'new-access', 'token_type' => 'Bearer', 'expires_in' => 900,
            ])),
        ], history: $history);

        $tokens = $client->oidcRefresh('the-refresh-token', configuration: $this->configuration());

        self::assertInstanceOf(OidcTokenSet::class, $tokens);
        self::assertSame('new-access', $tokens->accessToken->reveal());

        $body = (string) $history[0]['request']->getBody();
        parse_str($body, $form);
        self::assertSame('refresh_token', $form['grant_type']);
        self::assertSame('the-refresh-token', $form['refresh_token']);
        self::assertSame(self::CLIENT_ID, $form['client_id']);
        self::assertSame(self::CLIENT_SECRET, $form['client_secret']);
    }

    public function testOidcRefreshOmitsClientSecretForPublicClient(): void
    {
        $history = [];
        $client = $this->client([
            new Response(200, [], (string) json_encode([
                'access_token' => 'new-access', 'token_type' => 'Bearer', 'expires_in' => 900,
            ])),
        ], withSecret: false, history: $history);

        $client->oidcRefresh('the-refresh-token', configuration: $this->configuration());

        $body = (string) $history[0]['request']->getBody();
        parse_str($body, $form);
        self::assertArrayNotHasKey('client_secret', $form);
    }

    public function testOidcRefreshWithNarrowedScope(): void
    {
        $history = [];
        $client = $this->client([
            new Response(200, [], (string) json_encode([
                'access_token' => 'new-access', 'token_type' => 'Bearer', 'expires_in' => 900,
            ])),
        ], history: $history);

        $client->oidcRefresh('the-refresh-token', scope: 'profile', configuration: $this->configuration());

        parse_str((string) $history[0]['request']->getBody(), $form);
        self::assertSame('profile', $form['scope']);
    }

    /**
     * §9/§12.1: `oidcRefresh` shares Session's single guard slot with the cookie-session
     * refresh path. If that slot is already occupied by a DIFFERENT refresh when
     * `oidcRefresh` is called, it must wait for it to settle and retry — never return a
     * stale/foreign result — succeeding once the guard frees up.
     */
    public function testOidcRefreshRetriesWhenTheGuardIsBusyWithACookieSessionRefresh(): void
    {
        $client = $this->client([
            new Response(200, [], (string) json_encode([
                'access_token' => 'new-access', 'token_type' => 'Bearer', 'expires_in' => 900,
            ])),
        ]);

        $sessionProp = new \ReflectionProperty(AxiamClient::class, 'session');
        $sessionProp->setAccessible(true);
        /** @var \Axiam\Sdk\Session $session */
        $session = $sessionProp->getValue($client);

        // Occupy the guard with a FOREIGN refresh whose underlying promise is already
        // fulfilled, but whose RefreshGuard::settle() -> then() clearing callback has
        // not yet run: per Promises/A+ (and Guzzle's own implementation), a then()
        // callback is always deferred to the next task-queue drain, never invoked
        // synchronously — so immediately after this call the guard slot is STILL
        // occupied. oidcRefresh's first attempt must observe that (ran=false), wait on
        // it (which drains the queue and frees the slot as a side effect), and retry
        // successfully rather than returning the foreign result.
        $busy = $session->refreshGuard(static fn () => \GuzzleHttp\Promise\Create::promiseFor('unrelated-cookie-session-refresh-result'));
        self::assertTrue($busy['ran'], 'the foreign refresh must itself acquire the guard first');

        $tokens = $client->oidcRefresh('the-refresh-token', configuration: $this->configuration());

        self::assertSame('new-access', $tokens->accessToken->reveal());
    }

    /**
     * §9 rule 2 / rule 5 (CONTRACT.md 1.5, F-06): if the guard is already busy with
     * ANOTHER `oidcRefresh` call (same `Session::REFRESH_KIND_OIDC` kind), a second
     * concurrent caller must NOT issue its own wire call — it must share the first
     * call's single outcome. AXIAM refresh tokens are opaque, server-stored, and
     * single-use with rotation, so a second wire call here would replay an
     * already-consumed token and fail `invalid_grant`; the mock queue is left EMPTY
     * so any such second call fails the test immediately rather than silently
     * succeeding with a foreign response.
     */
    public function testOidcRefreshSharesTheResultWhenTheGuardIsAlreadyBusyWithAnotherOidcRefresh(): void
    {
        $history = [];
        $client = $this->client([], history: $history);

        $sessionProp = new \ReflectionProperty(AxiamClient::class, 'session');
        $sessionProp->setAccessible(true);
        /** @var \Axiam\Sdk\Session $session */
        $session = $sessionProp->getValue($client);

        // Simulate a concurrent oidcRefresh already occupying the guard under the
        // SAME "oidc" kind. As in the cookie-session busy test above, the underlying
        // promise is already fulfilled but its settle()->then() clearing callback has
        // not yet run (Promises/A+ callbacks are always deferred), so the guard slot
        // is still occupied immediately after this call returns.
        $leaderWire = ['access_token' => 'leader-access', 'token_type' => 'Bearer', 'expires_in' => 900];
        $leader = $session->refreshGuard(
            static fn () => \GuzzleHttp\Promise\Create::promiseFor($leaderWire),
            kind: \Axiam\Sdk\Session::REFRESH_KIND_OIDC,
        );
        self::assertTrue($leader['ran'], 'the leader oidcRefresh must itself acquire the guard first');

        $tokens = $client->oidcRefresh('a-different-refresh-token', configuration: $this->configuration());

        self::assertSame(
            'leader-access',
            $tokens->accessToken->reveal(),
            'the follower must receive the LEADER\'s outcome, not issue its own wire call',
        );
        self::assertCount(0, $history, 'no wire call should have been made — the outcome was shared from the in-flight oidcRefresh');
    }

    public function testOidcRefreshIsDistinctFromSessionRefresh(): void
    {
        // AxiamClient::refresh() (the §1 cookie-session path) and oidcRefresh() are
        // never merged/aliased (§12.1): refresh() with no access token still raises
        // its own AuthError, independent of any oidcRefresh() configuration.
        $client = $this->client([], withSecret: false);

        $this->expectException(AuthError::class);
        $client->refresh();
    }

    // ===================================================================================
    // loginClientCredentials
    // ===================================================================================

    public function testLoginClientCredentialsHappyPath(): void
    {
        $history = [];
        $client = $this->client([
            new Response(200, [], (string) json_encode([
                'access_token' => 'svc-access', 'token_type' => 'Bearer', 'expires_in' => 3600,
            ])),
        ], history: $history);

        $tokens = $client->loginClientCredentials(configuration: $this->configuration());

        self::assertSame('svc-access', $tokens->accessToken->reveal());
        self::assertNull($tokens->idToken, 'client_credentials requests no openid scope -> no id_token');

        $body = (string) $history[0]['request']->getBody();
        parse_str($body, $form);
        self::assertSame('client_credentials', $form['grant_type']);
        self::assertSame(self::CLIENT_ID, $form['client_id']);
        self::assertSame(self::CLIENT_SECRET, $form['client_secret']);
    }

    public function testLoginClientCredentialsWithScope(): void
    {
        $history = [];
        $client = $this->client([
            new Response(200, [], (string) json_encode([
                'access_token' => 'svc-access', 'token_type' => 'Bearer', 'expires_in' => 3600,
            ])),
        ], history: $history);

        $client->loginClientCredentials(scope: 'reports:read', configuration: $this->configuration());

        parse_str((string) $history[0]['request']->getBody(), $form);
        self::assertSame('reports:read', $form['scope']);
    }

    public function testLoginClientCredentialsWithoutSecretRaisesAuthError(): void
    {
        $client = $this->client([], withSecret: false);

        $this->expectException(AuthError::class);
        $client->loginClientCredentials(configuration: $this->configuration());
    }

    public function testLoginClientCredentialsAdoptAsCredentialUsesTokenOnSubsequentSameOriginCalls(): void
    {
        $history = [];
        $client = $this->client([
            new Response(200, [], (string) json_encode([
                'access_token' => 'adopted-access', 'token_type' => 'Bearer', 'expires_in' => 3600,
            ])),
            new Response(200, [], (string) json_encode(['allowed' => true])),
        ], history: $history);

        $client->loginClientCredentials(configuration: $this->configuration(), adoptAsCredential: true);
        $client->checkAccess('read', 'resource-1');

        // The SECOND request (checkAccess, over authzHttp) carries the adopted token.
        $authzRequest = $history[1]['request'];
        self::assertSame('Bearer adopted-access', $authzRequest->getHeaderLine('Authorization'));
    }

    public function testAdoptedCredentialIsNeverSentToOauth2Endpoints(): void
    {
        $history = [];
        $client = $this->client([
            new Response(200, [], (string) json_encode([
                'access_token' => 'adopted-access', 'token_type' => 'Bearer', 'expires_in' => 3600,
            ])),
            new Response(200, [], (string) json_encode(['active' => false])),
        ], history: $history);

        $client->loginClientCredentials(configuration: $this->configuration(), adoptAsCredential: true);
        $client->introspect('some-token', configuration: $this->configuration());

        $introspectRequest = $history[1]['request'];
        self::assertSame('', $introspectRequest->getHeaderLine('Authorization'), 'CONTRACT.md §12.1 note 3: never send a bearer credential to /oauth2/*');
    }

    // ===================================================================================
    // introspect
    // ===================================================================================

    public function testIntrospectHappyPathReturnsTypedResult(): void
    {
        $history = [];
        $client = $this->client([
            new Response(200, [], (string) json_encode([
                'active' => true, 'sub' => 'user-1', 'client_id' => 'my-app', 'scope' => 'openid profile',
                'token_type' => 'Bearer', 'exp' => 4102444800, 'iat' => 1751500000,
            ])),
        ], history: $history);

        $result = $client->introspect('a-token', configuration: $this->configuration());

        self::assertInstanceOf(IntrospectionResult::class, $result);
        self::assertTrue($result->active);
        self::assertSame('user-1', $result->sub);
        self::assertSame('my-app', $result->clientId);

        $body = (string) $history[0]['request']->getBody();
        parse_str($body, $form);
        self::assertSame('a-token', $form['token']);
        self::assertSame(self::CLIENT_ID, $form['client_id']);
        self::assertSame(self::CLIENT_SECRET, $form['client_secret']);
        self::assertSame('POST', $history[0]['request']->getMethod());
        self::assertSame(self::TENANT_UUID, self::queryParam($history[0]['request']->getUri()->getQuery(), 'tenant_id'));
    }

    public function testIntrospectWithTokenTypeHint(): void
    {
        $history = [];
        $client = $this->client([new Response(200, [], (string) json_encode(['active' => true]))], history: $history);

        $client->introspect('a-token', tokenTypeHint: 'access_token', configuration: $this->configuration());

        parse_str((string) $history[0]['request']->getBody(), $form);
        self::assertSame('access_token', $form['token_type_hint']);
    }

    public function testIntrospectNonJsonResponseRaisesNetworkError(): void
    {
        $client = $this->client([new Response(200, [], 'not json')]);

        $this->expectException(\Axiam\Sdk\Core\NetworkError::class);
        $client->introspect('a-token', configuration: $this->configuration());
    }

    public function testIntrospectWithoutClientSecretRaisesAuthError(): void
    {
        $client = $this->client([], withSecret: false);

        $this->expectException(AuthError::class);
        $client->introspect('a-token', configuration: $this->configuration());
    }

    public function testIntrospectInactiveTokenReturnsActiveFalse(): void
    {
        $client = $this->client([new Response(200, [], (string) json_encode(['active' => false]))]);

        $result = $client->introspect('unknown-token', configuration: $this->configuration());

        self::assertFalse($result->active);
        self::assertNull($result->sub);
    }

    /**
     * §12.3 rule 3: 401 from /oauth2/introspect -> OAuthProtocolError, NEVER the §9
     * refresh guard.
     *
     * This is the regression test for the structural invariant named at the OIDC
     * transport seam in {@see AxiamClient} (conformance-review F-14): the rule holds
     * only because no 401→refresh interceptor sits on the transport §12 uses, and
     * nothing in the type system notices if one is added later. So the wire log is
     * asserted directly — zero `/api/v1/auth/refresh` calls — rather than left to be
     * inferred from a MockHandler "queue is empty" error.
     */
    public function test401FromIntrospectSurfacesAsOAuthProtocolErrorAndNeverEntersRefreshGuard(): void
    {
        // Only ONE response queued. If the SDK mistakenly triggered the §9 refresh
        // guard (POST /api/v1/auth/refresh) on this 401, MockHandler would throw
        // "queue is empty" on that unexpected second request instead of surfacing
        // OAuthProtocolError from the first.
        $history = [];
        $client = $this->client([
            new Response(401, [], (string) json_encode([
                'error' => 'invalid_client', 'error_description' => 'client authentication failed',
            ])),
        ], history: $history);

        try {
            $client->introspect('a-token', configuration: $this->configuration());
            self::fail('expected OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame('invalid_client: client authentication failed', $e->getMessage());
        }

        self::assertSame(0, self::refreshCalls($history), self::NO_REFRESH_MESSAGE);
    }

    // ===================================================================================
    // revoke
    // ===================================================================================

    public function testRevokeIdempotentOnUnknownToken(): void
    {
        // RFC 7009: the server answers 200 for an unknown/expired/already-revoked
        // token too -- revoke() must not raise anything for this.
        $client = $this->client([new Response(200)]);

        $client->revoke('a-token-the-server-has-never-seen', configuration: $this->configuration());
        self::assertTrue(true, 'revoke() of an unknown token must not throw');
    }

    public function testRevokeSendsFormEncodedBodyWithTenantIdQuery(): void
    {
        $history = [];
        $client = $this->client([new Response(200)], history: $history);

        $client->revoke('a-token', tokenTypeHint: 'refresh_token', configuration: $this->configuration());

        $request = $history[0]['request'];
        self::assertSame('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
        self::assertSame(self::TENANT_UUID, self::queryParam($request->getUri()->getQuery(), 'tenant_id'));
        parse_str((string) $request->getBody(), $form);
        self::assertSame('a-token', $form['token']);
        self::assertSame('refresh_token', $form['token_type_hint']);
    }

    /**
     * §12.3 rule 3: 401 from /oauth2/revoke -> OAuthProtocolError, NEVER the §9 refresh
     * guard. The introspect twin above explains why the wire log is asserted directly
     * (conformance-review F-14).
     */
    public function test401FromRevokeSurfacesAsOAuthProtocolErrorAndNeverEntersRefreshGuard(): void
    {
        $history = [];
        $client = $this->client([
            new Response(401, [], (string) json_encode([
                'error' => 'invalid_client', 'error_description' => 'bad credentials',
            ])),
        ], history: $history);

        try {
            $client->revoke('a-token', configuration: $this->configuration());
            self::fail('expected OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame('invalid_client: bad credentials', $e->getMessage());
        }

        self::assertSame(0, self::refreshCalls($history), self::NO_REFRESH_MESSAGE);
    }

    /**
     * How many `/api/v1/auth/refresh` (§9 / §1 cookie-session refresh) calls the
     * transaction log contains — see the F-14 note on the introspect test above.
     *
     * @param array<int,array{request: \Psr\Http\Message\RequestInterface}> $history
     */
    private static function refreshCalls(array $history): int
    {
        return \count(array_filter(
            $history,
            static fn (array $transaction): bool => $transaction['request']->getUri()->getPath() === '/api/v1/auth/refresh',
        ));
    }

    public function test5xxFromRevokeIsNetworkErrorNotSuccess(): void
    {
        $client = $this->client([new Response(500, [], 'boom')]);

        $this->expectException(\Axiam\Sdk\Core\NetworkError::class);
        $client->revoke('a-token', configuration: $this->configuration());
    }

    public function testRevokeWithoutClientSecretRaisesAuthError(): void
    {
        $client = $this->client([], withSecret: false);

        $this->expectException(AuthError::class);
        $client->revoke('a-token', configuration: $this->configuration());
    }

    private static function queryParam(string $query, string $name): ?string
    {
        parse_str($query, $parsed);

        return is_string($parsed[$name] ?? null) ? $parsed[$name] : null;
    }
}
