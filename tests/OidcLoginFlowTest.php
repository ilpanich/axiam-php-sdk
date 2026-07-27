<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Oidc\MemoryOidcStateStore;
use Axiam\Sdk\Oidc\OidcConfiguration;
use Axiam\Sdk\Oidc\OidcLoginFlow;
use Axiam\Sdk\Oidc\OidcLoginOutcome;
use Axiam\Sdk\Oidc\OidcStateEntry;
use Axiam\Sdk\Oidc\OidcTokenSet;
use Axiam\Sdk\Tests\Fixtures\OidcJwtFixtureTrait;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * {@see OidcLoginFlow} — the ONE begin/complete + state-store + error-mapping path the
 * Laravel and Symfony "Login with AXIAM" controllers both call (CONTRACT.md §12,
 * plan T8 item 2), mirroring the TypeScript reference's `oidcLoginCore.ts` test
 * coverage. Framework-agnostic: driven directly here with plain values, no HTTP
 * kernel of any kind involved.
 */
final class OidcLoginFlowTest extends TestCase
{
    use OidcJwtFixtureTrait;

    private const BASE_URL = 'https://api.test';
    private const CLIENT_ID = 'my-app';

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
        );
    }

    /** @param array<int,Response> $queue */
    private function client(array $queue): AxiamClient
    {
        return new AxiamClient(
            self::BASE_URL,
            'acme-tenant',
            oidcClientId: self::CLIENT_ID,
            oidcTenantId: '55555555-5555-5555-5555-555555555555',
            transportHandler: new MockHandler($queue),
        );
    }

    private function discoveryResponse(): Response
    {
        return new Response(200, [], (string) json_encode([
            'issuer' => self::BASE_URL,
            'authorization_endpoint' => self::BASE_URL . '/oauth2/authorize',
            'token_endpoint' => self::BASE_URL . '/oauth2/token',
            'userinfo_endpoint' => self::BASE_URL . '/oauth2/userinfo',
            'jwks_uri' => self::BASE_URL . '/oauth2/jwks',
            'revocation_endpoint' => self::BASE_URL . '/oauth2/revoke',
            'introspection_endpoint' => self::BASE_URL . '/oauth2/introspect',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['EdDSA'],
            'scopes_supported' => ['openid'],
            'token_endpoint_auth_methods_supported' => ['client_secret_post'],
            'claims_supported' => ['sub'],
            'grant_types_supported' => ['authorization_code'],
        ]));
    }

    // ===================================================================================
    // begin()
    // ===================================================================================

    public function testBeginRedirectsAndParksStateInTheStore(): void
    {
        $store = new MemoryOidcStateStore();
        $flow = new OidcLoginFlow($this->client([$this->discoveryResponse()]), $store, 'https://app.test/callback');

        $outcome = $flow->begin('/return/here');

        self::assertSame(OidcLoginOutcome::KIND_REDIRECT, $outcome->kind);
        self::assertStringStartsWith(self::BASE_URL . '/oauth2/authorize', (string) $outcome->redirectUrl);
        self::assertSame(1, $store->size());
    }

    public function testBeginFailsClosedWith503WhenAxiamIsUnreachable(): void
    {
        // Empty MockHandler queue: oidcDiscover() throws -> begin() must fail closed,
        // never redirect the browser somewhere half-built.
        $store = new MemoryOidcStateStore();
        $flow = new OidcLoginFlow($this->client([]), $store, 'https://app.test/callback');

        $outcome = $flow->begin();

        self::assertSame(OidcLoginOutcome::KIND_ERROR, $outcome->kind);
        self::assertSame(503, $outcome->status);
        self::assertSame('oidc_unavailable', $outcome->error);
        self::assertSame(0, $store->size(), 'nothing should be parked in the store on failure');
    }

    // ===================================================================================
    // complete()
    // ===================================================================================

    public function testCompleteIdpErrorMapsTo401AuthenticationFailed(): void
    {
        $flow = new OidcLoginFlow($this->client([]), new MemoryOidcStateStore(), 'https://app.test/callback');

        $outcome = $flow->complete(state: null, code: null, error: 'access_denied', errorDescription: 'user cancelled');

        self::assertSame(OidcLoginOutcome::KIND_ERROR, $outcome->kind);
        self::assertSame(401, $outcome->status);
        self::assertSame('authentication_failed', $outcome->error);
        self::assertStringContainsString('access_denied', (string) $outcome->message);
    }

    public function testCompleteMissingStateOrCodeMapsTo400InvalidRequest(): void
    {
        $flow = new OidcLoginFlow($this->client([]), new MemoryOidcStateStore(), 'https://app.test/callback');

        $outcome = $flow->complete(state: null, code: 'a-code');

        self::assertSame(400, $outcome->status);
        self::assertSame('invalid_request', $outcome->error);
    }

    public function testCompleteUnknownStateMapsTo401AuthenticationFailed(): void
    {
        $flow = new OidcLoginFlow($this->client([]), new MemoryOidcStateStore(), 'https://app.test/callback');

        $outcome = $flow->complete(state: 'never-issued-state', code: 'a-code');

        self::assertSame(401, $outcome->status);
        self::assertSame('authentication_failed', $outcome->error);
    }

    public function testCompleteConsumesStateSingleUse(): void
    {
        $store = new MemoryOidcStateStore();
        $store->save(new OidcStateEntry(
            state: 'state-1',
            nonce: 'nonce-1',
            codeVerifier: new \Axiam\Sdk\Core\Sensitive('verifier-1'),
            redirectUri: 'https://app.test/callback',
        ));
        $flow = new OidcLoginFlow($this->client([
            $this->discoveryResponse(),
            new Response(400, [], (string) json_encode(['error' => 'invalid_grant', 'error_description' => 'bad code'])),
        ]), $store, 'https://app.test/callback');

        $flow->complete(state: 'state-1', code: 'a-code');

        self::assertSame(0, $store->size(), 'the state must be consumed even though the exchange itself later failed');
    }

    public function testCompleteNetworkErrorMapsTo503(): void
    {
        $store = new MemoryOidcStateStore();
        $store->save(new OidcStateEntry('state-1', 'nonce-1', new \Axiam\Sdk\Core\Sensitive('verifier-1'), 'https://app.test/callback'));
        // A raw connection-refused-shaped failure (no HTTP response at all).
        $flow = new OidcLoginFlow($this->client([
            new \GuzzleHttp\Exception\ConnectException('connection refused', new \GuzzleHttp\Psr7\Request('POST', self::BASE_URL)),
        ]), $store, 'https://app.test/callback');

        $outcome = $flow->complete(state: 'state-1', code: 'a-code');

        self::assertSame(503, $outcome->status);
        self::assertSame('oidc_unavailable', $outcome->error);
    }

    public function testCompleteOAuthProtocolErrorMapsTo401(): void
    {
        $store = new MemoryOidcStateStore();
        $store->save(new OidcStateEntry('state-1', 'nonce-1', new \Axiam\Sdk\Core\Sensitive('verifier-1'), 'https://app.test/callback'));
        $flow = new OidcLoginFlow($this->client([
            $this->discoveryResponse(),
            new Response(400, [], (string) json_encode(['error' => 'invalid_grant', 'error_description' => 'code already used'])),
        ]), $store, 'https://app.test/callback');

        $outcome = $flow->complete(state: 'state-1', code: 'a-code');

        self::assertSame(401, $outcome->status);
        self::assertSame('authentication_failed', $outcome->error);
        self::assertStringContainsString('invalid_grant', (string) $outcome->message);
    }

    public function testCompleteSuccessRunsOnSuccessAndRedirectsToConfiguredSuccessRedirect(): void
    {
        $store = new MemoryOidcStateStore();
        $store->save(new OidcStateEntry('state-1', 'the-nonce', new \Axiam\Sdk\Core\Sensitive('the-verifier'), 'https://app.test/callback', '/return/here'));
        $flow = new OidcLoginFlow($this->client([
            $this->discoveryResponse(),
            new Response(200, [], (string) json_encode(['access_token' => 'a', 'token_type' => 'Bearer', 'expires_in' => 900])),
        ]), $store, 'https://app.test/callback');

        $called = false;
        $outcome = $flow->complete(
            state: 'state-1',
            code: 'a-code',
            successRedirect: '/explicit-destination',
            onSuccess: function (OidcTokenSet $tokens, OidcStateEntry $entry) use (&$called): void {
                $called = true;
                self::assertSame('a', $tokens->accessToken->reveal());
                self::assertSame('/return/here', $entry->returnTo);
            },
        );

        self::assertTrue($called, 'onSuccess must run with the validated token set and the consumed entry');
        self::assertSame(OidcLoginOutcome::KIND_REDIRECT, $outcome->kind);
        // Explicit successRedirect wins over the stored returnTo.
        self::assertSame('/explicit-destination', $outcome->redirectUrl);
    }

    public function testCompleteSuccessFallsBackToStoredReturnToWhenNoExplicitRedirect(): void
    {
        $store = new MemoryOidcStateStore();
        $store->save(new OidcStateEntry('state-1', 'nonce', new \Axiam\Sdk\Core\Sensitive('verifier'), 'https://app.test/callback', '/from-the-store'));
        $flow = new OidcLoginFlow($this->client([
            $this->discoveryResponse(),
            new Response(200, [], (string) json_encode(['access_token' => 'a', 'token_type' => 'Bearer', 'expires_in' => 900])),
        ]), $store, 'https://app.test/callback');

        $outcome = $flow->complete(state: 'state-1', code: 'a-code');

        self::assertSame(OidcLoginOutcome::KIND_REDIRECT, $outcome->kind);
        self::assertSame('/from-the-store', $outcome->redirectUrl);
    }

    public function testCompleteSuccessWithNoRedirectFallsBackToJsonSummary(): void
    {
        $nonce = 'the-nonce';
        $idToken = $this->signIdToken([
            'iss' => self::BASE_URL, 'sub' => 'user-77', 'aud' => self::CLIENT_ID,
            'exp' => time() + 900, 'iat' => time(), 'nonce' => $nonce,
        ]);
        $store = new MemoryOidcStateStore();
        $store->save(new OidcStateEntry('state-1', $nonce, new \Axiam\Sdk\Core\Sensitive('verifier'), 'https://app.test/callback'));
        $flow = new OidcLoginFlow($this->client([
            $this->discoveryResponse(),
            new Response(200, [], (string) json_encode([
                'access_token' => 'a', 'token_type' => 'Bearer', 'expires_in' => 900, 'id_token' => $idToken,
            ])),
            new Response(200, [], (string) json_encode(['jwks_uri' => self::BASE_URL . '/oauth2/jwks'])),
            new Response(200, [], (string) json_encode($this->fixtureJwks())),
        ]), $store, 'https://app.test/callback');

        $outcome = $flow->complete(state: 'state-1', code: 'a-code');

        self::assertSame(OidcLoginOutcome::KIND_JSON, $outcome->kind);
        $body = $outcome->jsonBody();
        self::assertTrue($body['authenticated']);
        self::assertSame('user-77', $body['sub']);
        self::assertSame(900, $body['expiresIn']);
    }
}
