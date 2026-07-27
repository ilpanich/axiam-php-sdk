<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Oidc\SsoCompleteResult;
use Axiam\Sdk\Oidc\SsoStartResult;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * `ssoStart` / `ssoComplete` (CONTRACT.md §12.1) — the upstream-IdP federation pair:
 * JSON request bodies, §5.1 tenant/org resolution, the cookie-delivered session on
 * `ssoComplete`, and the "no nonce on this path" rule (§12.1 note 7).
 */
final class OidcSsoTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT_SLUG = 'acme-tenant';

    /** @param array<int,Response> $queue */
    private function client(array $queue, ?array &$history = null, ?string $orgSlug = 'acme'): AxiamClient
    {
        $mock = new MockHandler($queue);
        $stack = HandlerStack::create($mock);
        if ($history !== null) {
            $stack->push(Middleware::history($history));
        }

        return new AxiamClient(
            self::BASE_URL,
            self::TENANT_SLUG,
            orgSlug: $orgSlug,
            oidcClientId: 'my-app',
            transportHandler: $stack,
        );
    }

    // ===================================================================================
    // ssoStart
    // ===================================================================================

    public function testSsoStartHappyPathSendsJsonBodyAndDefaultsTenantOrgFromClient(): void
    {
        $history = [];
        $client = $this->client([
            new Response(200, [], (string) json_encode([
                'authorize_url' => 'https://upstream-idp.example/authorize?...',
                'state' => 'federation-state-value',
                'expires_in_secs' => 600,
            ])),
        ], $history);

        $result = $client->ssoStart(
            federationConfigId: 'fed-config-1',
            redirectUri: 'https://app.test/sso/callback',
        );

        self::assertInstanceOf(SsoStartResult::class, $result);
        self::assertSame('https://upstream-idp.example/authorize?...', $result->authorizeUrl);
        self::assertSame('federation-state-value', $result->state);
        self::assertSame(600, $result->expiresInSecs);

        $request = $history[0]['request'];
        self::assertSame('application/json', $request->getHeaderLine('Content-Type'));
        $body = json_decode((string) $request->getBody(), true);
        self::assertSame('fed-config-1', $body['federation_config_id']);
        self::assertSame('https://app.test/sso/callback', $body['redirect_uri']);
        self::assertSame(self::TENANT_SLUG, $body['tenant_slug']);
        self::assertSame('acme', $body['org_slug']);
        self::assertArrayNotHasKey('nonce', $body, '§12.1 note 7: the federation nonce never leaves the server');
    }

    public function testSsoStartExplicitArgumentsOverrideClientDefaults(): void
    {
        $history = [];
        $client = $this->client([
            new Response(200, [], (string) json_encode([
                'authorize_url' => 'https://upstream-idp.example/authorize',
                'state' => 's',
                'expires_in_secs' => 600,
            ])),
        ], $history);

        $client->ssoStart(
            federationConfigId: 'fed-config-1',
            redirectUri: 'https://app.test/sso/callback',
            tenantId: '33333333-3333-3333-3333-333333333333',
            orgId: '44444444-4444-4444-4444-444444444444',
        );

        $body = json_decode((string) $history[0]['request']->getBody(), true);
        self::assertSame('33333333-3333-3333-3333-333333333333', $body['tenant_id']);
        self::assertSame('44444444-4444-4444-4444-444444444444', $body['org_id']);
        self::assertArrayNotHasKey('tenant_slug', $body);
        self::assertArrayNotHasKey('org_slug', $body);
    }

    public function testSsoStartWithoutOrgContextRaisesAuthErrorWithNoWireCall(): void
    {
        // No org configured anywhere -> client-side AuthError, no wire call at all
        // (an empty MockHandler queue proves it: a wire call would throw "queue empty").
        $client = $this->client([], orgSlug: null);

        $this->expectException(AuthError::class);
        $client->ssoStart(federationConfigId: 'fed-config-1', redirectUri: 'https://app.test/sso/callback');
    }

    public function testSsoStartWithNoTenantContextAtAllRaisesAuthError(): void
    {
        // AxiamClient always has a required tenant slug, so the ONLY way to force "no
        // tenant resolvable" is an explicit empty override — exercises the defensive
        // branch OidcClient::ssoStart() carries for it regardless.
        $client = $this->client([]);

        $this->expectException(AuthError::class);
        $client->ssoStart(federationConfigId: 'fed-config-1', redirectUri: 'https://app.test/sso/callback', tenantSlug: '');
    }

    public function testSsoStartMalformedResponseRaisesNetworkError(): void
    {
        $client = $this->client([new Response(200, [], (string) json_encode(['expires_in_secs' => 600]))]);

        $this->expectException(\Axiam\Sdk\Core\NetworkError::class);
        $client->ssoStart(federationConfigId: 'fed-config-1', redirectUri: 'https://app.test/sso/callback');
    }

    public function testSsoStartFederationErrorWithNoDocumentedSchemaIsPlainAuthError(): void
    {
        // Port-brief addendum item 12: the federation endpoint documents 400/401 with
        // NO response schema -- this must fall through to the generic §2 mapping
        // (401 -> AuthError), never attempt to parse an OAuth2ErrorResponse shape.
        $client = $this->client([new Response(401, [], 'unauthorized')]);

        $this->expectException(AuthError::class);
        $client->ssoStart(federationConfigId: 'fed-config-1', redirectUri: 'https://app.test/sso/callback');
    }

    public function testSsoStartFederationErrorIsPlainAuthErrorNotOAuthProtocolError(): void
    {
        $client = $this->client([new Response(401, [], (string) json_encode(['error' => 'looks_like_oauth2']))]);

        try {
            $client->ssoStart(federationConfigId: 'fed-config-1', redirectUri: 'https://app.test/sso/callback');
            self::fail('expected AuthError');
        } catch (\Axiam\Sdk\Core\OAuthProtocolError $e) {
            self::fail('ssoStart must never surface OAuthProtocolError (port-brief addendum item 12): ' . $e->getMessage());
        } catch (AuthError $e) {
            self::assertTrue(true);
        }
    }

    // ===================================================================================
    // ssoComplete
    // ===================================================================================

    public function testSsoCompleteHappyPathCapturesCookieAndCsrf(): void
    {
        $history = [];
        $client = $this->client([
            new Response(
                200,
                [
                    'Set-Cookie' => 'axiam_access=sso-session-token; Path=/',
                    'X-CSRF-Token' => 'fresh-csrf-token',
                ],
                (string) json_encode([
                    'user_id' => 'user-1',
                    'session_id' => 'session-1',
                    'expires_in' => 900,
                    'redirect_uri' => 'https://app.test/dashboard',
                ]),
            ),
        ], $history);

        $result = $client->ssoComplete('federation-state-value', 'upstream-auth-code');

        self::assertInstanceOf(SsoCompleteResult::class, $result);
        self::assertSame('user-1', $result->userId);
        self::assertSame('session-1', $result->sessionId);
        self::assertSame(900, $result->expiresIn);
        self::assertSame('https://app.test/dashboard', $result->redirectUri);

        $body = json_decode((string) $history[0]['request']->getBody(), true);
        self::assertSame('federation-state-value', $body['state']);
        self::assertSame('upstream-auth-code', $body['code']);

        // §12.1 note 6: the session arrives as Set-Cookie -> the shared cookie jar (§4)
        // now carries it, provable via a subsequent authenticated call that reads it.
        self::assertSame('sso-session-token', self::currentAccessTokenOf($client));
    }

    public function testSsoCompleteMalformedResponseRaisesNetworkError(): void
    {
        $client = $this->client([new Response(200, [], (string) json_encode(['user_id' => 'only-this']))]);

        $this->expectException(\Axiam\Sdk\Core\NetworkError::class);
        $client->ssoComplete('state', 'code');
    }

    private static function currentAccessTokenOf(AxiamClient $client): ?string
    {
        $sessionProp = new \ReflectionProperty(AxiamClient::class, 'session');
        $sessionProp->setAccessible(true);
        $session = $sessionProp->getValue($client);

        return $session->accessToken();
    }
}
