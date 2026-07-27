<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\OAuthProtocolError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Oidc\OidcConfiguration;
use Axiam\Sdk\Oidc\OidcTokenSet;
use Axiam\Sdk\Tests\Fixtures\OidcJwtFixtureTrait;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * `oidcExchange` (CONTRACT.md §12.1, `grant_type=authorization_code`) — the
 * form-encoded wire shape, the `?tenant_id=` query parameter, the happy path, and one
 * failing test per §12.4 ID-token validation rule (the contract's own hard requirement:
 * "every SDK MUST carry one failing test per requirement").
 */
final class OidcExchangeTest extends TestCase
{
    use OidcJwtFixtureTrait;

    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';
    private const CLIENT_ID = 'my-app';
    private const TENANT_UUID = '11111111-1111-1111-1111-111111111111';

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
    private function client(array $queue, ?array &$history = null): AxiamClient
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
            oidcTenantId: self::TENANT_UUID,
            transportHandler: $stack,
        );
    }

    /** @param array<string,mixed> $extra */
    private function tokenResponse(array $extra = []): Response
    {
        $body = array_merge([
            'access_token' => 'access-token-abc',
            'token_type' => 'Bearer',
            'expires_in' => 900,
        ], $extra);

        return new Response(200, [], (string) json_encode($body));
    }

    private function jwksDiscoveryResponse(): Response
    {
        return new Response(200, [], (string) json_encode(['jwks_uri' => self::BASE_URL . '/oauth2/jwks']));
    }

    private function jwksResponse(): Response
    {
        return new Response(200, [], (string) json_encode($this->fixtureJwks()));
    }

    private function validIdToken(string $nonce, ?int $now = null): string
    {
        $now ??= time();

        return $this->signIdToken([
            'iss' => self::BASE_URL,
            'sub' => 'user-0001',
            'aud' => self::CLIENT_ID,
            'exp' => $now + 900,
            'iat' => $now,
            'nonce' => $nonce,
        ]);
    }

    // --- happy path: form-encoded body + ?tenant_id= query param ----------------------

    public function testHappyPathSendsFormEncodedBodyWithTenantIdQueryParam(): void
    {
        $history = [];
        $client = $this->client([
            $this->tokenResponse(),
        ], $history);

        $tokens = $client->oidcExchange(
            code: 'auth-code-1',
            codeVerifier: 'verifier-value',
            redirectUri: 'https://app.test/callback',
            nonce: 'nonce-value',
            configuration: $this->configuration(),
        );

        self::assertInstanceOf(OidcTokenSet::class, $tokens);
        self::assertSame('access-token-abc', $tokens->accessToken->reveal());
        self::assertSame('Bearer', $tokens->tokenType);
        self::assertSame(900, $tokens->expiresIn);
        self::assertNull($tokens->idToken, 'no id_token in the response -> no id_claims either');

        self::assertCount(1, $history);
        $request = $history[0]['request'];
        self::assertSame('POST', $request->getMethod());
        self::assertSame('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
        self::assertSame(self::TENANT_UUID, self::parseQueryParam($request->getUri()->getQuery(), 'tenant_id'));

        $body = (string) $request->getBody();
        parse_str($body, $form);
        self::assertSame('authorization_code', $form['grant_type']);
        self::assertSame('auth-code-1', $form['code']);
        self::assertSame('verifier-value', $form['code_verifier']);
        self::assertSame('https://app.test/callback', $form['redirect_uri']);
        self::assertSame(self::CLIENT_ID, $form['client_id']);
        self::assertArrayNotHasKey('client_secret', $form, 'no client_secret configured -> omitted, never sent empty');
    }

    private static function parseQueryParam(string $query, string $name): ?string
    {
        parse_str($query, $parsed);

        return is_string($parsed[$name] ?? null) ? $parsed[$name] : null;
    }

    public function testCodeVerifierAcceptsSensitiveWrapperOrBareString(): void
    {
        $client = $this->client([$this->tokenResponse()]);

        $tokens = $client->oidcExchange(
            code: 'code',
            codeVerifier: new Sensitive('wrapped-verifier'),
            redirectUri: 'https://app.test/callback',
            nonce: 'nonce',
            configuration: $this->configuration(),
        );

        self::assertSame('access-token-abc', $tokens->accessToken->reveal());
    }

    public function testMissingTenantIdRaisesAuthErrorWithNoWireCall(): void
    {
        // Empty MockHandler queue: if a wire call were attempted, MockHandler would
        // throw "queue is empty" instead of AuthError -- proving no network I/O happens.
        $client = new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            oidcClientId: self::CLIENT_ID,
            transportHandler: new MockHandler([]),
        );

        $this->expectException(AuthError::class);
        $client->oidcExchange(
            code: 'code',
            codeVerifier: 'verifier',
            redirectUri: 'https://app.test/callback',
            nonce: 'nonce',
            configuration: $this->configuration(),
        );
    }

    public function testSlugTenantIdIsRejectedAsQueryParameter(): void
    {
        $client = new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            oidcClientId: self::CLIENT_ID,
            transportHandler: new MockHandler([]),
        );

        $this->expectException(AuthError::class);
        $client->oidcExchange(
            code: 'code',
            codeVerifier: 'verifier',
            redirectUri: 'https://app.test/callback',
            nonce: 'nonce',
            tenantId: 'not-a-uuid',
            configuration: $this->configuration(),
        );
    }

    public function testAuthorizationEndpointWithExistingQueryPortAndFragmentIsPreserved(): void
    {
        // Exercises OidcClient::withQuery()'s "existing query string" / explicit port /
        // fragment branches — the token endpoint below already carries all three.
        $configuration = new OidcConfiguration(
            issuer: self::BASE_URL,
            authorization_endpoint: self::BASE_URL . '/oauth2/authorize',
            token_endpoint: 'https://api.test:8443/oauth2/token?debug=1#frag',
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
        $history = [];
        $client = $this->client([$this->tokenResponse()], $history);

        $client->oidcExchange(code: 'c', codeVerifier: 'v', redirectUri: 'https://app.test/cb', nonce: 'n', configuration: $configuration);

        $uri = (string) $history[0]['request']->getUri();
        self::assertStringContainsString(':8443', $uri);
        self::assertStringContainsString('debug=1', $uri);
        self::assertStringContainsString('tenant_id=' . self::TENANT_UUID, $uri);
    }

    public function testNonJsonTokenResponseBodyRaisesNetworkError(): void
    {
        $client = $this->client([new Response(200, [], 'not json at all')]);

        $this->expectException(\Axiam\Sdk\Core\NetworkError::class);
        $client->oidcExchange(code: 'c', codeVerifier: 'v', redirectUri: 'https://app.test/cb', nonce: 'n', configuration: $this->configuration());
    }

    public function testTokenResponseMissingRequiredFieldsRaisesNetworkError(): void
    {
        $client = $this->client([new Response(200, [], (string) json_encode(['scope' => 'openid']))]);

        $this->expectException(\Axiam\Sdk\Core\NetworkError::class);
        $client->oidcExchange(code: 'c', codeVerifier: 'v', redirectUri: 'https://app.test/cb', nonce: 'n', configuration: $this->configuration());
    }

    // --- OAuth2ErrorResponse -> OAuthProtocolError -------------------------------------

    public function testOAuth2ErrorResponseSurfacesAsOAuthProtocolErrorWithExactMessage(): void
    {
        $client = $this->client([
            new Response(400, [], (string) json_encode([
                'error' => 'invalid_grant',
                'error_description' => 'the authorization code has expired',
            ])),
        ]);

        try {
            $client->oidcExchange(
                code: 'stale-code',
                codeVerifier: 'verifier',
                redirectUri: 'https://app.test/callback',
                nonce: 'nonce',
                configuration: $this->configuration(),
            );
            self::fail('expected OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame('invalid_grant', $e->error);
            self::assertSame('the authorization code has expired', $e->errorDescription);
            self::assertSame('invalid_grant: the authorization code has expired', $e->getMessage());
            // Backward compatibility (contract 1.4, addendum item 17): an
            // OAuthProtocolError IS an AuthError, so existing catch(AuthError) blocks
            // still see it.
            self::assertInstanceOf(AuthError::class, $e);
        }
    }

    // --- happy path with a valid id_token (§12.4 all seven rules pass) ----------------

    public function testHappyPathWithValidIdTokenPopulatesIdClaims(): void
    {
        $nonce = 'the-request-nonce';
        $client = $this->client([
            $this->tokenResponse(['id_token' => $this->validIdToken($nonce)]),
            $this->jwksDiscoveryResponse(),
            $this->jwksResponse(),
        ]);

        $tokens = $client->oidcExchange(
            code: 'code',
            codeVerifier: 'verifier',
            redirectUri: 'https://app.test/callback',
            nonce: $nonce,
            configuration: $this->configuration(),
        );

        self::assertNotNull($tokens->idToken);
        self::assertIsArray($tokens->idClaims);
        self::assertSame('user-0001', $tokens->idClaims['sub']);
        self::assertSame(self::BASE_URL, $tokens->idClaims['iss']);
    }

    // --- §12.4 rule 1: invalid_alg (alg: none AND alg: RS256) --------------------------

    public function testInvalidAlgNoneIsRejected(): void
    {
        $nonce = 'n1';
        $badToken = $this->tokenWithHeader(['alg' => 'none'], [
            'iss' => self::BASE_URL, 'sub' => 's', 'aud' => self::CLIENT_ID,
            'exp' => time() + 900, 'iat' => time(), 'nonce' => $nonce,
        ]);
        // No JWKS fetch expected: alg is checked BEFORE any key lookup.
        $client = $this->client([$this->tokenResponse(['id_token' => $badToken])]);

        try {
            $client->oidcExchange(code: 'c', codeVerifier: 'v', redirectUri: 'https://app.test/cb', nonce: $nonce, configuration: $this->configuration());
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertSame('invalid_alg', $e->getReason());
        }
    }

    public function testInvalidAlgRs256IsRejected(): void
    {
        $nonce = 'n2';
        $badToken = $this->tokenWithHeader(['alg' => 'RS256'], [
            'iss' => self::BASE_URL, 'sub' => 's', 'aud' => self::CLIENT_ID,
            'exp' => time() + 900, 'iat' => time(), 'nonce' => $nonce,
        ]);
        $client = $this->client([$this->tokenResponse(['id_token' => $badToken])]);

        try {
            $client->oidcExchange(code: 'c', codeVerifier: 'v', redirectUri: 'https://app.test/cb', nonce: $nonce, configuration: $this->configuration());
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertSame('invalid_alg', $e->getReason());
        }
    }

    // --- §12.4 rule 2: unknown_kid (single re-fetch, then fail) ------------------------

    public function testUnknownKidTriggersOneRefetchThenFails(): void
    {
        $nonce = 'n3';
        $badToken = $this->tokenWithHeader(['kid' => 'totally-unknown-kid'], [
            'iss' => self::BASE_URL, 'sub' => 's', 'aud' => self::CLIENT_ID,
            'exp' => time() + 900, 'iat' => time(), 'nonce' => $nonce,
        ]);
        $history = [];
        // Exactly 3 responses: token + 1 discovery + 1 jwks. If a SECOND refetch were
        // attempted, MockHandler would throw "queue is empty" instead of AuthError.
        $client = $this->client([
            $this->tokenResponse(['id_token' => $badToken]),
            $this->jwksDiscoveryResponse(),
            $this->jwksResponse(),
        ], $history);

        try {
            $client->oidcExchange(code: 'c', codeVerifier: 'v', redirectUri: 'https://app.test/cb', nonce: $nonce, configuration: $this->configuration());
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertSame('unknown_kid', $e->getReason());
        }
        self::assertCount(3, $history, 'expected exactly one JWKS re-fetch (token + discovery + jwks)');
    }

    public function testNoKidHeaderAtAllIsUnknownKid(): void
    {
        // Port-brief addendum item 12: "no kid header at all" is unknown_kid too.
        $nonce = 'n4';
        $headerNoKid = ['typ' => 'JWT', 'alg' => 'EdDSA'];
        $payload = ['iss' => self::BASE_URL, 'sub' => 's', 'aud' => self::CLIENT_ID, 'exp' => time() + 900, 'iat' => time(), 'nonce' => $nonce];
        $badToken = rtrim(strtr(base64_encode((string) json_encode($headerNoKid)), '+/', '-_'), '=')
            . '.' . rtrim(strtr(base64_encode((string) json_encode($payload)), '+/', '-_'), '=')
            . '.sig';
        $client = $this->client([$this->tokenResponse(['id_token' => $badToken])]);

        try {
            $client->oidcExchange(code: 'c', codeVerifier: 'v', redirectUri: 'https://app.test/cb', nonce: $nonce, configuration: $this->configuration());
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertSame('unknown_kid', $e->getReason());
        }
    }

    // --- §12.4 rule 2: invalid_signature ------------------------------------------------

    public function testInvalidSignatureIsRejected(): void
    {
        $nonce = 'n5';
        $badToken = $this->signIdTokenWithBadSignature([
            'iss' => self::BASE_URL, 'sub' => 's', 'aud' => self::CLIENT_ID,
            'exp' => time() + 900, 'iat' => time(), 'nonce' => $nonce,
        ]);
        $client = $this->client([
            $this->tokenResponse(['id_token' => $badToken]),
            $this->jwksDiscoveryResponse(),
            $this->jwksResponse(),
        ]);

        try {
            $client->oidcExchange(code: 'c', codeVerifier: 'v', redirectUri: 'https://app.test/cb', nonce: $nonce, configuration: $this->configuration());
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertSame('invalid_signature', $e->getReason());
        }
    }

    // --- §12.4 rule 3: invalid_issuer ---------------------------------------------------

    public function testInvalidIssuerIsRejected(): void
    {
        $nonce = 'n6';
        $badToken = $this->signIdToken([
            'iss' => 'https://not-the-right-issuer.example', 'sub' => 's', 'aud' => self::CLIENT_ID,
            'exp' => time() + 900, 'iat' => time(), 'nonce' => $nonce,
        ]);
        $client = $this->client([
            $this->tokenResponse(['id_token' => $badToken]),
            $this->jwksDiscoveryResponse(),
            $this->jwksResponse(),
        ]);

        try {
            $client->oidcExchange(code: 'c', codeVerifier: 'v', redirectUri: 'https://app.test/cb', nonce: $nonce, configuration: $this->configuration());
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertSame('invalid_issuer', $e->getReason());
        }
    }

    // --- §12.4 rule 4: invalid_audience --------------------------------------------------

    public function testInvalidAudienceIsRejected(): void
    {
        $nonce = 'n7';
        $badToken = $this->signIdToken([
            'iss' => self::BASE_URL, 'sub' => 's', 'aud' => 'some-other-client',
            'exp' => time() + 900, 'iat' => time(), 'nonce' => $nonce,
        ]);
        $client = $this->client([
            $this->tokenResponse(['id_token' => $badToken]),
            $this->jwksDiscoveryResponse(),
            $this->jwksResponse(),
        ]);

        try {
            $client->oidcExchange(code: 'c', codeVerifier: 'v', redirectUri: 'https://app.test/cb', nonce: $nonce, configuration: $this->configuration());
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertSame('invalid_audience', $e->getReason());
        }
    }

    public function testMultipleAudienceWithoutMatchingAzpIsInvalidAudience(): void
    {
        $nonce = 'n7b';
        $badToken = $this->signIdToken([
            'iss' => self::BASE_URL, 'sub' => 's', 'aud' => [self::CLIENT_ID, 'another-aud'],
            'exp' => time() + 900, 'iat' => time(), 'nonce' => $nonce,
            // no azp claim
        ]);
        $client = $this->client([
            $this->tokenResponse(['id_token' => $badToken]),
            $this->jwksDiscoveryResponse(),
            $this->jwksResponse(),
        ]);

        try {
            $client->oidcExchange(code: 'c', codeVerifier: 'v', redirectUri: 'https://app.test/cb', nonce: $nonce, configuration: $this->configuration());
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertSame('invalid_audience', $e->getReason());
        }
    }

    // --- §12.4 rule 5: token_expired -----------------------------------------------------

    public function testExpiredTokenIsRejected(): void
    {
        $nonce = 'n8';
        $badToken = $this->signIdToken([
            'iss' => self::BASE_URL, 'sub' => 's', 'aud' => self::CLIENT_ID,
            'exp' => time() - 3600, 'iat' => time() - 4000, 'nonce' => $nonce,
        ]);
        $client = $this->client([
            $this->tokenResponse(['id_token' => $badToken]),
            $this->jwksDiscoveryResponse(),
            $this->jwksResponse(),
        ]);

        try {
            $client->oidcExchange(code: 'c', codeVerifier: 'v', redirectUri: 'https://app.test/cb', nonce: $nonce, configuration: $this->configuration());
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertSame('token_expired', $e->getReason());
        }
    }

    // --- §12.4 rule 6: nonce_mismatch -----------------------------------------------------

    public function testNonceMismatchIsRejected(): void
    {
        $badToken = $this->signIdToken([
            'iss' => self::BASE_URL, 'sub' => 's', 'aud' => self::CLIENT_ID,
            'exp' => time() + 900, 'iat' => time(), 'nonce' => 'a-different-nonce',
        ]);
        $client = $this->client([
            $this->tokenResponse(['id_token' => $badToken]),
            $this->jwksDiscoveryResponse(),
            $this->jwksResponse(),
        ]);

        try {
            $client->oidcExchange(code: 'c', codeVerifier: 'v', redirectUri: 'https://app.test/cb', nonce: 'the-expected-nonce', configuration: $this->configuration());
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertSame('nonce_mismatch', $e->getReason());
        }
    }

    // --- §12.4 rule 7: all-or-nothing — failure discards the WHOLE token set ------------

    public function testFailedIdTokenValidationNeverExposesAccessOrRefreshToken(): void
    {
        $badToken = $this->signIdToken([
            'iss' => self::BASE_URL, 'sub' => 's', 'aud' => self::CLIENT_ID,
            'exp' => time() - 3600, 'iat' => time() - 4000, 'nonce' => 'nonce',
        ]);
        $client = $this->client([
            $this->tokenResponse(['id_token' => $badToken, 'refresh_token' => 'super-secret-refresh']),
            $this->jwksDiscoveryResponse(),
            $this->jwksResponse(),
        ]);

        try {
            $tokens = $client->oidcExchange(code: 'c', codeVerifier: 'v', redirectUri: 'https://app.test/cb', nonce: 'nonce', configuration: $this->configuration());
            self::fail('expected AuthError, got a token set: ' . $tokens->accessToken->reveal());
        } catch (AuthError $e) {
            self::assertSame('token_expired', $e->getReason());
            self::assertStringNotContainsString('access-token-abc', $e->getMessage());
            self::assertStringNotContainsString('super-secret-refresh', $e->getMessage());
        }
    }
}
