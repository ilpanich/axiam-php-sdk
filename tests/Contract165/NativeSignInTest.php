<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract165;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\OAuthProtocolError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Oidc\OidcClient;
use Axiam\Sdk\Oidc\OidcConfiguration;
use Axiam\Sdk\Oidc\ProviderNonce;
use Axiam\Sdk\Tests\Fixtures\OidcJwtFixtureTrait;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Psr\Log\AbstractLogger;

/**
 * CONTRACT.md §37.9 — native sign-in with a provider ID token (contract 1.65). One test per
 * entry of the contract's list, under the contract's names, so the eleven SDKs' suites can be
 * compared. Every test runs against a mocked transport that records the requests it is asked for.
 */
final class NativeSignInTest extends TestCase
{
    use OidcJwtFixtureTrait;

    private const BASE_URL = 'https://api.test';
    private const TENANT_UUID = '22222222-2222-2222-2222-222222222222';
    private const CLIENT_ID = 'mobile-app';
    private const CLIENT_SECRET = 'relay-client-secret';
    private const PROVIDER_UUID = '9b2f1c0e-7d4a-4c1b-8e55-0a1b2c3d4e5f';

    /** The §37.4 fixed vector: SHA-256 of the ASCII string, lower-case hex. */
    private const VECTOR_RAW = 'n-0S6_WzA2Mj';
    private const VECTOR_HASH = '0823a09b54cb9381561068b00aaf4e539b3f54604631d3e6a820879b6b04cc19';

    private const TOKEN_FAILURE_MESSAGE = 'the provider ID token is not acceptable';

    /** @var list<RequestInterface> */
    private array $sent = [];

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
            grant_types_supported: [OidcClient::PROVIDER_ID_TOKEN_GRANT_TYPE],
        );
    }

    /**
     * @param array<int,Response|\Throwable> $queue
     */
    private function client(
        array $queue,
        ?string $clientSecret = null,
        ?string $oidcTenantId = self::TENANT_UUID,
        ?AbstractLogger $logger = null,
        ?callable $telemetry = null,
    ): AxiamClient {
        $this->sent = [];
        $mock = new MockHandler($queue);
        $captured = &$this->sent;
        $handler = static function (RequestInterface $request, array $options) use ($mock, &$captured) {
            $captured[] = $request;

            return $mock($request, $options);
        };

        return new AxiamClient(
            self::BASE_URL,
            'acme-tenant',
            oidcClientId: self::CLIENT_ID,
            oidcClientSecret: $clientSecret,
            oidcTenantId: $oidcTenantId,
            logger: $logger,
            transportHandler: $handler,
            telemetryHook: $telemetry,
        );
    }

    /** @param array<string,mixed> $extra */
    private static function tokens(array $extra = []): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], (string) json_encode(array_merge([
            'access_token' => 'native-access-token',
            'token_type' => 'Bearer',
            'expires_in' => 900,
        ], $extra)));
    }

    private static function oauthError(string $error, int $status = 400, string $description = '', array $headers = []): Response
    {
        return new Response(
            $status,
            array_merge(['Content-Type' => 'application/json'], $headers),
            (string) json_encode(['error' => $error, 'error_description' => $description]),
        );
    }

    /** @return array<string,string> the parsed form body of request `$i` */
    private function form(int $i = 0): array
    {
        parse_str((string) $this->sent[$i]->getBody(), $form);

        /** @var array<string,string> $form */
        return $form;
    }

    // ===================================================================================
    // 1. request_body_exact
    // ===================================================================================

    public function testRequestBodyExact(): void
    {
        $client = $this->client([self::tokens(), self::tokens()]);

        $client->loginWithProviderIdToken(
            self::PROVIDER_UUID,
            'provider.id.token',
            self::VECTOR_RAW,
            scopes: ['openid', 'profile'],
            resource: 'https://api.example.com/orders',
            configuration: $this->configuration(),
        );

        self::assertCount(1, $this->sent);
        $request = $this->sent[0];
        self::assertSame('POST', $request->getMethod());
        self::assertSame('/oauth2/token', $request->getUri()->getPath());
        parse_str($request->getUri()->getQuery(), $query);
        self::assertSame(['tenant_id' => self::TENANT_UUID], $query, 'tenant_id is the one query parameter');
        self::assertStringStartsWith('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
        foreach (['Authorization', 'Cookie', 'X-CSRF-Token'] as $header) {
            self::assertFalse($request->hasHeader($header), $header . ' must not be sent to /oauth2/token');
        }

        $form = $this->form();
        $keys = array_keys($form);
        sort($keys);
        self::assertSame(
            ['client_id', 'grant_type', 'id_token', 'nonce', 'provider', 'resource', 'scope'],
            $keys,
            'the full key set, and nothing else — tenant_id is not a body field',
        );
        self::assertSame('urn:axiam:params:oauth:grant-type:provider-id-token', $form['grant_type']);
        self::assertSame(self::CLIENT_ID, $form['client_id']);
        self::assertSame(self::PROVIDER_UUID, $form['provider']);
        self::assertSame('provider.id.token', $form['id_token']);
        self::assertSame('openid profile', $form['scope'], 'scope is the space-joined list');
        self::assertSame('https://api.example.com/orders', $form['resource']);

        // The same call with no scopes and no resource sends neither key, and does not add `openid`.
        $client->loginWithProviderIdToken(
            self::PROVIDER_UUID,
            'provider.id.token',
            self::VECTOR_RAW,
            configuration: $this->configuration(),
        );
        $bare = array_keys($this->form(1));
        sort($bare);
        self::assertSame(['client_id', 'grant_type', 'id_token', 'nonce', 'provider'], $bare);
        self::assertStringNotContainsString('openid', (string) $this->sent[1]->getBody());

        // An empty scopes list is "none", not an empty `scope=`.
        $client = $this->client([self::tokens()]);
        $client->loginWithProviderIdToken('slug', 't', 'n', scopes: [], configuration: $this->configuration());
        self::assertArrayNotHasKey('scope', $this->form());
    }

    // ===================================================================================
    // 2. raw_nonce_sent_not_hash
    // ===================================================================================

    public function testRawNonceSentNotHash(): void
    {
        // A fixture token whose payload carries the HASH, as the provider's token does.
        $providerToken = $this->signIdToken([
            'iss' => 'https://accounts.google.example',
            'sub' => 'g-1',
            'aud' => 'mobile-app',
            'exp' => time() + 300,
            'iat' => time(),
            'nonce' => self::VECTOR_HASH,
        ]);
        $client = $this->client([self::tokens()]);

        $client->loginWithProviderIdToken(
            self::PROVIDER_UUID,
            $providerToken,
            self::VECTOR_RAW,
            configuration: $this->configuration(),
        );

        $form = $this->form();
        self::assertSame(self::VECTOR_RAW, $form['nonce'], 'the raw nonce, byte for byte');
        $body = (string) $this->sent[0]->getBody();
        self::assertStringNotContainsString(self::VECTOR_HASH, $body, 'the hash of the nonce is never sent');
        // The token itself is in the body (it is the id_token field); the nonce field must not be its claim.
        self::assertNotSame(self::VECTOR_HASH, $form['nonce']);
        self::assertSame(1, substr_count($body, 'nonce='), 'a single nonce field: no second one read from the token');

        // A wrapped nonce is the same value on the wire.
        $client = $this->client([self::tokens()]);
        $client->loginWithProviderIdToken(
            self::PROVIDER_UUID,
            new Sensitive($providerToken),
            new Sensitive(self::VECTOR_RAW),
            configuration: $this->configuration(),
        );
        self::assertSame(self::VECTOR_RAW, $this->form()['nonce']);
        self::assertSame($providerToken, $this->form()['id_token']);
    }

    // ===================================================================================
    // 3. provider_sent_verbatim
    // ===================================================================================

    public function testProviderSentVerbatim(): void
    {
        $client = $this->client([self::tokens(), self::tokens(), self::tokens()]);

        foreach ([self::PROVIDER_UUID, 'Corp-Okta', 'google'] as $provider) {
            $client->loginWithProviderIdToken($provider, 't', 'n', configuration: $this->configuration());
        }

        self::assertCount(3, $this->sent, 'one request per call: no sso_providers lookup, no discovery fetch');
        self::assertSame(self::PROVIDER_UUID, $this->form(0)['provider']);
        self::assertSame('Corp-Okta', $this->form(1)['provider'], 'mixed case is not folded');
        self::assertSame('google', $this->form(2)['provider'], 'a kind name is sent as given, not translated');
        foreach ($this->sent as $request) {
            self::assertSame('/oauth2/token', $request->getUri()->getPath());
        }
    }

    // ===================================================================================
    // 4. public_client_sends_client_id_only / confidential_client_sends_its_credential
    // ===================================================================================

    public function testPublicClientSendsClientIdOnly(): void
    {
        $client = $this->client([self::tokens()], clientSecret: null);

        $client->loginWithProviderIdToken('slug', 't', 'n', configuration: $this->configuration());

        $form = $this->form();
        self::assertSame(self::CLIENT_ID, $form['client_id']);
        foreach (['client_secret', 'client_assertion', 'client_assertion_type'] as $credential) {
            self::assertArrayNotHasKey($credential, $form);
        }
        self::assertFalse($this->sent[0]->hasHeader('Authorization'));
    }

    public function testConfidentialClientSendsItsCredential(): void
    {
        $client = $this->client([self::tokens()], clientSecret: self::CLIENT_SECRET);

        // The mock's discovery document may name either method; both are the body field.
        foreach (['client_secret_post', 'client_secret_basic'] as $method) {
            $configuration = $this->configuration();
            $configuration = new OidcConfiguration(
                issuer: $configuration->issuer,
                authorization_endpoint: $configuration->authorization_endpoint,
                token_endpoint: $configuration->token_endpoint,
                userinfo_endpoint: $configuration->userinfo_endpoint,
                jwks_uri: $configuration->jwks_uri,
                revocation_endpoint: $configuration->revocation_endpoint,
                introspection_endpoint: $configuration->introspection_endpoint,
                response_types_supported: $configuration->response_types_supported,
                subject_types_supported: $configuration->subject_types_supported,
                id_token_signing_alg_values_supported: $configuration->id_token_signing_alg_values_supported,
                scopes_supported: $configuration->scopes_supported,
                token_endpoint_auth_methods_supported: [$method],
                claims_supported: $configuration->claims_supported,
                grant_types_supported: $configuration->grant_types_supported,
            );
            $client = $this->client([self::tokens()], clientSecret: self::CLIENT_SECRET);
            $client->loginWithProviderIdToken('slug', 't', 'n', configuration: $configuration);

            self::assertSame(self::CLIENT_SECRET, $this->form()['client_secret'], $method);
            self::assertFalse($this->sent[0]->hasHeader('Authorization'), $method . ': never a Basic header');
        }
    }

    // ===================================================================================
    // 5. empty_inputs_refused_locally
    // ===================================================================================

    /** @return iterable<string,array{string,string,string}> */
    public static function emptyInputs(): iterable
    {
        yield 'empty provider' => ['', 'token', 'nonce'];
        yield 'empty id_token' => ['slug', '', 'nonce'];
        yield 'empty nonce' => ['slug', 'token', ''];
    }

    /** @dataProvider emptyInputs */
    public function testEmptyInputsRefusedLocally(string $provider, string $idToken, string $nonce): void
    {
        $client = $this->client([]);

        try {
            // No configuration passed: a discovery fetch would be a request too.
            $client->loginWithProviderIdToken($provider, $idToken, $nonce);
            self::fail('expected a client-side refusal');
        } catch (AuthError $e) {
            self::assertStringContainsString('§37.2 rule 4', $e->getMessage());
        }
        self::assertCount(0, $this->sent, 'zero requests, discovery included');
    }

    public function testEmptyWrappedInputsAreRefusedToo(): void
    {
        $client = $this->client([]);

        foreach ([[new Sensitive(''), 'n'], ['t', new Sensitive('')]] as [$idToken, $nonce]) {
            try {
                $client->loginWithProviderIdToken('slug', $idToken, $nonce);
                self::fail('expected a client-side refusal');
            } catch (AuthError) {
                // expected
            }
        }
        self::assertCount(0, $this->sent);
    }

    public function testASlugOnlyClientIsRefusedLocallyWithNoRequest(): void
    {
        $client = $this->client([], oidcTenantId: null);

        try {
            $client->loginWithProviderIdToken('slug', 't', 'n');
            self::fail('expected the §12.3 rule 4 refusal');
        } catch (AuthError $e) {
            self::assertStringContainsString('§12.3 rule 4', $e->getMessage());
        }
        self::assertCount(0, $this->sent, 'no wire call — not even the discovery fetch');
    }

    public function testANonceOverTheServersBoundIsRefusedLocally(): void
    {
        $client = $this->client([self::tokens()]);

        try {
            $client->loginWithProviderIdToken('slug', 't', str_repeat('a', 513), configuration: $this->configuration());
            self::fail('expected a client-side refusal');
        } catch (AuthError) {
            self::assertCount(0, $this->sent);
        }

        // 512 bytes is the bound, inclusive.
        $client->loginWithProviderIdToken('slug', 't', str_repeat('a', 512), configuration: $this->configuration());
        self::assertCount(1, $this->sent);
    }

    // ===================================================================================
    // 6. generic_invalid_grant_mapped
    // ===================================================================================

    public function testGenericInvalidGrantMapped(): void
    {
        $client = $this->client([
            self::oauthError('invalid_grant', 400, self::TOKEN_FAILURE_MESSAGE),
            // A second response that a retrying implementation would consume.
            self::tokens(),
        ]);

        try {
            $client->loginWithProviderIdToken('slug', 'id.token.value', 'raw-nonce-value', configuration: $this->configuration());
            self::fail('expected OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame('invalid_grant', $e->error);
            self::assertSame(self::TOKEN_FAILURE_MESSAGE, $e->errorDescription);
            self::assertSame('invalid_grant: the provider ID token is not acceptable', $e->getMessage());
        }

        self::assertCount(1, $this->sent, 'exactly one request: no retry, no regenerated nonce');
        // The §9 guard is not entered and no refresh token exists to spend: nothing but the one POST.
        foreach ($this->sent as $request) {
            self::assertSame('/oauth2/token', $request->getUri()->getPath());
        }
    }

    // ===================================================================================
    // 7. consent_required_mapped
    // ===================================================================================

    public function testConsentRequiredMapped(): void
    {
        $client = $this->client([self::oauthError('consent_required', 400, 'consent is required'), self::tokens()]);

        try {
            $client->loginWithProviderIdToken('slug', 't', 'n', scopes: ['address'], configuration: $this->configuration());
            self::fail('expected OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame('consent_required', $e->error);
        }

        self::assertCount(1, $this->sent, 'one request; no browser flow, no other grant');
        self::assertSame(OidcClient::PROVIDER_ID_TOKEN_GRANT_TYPE, $this->form()['grant_type']);
    }

    // ===================================================================================
    // 8. client_and_scope_refusals_surfaced
    // ===================================================================================

    /** @return iterable<string,array{int,string,array<string,string>}> */
    public static function clientAndScopeRefusals(): iterable
    {
        yield 'unauthorized_client' => [400, 'unauthorized_client', []];
        yield 'invalid_client' => [401, 'invalid_client', ['WWW-Authenticate' => 'Basic realm="axiam"']];
        yield 'invalid_scope' => [400, 'invalid_scope', []];
        yield 'invalid_target' => [400, 'invalid_target', []];
    }

    /**
     * @dataProvider clientAndScopeRefusals
     *
     * @param array<string,string> $headers
     */
    public function testClientAndScopeRefusalsSurfaced(int $status, string $error, array $headers): void
    {
        $client = $this->client([self::oauthError($error, $status, $error . ' text', $headers), self::tokens()]);

        try {
            $client->loginWithProviderIdToken('slug', 't', 'n', scopes: ['openid', 'phone'], configuration: $this->configuration());
            self::fail('expected OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame($error, $e->error);
            self::assertSame($status, $e->httpStatus);
        }

        self::assertCount(1, $this->sent, 'one request each');
        self::assertSame('openid phone', $this->form()['scope'], 'not narrowed and re-sent');
        self::assertSame('/oauth2/token', $this->sent[0]->getUri()->getPath(), 'a 401 does not enter the §9 refresh guard');
    }

    // ===================================================================================
    // 9. rate_limit_with_retry_after_mapped
    // ===================================================================================

    public function testRateLimitWithRetryAfterMapped(): void
    {
        $client = $this->client([self::oauthError('rate_limit_exceeded', 429, 'slow down', ['Retry-After' => '7']), self::tokens()]);

        try {
            $client->loginWithProviderIdToken('slug', 't', 'n', configuration: $this->configuration());
            self::fail('expected OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame('rate_limit_exceeded', $e->error);
            self::assertSame(7000.0, $e->retryAfterMs, 'Retry-After: 7 is exposed (milliseconds)');
            self::assertSame(429, $e->httpStatus);
        }

        self::assertCount(1, $this->sent, 'exactly one request; the SDK does not wait and try again');
    }

    // ===================================================================================
    // 10. server_error_not_retried
    // ===================================================================================

    public function testServerErrorNotRetried(): void
    {
        // A 500 with a well-formed body is dispatched on the body.
        $client = $this->client([self::oauthError('server_error', 500, 'datastore unavailable'), self::tokens()]);
        try {
            $client->loginWithProviderIdToken('slug', 't', 'n', configuration: $this->configuration());
            self::fail('expected OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame('server_error', $e->error);
        }
        self::assertCount(1, $this->sent);

        // A 500 with no body is a NetworkError.
        $client = $this->client([new Response(500), self::tokens()]);
        try {
            $client->loginWithProviderIdToken('slug', 't', 'n', configuration: $this->configuration());
            self::fail('expected NetworkError');
        } catch (NetworkError $e) {
            self::assertNotInstanceOf(OAuthProtocolError::class, $e);
        }
        self::assertCount(1, $this->sent);

        // A transport failure after the request was sent is a NetworkError, still one request.
        $client = $this->client([
            new ConnectException('connection reset by peer', new Request('POST', self::BASE_URL . '/oauth2/token')),
            self::tokens(),
        ]);
        try {
            $client->loginWithProviderIdToken('slug', 't', 'n', configuration: $this->configuration());
            self::fail('expected NetworkError');
        } catch (NetworkError) {
            // expected
        }
        self::assertCount(1, $this->sent);
    }

    // ===================================================================================
    // 11. result_is_the_ordinary_token_set
    // ===================================================================================

    public function testResultIsTheOrdinaryTokenSet(): void
    {
        $raw = self::VECTOR_RAW;
        $idToken = $this->signIdToken([
            'iss' => self::BASE_URL,
            'sub' => 'user-0001',
            'aud' => self::CLIENT_ID,
            'exp' => time() + 900,
            'iat' => time(),
            'nonce' => $raw, // AXIAM's own token carries the RAW nonce, as sent
        ]);
        $client = $this->client([
            self::tokens([
                'token_type' => 'DPoP',
                'refresh_token' => 'native-refresh-token',
                'id_token' => $idToken,
                'scope' => 'openid profile',
            ]),
            new Response(200, [], (string) json_encode(['jwks_uri' => self::BASE_URL . '/oauth2/jwks'])),
            new Response(200, [], (string) json_encode($this->fixtureJwks())),
        ]);

        $set = $client->loginWithProviderIdToken('slug', 'provider.id.token', $raw, scopes: ['openid', 'profile'], configuration: $this->configuration());

        self::assertSame('native-access-token', $set->accessToken->reveal());
        self::assertSame('DPoP', $set->tokenType, 'token_type is read, not assumed');
        self::assertSame('openid profile', $set->scope);
        self::assertSame('native-refresh-token', $set->refreshToken?->reveal());
        self::assertSame($idToken, $set->idToken?->reveal());
        self::assertSame('user-0001', $set->idClaims['sub'] ?? null);
        self::assertSame($raw, $set->idClaims['nonce'] ?? null);

        // The client's own credentials are unchanged: this SDK adopts only on request, as
        // loginClientCredentials and deviceLogin do (asserted in
        // testAdoptAsCredentialIsTheSameOptInAsLoginClientCredentials).

        // A mismatching nonce claim is the nonce_mismatch AuthError, and the set is discarded.
        $client = $this->client([
            self::tokens(['id_token' => $idToken, 'refresh_token' => 'native-refresh-token']),
            new Response(200, [], (string) json_encode(['jwks_uri' => self::BASE_URL . '/oauth2/jwks'])),
            new Response(200, [], (string) json_encode($this->fixtureJwks())),
        ]);
        try {
            $client->loginWithProviderIdToken('slug', 'provider.id.token', 'a-different-raw-nonce', scopes: ['openid'], configuration: $this->configuration());
            self::fail('expected nonce_mismatch');
        } catch (AuthError $e) {
            self::assertSame('nonce_mismatch', $e->getReason());
        }

        // A 200 without refresh_token and id_token decodes with both absent.
        $client = $this->client([self::tokens()]);
        $bare = $client->loginWithProviderIdToken('slug', 't', 'n', configuration: $this->configuration());
        self::assertNull($bare->refreshToken);
        self::assertNull($bare->idToken);
        self::assertNull($bare->idClaims);
        self::assertSame('Bearer', $bare->tokenType);
        self::assertCount(1, $this->sent, 'no JWKS fetch without an id_token');
    }

    public function testAdoptAsCredentialIsTheSameOptInAsLoginClientCredentials(): void
    {
        $allowed = static fn (): Response => new Response(200, ['Content-Type' => 'application/json'], '{"allowed":true}');
        $client = $this->client([self::tokens(), $allowed(), self::tokens(), $allowed()]);

        $client->loginWithProviderIdToken('slug', 't', 'n', configuration: $this->configuration());
        self::assertNull($this->authorizationOfNextCall($client), 'not adopted unless the caller opts in');

        $client->loginWithProviderIdToken('slug', 't', 'n', configuration: $this->configuration(), adoptAsCredential: true);
        self::assertSame(
            'Bearer native-access-token',
            $this->authorizationOfNextCall($client),
            'adopted, it authenticates the next same-origin REST call as Bearer',
        );
        self::assertFalse($this->sent[2]->hasHeader('Authorization'), 'and was never sent to /oauth2/token');
    }

    /** The `Authorization` the client puts on its next REST call, `null` when it sends none. */
    private function authorizationOfNextCall(AxiamClient $client): ?string
    {
        $client->checkAccess('read', 'doc-1');
        $request = $this->sent[array_key_last($this->sent)];
        self::assertSame('/api/v1/authz/check', $request->getUri()->getPath());

        return $request->hasHeader('Authorization') ? $request->getHeaderLine('Authorization') : null;
    }

    // ===================================================================================
    // 12. no_secret_in_logs_or_errors
    // ===================================================================================

    public function testNoSecretInLogsOrErrors(): void
    {
        $idToken = 'provider.id.' . bin2hex(random_bytes(16));
        $nonce = 'raw-nonce-' . bin2hex(random_bytes(16));
        $logger = new class () extends AbstractLogger {
            /** @var list<string> */
            public array $lines = [];

            public function log($level, string|\Stringable $message, array $context = []): void
            {
                $this->lines[] = $level . ' ' . $message . ' ' . json_encode($context);
            }
        };
        $events = [];
        $telemetry = static function (object $event) use (&$events): void {
            ob_start();
            var_dump($event);
            $events[] = print_r($event, true) . var_export($event, true) . (string) ob_get_clean();
        };

        $scenarios = [
            'success' => [self::tokens(), null],
            'invalid_grant' => [self::oauthError('invalid_grant', 400, self::TOKEN_FAILURE_MESSAGE), OAuthProtocolError::class],
            'consent_required' => [self::oauthError('consent_required', 400, 'consent'), OAuthProtocolError::class],
            'client refusal' => [self::oauthError('invalid_client', 401, 'client authentication failed'), OAuthProtocolError::class],
            'rate limit' => [self::oauthError('rate_limit_exceeded', 429, 'slow', ['Retry-After' => '7']), OAuthProtocolError::class],
            'server_error' => [self::oauthError('server_error', 500, 'boom'), OAuthProtocolError::class],
            'bodyless 500' => [new Response(500), NetworkError::class],
            'transport' => [new ConnectException('connection reset', new Request('POST', self::BASE_URL . '/oauth2/token')), NetworkError::class],
            'malformed 200' => [new Response(200, [], '{"access_token":""}'), NetworkError::class],
        ];

        $rendered = '';
        foreach ($scenarios as $name => [$response, $expected]) {
            $client = $this->client([$response], logger: $logger, telemetry: $telemetry);
            try {
                $result = $client->loginWithProviderIdToken('slug', $idToken, $nonce, configuration: $this->configuration());
                self::assertNull($expected, $name . ': expected a failure');
                $rendered .= print_r($result, true) . var_export($result, true) . json_encode($result);
            } catch (\Throwable $e) {
                self::assertNotNull($expected, $name . ': unexpected failure');
                self::assertInstanceOf($expected, $e, $name);
                $rendered .= $e->getMessage() . "\n" . $e . "\n" . print_r($e, true);
                for ($cause = $e->getPrevious(); $cause !== null; $cause = $cause->getPrevious()) {
                    $rendered .= $cause->getMessage() . "\n" . $cause . "\n";
                }
            }
        }

        // The local refusals, too (rule 4): the message names the parameter, never the value.
        try {
            $this->client([])->loginWithProviderIdToken('', $idToken, $nonce);
        } catch (AuthError $e) {
            $rendered .= $e->getMessage() . "\n" . $e;
        }

        // The ID-token validation failure (nonce_mismatch) is a failure path as well.
        $signed = $this->signIdToken([
            'iss' => self::BASE_URL, 'sub' => 's', 'aud' => self::CLIENT_ID,
            'exp' => time() + 900, 'iat' => time(), 'nonce' => 'something-else',
        ]);
        $client = $this->client([
            self::tokens(['id_token' => $signed]),
            new Response(200, [], (string) json_encode(['jwks_uri' => self::BASE_URL . '/oauth2/jwks'])),
            new Response(200, [], (string) json_encode($this->fixtureJwks())),
        ], logger: $logger, telemetry: $telemetry);
        try {
            $client->loginWithProviderIdToken('slug', $idToken, $nonce, scopes: ['openid'], configuration: $this->configuration());
        } catch (AuthError $e) {
            $rendered .= $e->getMessage() . "\n" . $e . "\n" . print_r($e, true);
        }

        $everything = $rendered . implode("\n", $logger->lines) . implode("\n", $events);
        self::assertNotSame('', $everything);
        self::assertFalse(str_contains($everything, $idToken), 'the provider ID token appears in a log, error, rendering or telemetry attribute');
        self::assertFalse(str_contains($everything, $nonce), 'the raw nonce appears in a log, error, rendering or telemetry attribute');

        // ProviderNonce.raw's rendering (§37.4).
        $pair = $client->nativeNonce();
        $raw = $pair->raw->reveal();
        $renderedPair = print_r($pair, true) . var_export($pair, true) . (string) json_encode($pair)
            . print_r($pair->raw, true) . (string) $pair->raw . (string) json_encode($pair->raw);
        ob_start();
        var_dump($pair);
        $renderedPair .= (string) ob_get_clean();
        self::assertFalse(str_contains($renderedPair, $raw), 'ProviderNonce.raw is rendered in clear');
        self::assertTrue(str_contains($renderedPair, $pair->hashed), 'the hashed value is not secret and may be rendered');
    }

    // ===================================================================================
    // 13. native_nonce_pair
    // ===================================================================================

    public function testNativeNoncePair(): void
    {
        $client = $this->client([]);

        $pair = $client->nativeNonce();

        self::assertInstanceOf(ProviderNonce::class, $pair);
        self::assertInstanceOf(Sensitive::class, $pair->raw, 'raw is wrapped');
        self::assertIsString($pair->hashed, 'hashed is a plain string');

        $raw = $pair->raw->reveal();
        self::assertMatchesRegularExpression('/^[A-Za-z0-9_-]+$/', $raw, 'base64url without padding');
        self::assertStringNotContainsString('=', $raw);
        $decoded = base64_decode(strtr($raw, '-_', '+/'), true);
        self::assertNotFalse($decoded);
        self::assertGreaterThanOrEqual(32, strlen($decoded), 'at least 32 bytes of entropy');
        self::assertLessThanOrEqual(512, strlen($raw), 'well under the server bound');

        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $pair->hashed, '64 lower-case hex characters');
        self::assertSame(hash('sha256', $raw), $pair->hashed, 'SHA-256 of the bytes of raw as sent');

        // The fixed vector tests the hashing step only.
        self::assertSame(self::VECTOR_HASH, ProviderNonce::hash(self::VECTOR_RAW));

        $other = $client->nativeNonce();
        self::assertNotSame($raw, $other->raw->reveal(), 'a fresh pair on every call');
        self::assertNotSame($pair->hashed, $other->hashed);

        self::assertCount(0, $this->sent, 'pure local computation: no network I/O');
    }
}
