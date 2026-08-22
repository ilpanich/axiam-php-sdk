<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\OAuthProtocolError;
use Axiam\Sdk\Oidc\AuthorizationRequest;
use Axiam\Sdk\Oidc\OidcConfiguration;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * CONTRACT.md §26 — Pushed Authorization Requests (RFC 9126).
 *
 * Two assertions carry the section:
 *
 * - `testASuccessfulPushAnswers201` — RFC 9126 §2.2 specifies *Created*. A success
 *   predicate written `=== 200` passes every other test in this file and treats every real
 *   push as a failure.
 * - `testTheRedirectUrlCarriesExactlyTwoParameters` — the server refuses a request that
 *   mixes a `request_uri` with inline authorization parameters rather than merging them,
 *   and merging is where parameter confusion lives (§26.2 rule 2).
 */
final class OidcParTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT_UUID = '22222222-2222-2222-2222-222222222222';
    private const CLIENT_ID = 'test-relying-party';
    private const CLIENT_SECRET = 'test-client-secret';
    private const REDIRECT_URI = 'https://app.example.com/callback';
    private const REQUEST_URI = 'urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c';

    /** @var list<RequestInterface> */
    private array $sent = [];

    /** @param array<int,Response|\Throwable> $queue */
    private function client(array $queue, ?string $clientSecret = self::CLIENT_SECRET): AxiamClient
    {
        $this->sent = [];
        $mock = new MockHandler($queue);
        $captured = &$this->sent;
        $transportHandler = static function (RequestInterface $request, array $options) use ($mock, &$captured) {
            $captured[] = $request;

            return $mock($request, $options);
        };

        return new AxiamClient(
            self::BASE_URL,
            self::TENANT_UUID,
            oidcClientId: self::CLIENT_ID,
            oidcClientSecret: $clientSecret,
            oidcTenantId: self::TENANT_UUID,
            transportHandler: $transportHandler,
        );
    }

    private function discoveryResponse(bool $withPar = true): Response
    {
        $document = [
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
            'scopes_supported' => ['openid', 'profile'],
            'token_endpoint_auth_methods_supported' => ['client_secret_post'],
            'claims_supported' => ['sub'],
            'grant_types_supported' => ['authorization_code'],
        ];
        if ($withPar) {
            $document['pushed_authorization_request_endpoint'] = self::BASE_URL . '/oauth2/par';
        }

        return new Response(200, ['Content-Type' => 'application/json'], (string) json_encode($document));
    }

    private function parResponse(): Response
    {
        return new Response(201, ['Content-Type' => 'application/json'], (string) json_encode([
            'request_uri' => self::REQUEST_URI,
            'expires_in' => 90,
        ]));
    }

    /** @return array<string,string> */
    private function formOf(int $index): array
    {
        parse_str((string) $this->sent[$index]->getBody(), $parsed);
        /** @var array<string,string> $parsed */
        return $parsed;
    }

    /** @return array{0:OidcConfiguration,1:AuthorizationRequest} */
    private function begin(AxiamClient $client): array
    {
        $config = $client->oidcDiscover();

        return [$config, $client->oidcBegin($config, self::REDIRECT_URI)];
    }

    // -----------------------------------------------------------------------
    // §26.1 — the push
    // -----------------------------------------------------------------------

    public function testASuccessfulPushAnswers201(): void
    {
        $client = $this->client([$this->discoveryResponse(), $this->parResponse()]);
        [$config, $begun] = $this->begin($client);

        $pushed = $client->oidcPar($begun, self::REDIRECT_URI, $config, 'openid profile');

        self::assertSame(self::REQUEST_URI, $pushed->requestUri->reveal());
        self::assertSame(90, $pushed->expiresIn);
    }

    public function testThePushGoesToTheDiscoveredEndpointWithTheTenantQuery(): void
    {
        $client = $this->client([$this->discoveryResponse(), $this->parResponse()]);
        [$config, $begun] = $this->begin($client);

        $client->oidcPar($begun, self::REDIRECT_URI, $config);

        $request = $this->sent[1];
        self::assertSame('POST', $request->getMethod());
        self::assertSame('/oauth2/par', $request->getUri()->getPath());
        // §12.1 rule 2: the /oauth2 endpoints carry the tenant as a query parameter, and
        // PAR is one of those.
        parse_str($request->getUri()->getQuery(), $query);
        self::assertSame(self::TENANT_UUID, $query['tenant_id']);
    }

    public function testThePushCarriesEverythingOidcBeginComputed(): void
    {
        $client = $this->client([$this->discoveryResponse(), $this->parResponse()]);
        [$config, $begun] = $this->begin($client);

        $pushed = $client->oidcPar($begun, self::REDIRECT_URI, $config, 'openid profile');

        $form = $this->formOf(1);
        // §26.2 rule 1: no second generator. state, nonce and the PKCE pair all come from
        // the AuthorizationRequest that was pushed — two sources for any of them are two
        // things that can disagree.
        self::assertSame($begun->state, $form['state']);
        self::assertSame($begun->nonce, $form['nonce']);
        self::assertSame($begun->state, $pushed->state);
        self::assertSame($begun->nonce, $pushed->nonce);
        self::assertSame($begun->codeVerifier->reveal(), $pushed->codeVerifier->reveal());

        self::assertSame(self::CLIENT_ID, $form['client_id']);
        self::assertSame('code', $form['response_type']);
        self::assertSame(self::REDIRECT_URI, $form['redirect_uri']);
        self::assertSame('openid profile', $form['scope']);
        self::assertSame('S256', $form['code_challenge_method']);
        self::assertNotEmpty($form['code_challenge']);
    }

    public function testAConfidentialClientAuthenticatesThePush(): void
    {
        $client = $this->client([$this->discoveryResponse(), $this->parResponse()]);
        [$config, $begun] = $this->begin($client);

        $client->oidcPar($begun, self::REDIRECT_URI, $config);

        self::assertSame(self::CLIENT_SECRET, $this->formOf(1)['client_secret']);
    }

    public function testAPublicClientPushesWithoutASecret(): void
    {
        $client = $this->client([$this->discoveryResponse(), $this->parResponse()], clientSecret: null);
        [$config, $begun] = $this->begin($client);

        $client->oidcPar($begun, self::REDIRECT_URI, $config);

        self::assertArrayNotHasKey('client_secret', $this->formOf(1));
    }

    public function testOpenidIsAddedToAScopeThatOmitsIt(): void
    {
        $client = $this->client([$this->discoveryResponse(), $this->parResponse()]);
        [$config, $begun] = $this->begin($client);

        $client->oidcPar($begun, self::REDIRECT_URI, $config, 'profile email');

        $scope = $this->formOf(1)['scope'];
        self::assertContains('openid', explode(' ', $scope), 'an OIDC request without openid is not one: ' . $scope);
    }

    public function testParDiscoversWhenGivenNoConfiguration(): void
    {
        $client = $this->client([$this->discoveryResponse(), $this->parResponse()]);
        [, $begun] = $this->begin($client);

        // The document is cached per client (§12.3 rule 6), so passing null costs no
        // second fetch.
        $client->oidcPar($begun, self::REDIRECT_URI);

        self::assertCount(2, $this->sent);
        self::assertSame('/oauth2/par', $this->sent[1]->getUri()->getPath());
    }

    public function testAnExplicitTenantOverridesTheClientTenant(): void
    {
        $other = '44444444-4444-4444-4444-444444444444';
        $client = $this->client([$this->discoveryResponse(), $this->parResponse()]);
        [$config, $begun] = $this->begin($client);

        $client->oidcPar($begun, self::REDIRECT_URI, $config, null, $other);

        parse_str($this->sent[1]->getUri()->getQuery(), $query);
        self::assertSame($other, $query['tenant_id']);
    }

    // -----------------------------------------------------------------------
    // §26.2 rule 2 — the redirect URL
    // -----------------------------------------------------------------------

    public function testTheRedirectUrlCarriesExactlyTwoParameters(): void
    {
        $client = $this->client([$this->discoveryResponse(), $this->parResponse()]);
        [$config, $begun] = $this->begin($client);

        $pushed = $client->oidcPar($begun, self::REDIRECT_URI, $config, 'openid');

        $parts = parse_url($pushed->url);
        parse_str($parts['query'] ?? '', $query);
        // The server REFUSES a request_uri mixed with inline parameters rather than merging
        // them — re-adding scope/state/redirect_uri here restores the parameter-confusion
        // attack (§26.2 rule 2).
        self::assertSame(['client_id', 'request_uri'], array_keys($query));
        self::assertSame(self::CLIENT_ID, $query['client_id']);
        self::assertSame(self::REQUEST_URI, $query['request_uri']);
        self::assertSame('/oauth2/authorize', $parts['path']);
    }

    public function testTheRedirectUrlDropsAnyQueryTheDiscoveredEndpointCarried(): void
    {
        $client = $this->client([$this->parResponse()]);

        // An authorization_endpoint that already carries a query is legal, and its
        // parameters are exactly the ones rule 2 forbids travelling alongside a request_uri.
        $config = new OidcConfiguration(
            issuer: self::BASE_URL,
            authorization_endpoint: self::BASE_URL . '/oauth2/authorize?audience=legacy&scope=all',
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
            pushed_authorization_request_endpoint: self::BASE_URL . '/oauth2/par',
        );
        $begun = $client->oidcBegin($config, self::REDIRECT_URI);

        $pushed = $client->oidcPar($begun, self::REDIRECT_URI, $config, 'openid');

        parse_str(parse_url($pushed->url)['query'] ?? '', $query);
        self::assertSame(['client_id', 'request_uri'], array_keys($query));
    }

    // -----------------------------------------------------------------------
    // refusals
    // -----------------------------------------------------------------------

    public function testAServerWithoutParIsRefusedClientSideWithNoWireCall(): void
    {
        $client = $this->client([$this->discoveryResponse(withPar: false)]);
        [$config, $begun] = $this->begin($client);
        $before = count($this->sent);

        try {
            $client->oidcPar($begun, self::REDIRECT_URI, $config);
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertStringContainsString('pushed_authorization_request_endpoint', $e->getMessage());
        }

        // §12.7.2 rule 1's discipline: no URL is concatenated onto the issuer.
        self::assertSame(0, count($this->sent) - $before);
    }

    public function testAnOAuthErrorBodyBecomesAnOAuthProtocolError(): void
    {
        $client = $this->client([
            $this->discoveryResponse(),
            new Response(400, ['Content-Type' => 'application/json'], (string) json_encode([
                'error' => 'invalid_request_uri',
                'error_description' => 'bad request_uri',
            ])),
        ]);
        [$config, $begun] = $this->begin($client);

        try {
            $client->oidcPar($begun, self::REDIRECT_URI, $config);
            self::fail('expected OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame('invalid_request_uri', $e->error);
        }
    }

    public function testA503IsNotRetried(): void
    {
        $client = $this->client([$this->discoveryResponse(), new Response(503, [], '{}')]);
        [$config, $begun] = $this->begin($client);
        $before = count($this->sent);

        try {
            $client->oidcPar($begun, self::REDIRECT_URI, $config);
            self::fail('expected a failure');
        } catch (\Throwable) {
            // expected
        }

        // §26.2 rule 4: a POST that creates server state falls outside §16.2's read-only
        // eligibility. The safe recovery is a fresh push, which cannot double-consume
        // anything.
        self::assertSame(1, count($this->sent) - $before, 'the push must not be retried');
    }

    public function testAResponseWithNoRequestUriIsANetworkError(): void
    {
        $client = $this->client([
            $this->discoveryResponse(),
            new Response(201, ['Content-Type' => 'application/json'], '{"expires_in":90}'),
        ]);
        [$config, $begun] = $this->begin($client);

        $this->expectException(NetworkError::class);
        $client->oidcPar($begun, self::REDIRECT_URI, $config);
    }

    // -----------------------------------------------------------------------
    // §26.5 / discovery
    // -----------------------------------------------------------------------

    public function testTheRequestUriIsSensitive(): void
    {
        $client = $this->client([$this->discoveryResponse(), $this->parResponse()]);
        [$config, $begun] = $this->begin($client);

        $pushed = $client->oidcPar($begun, self::REDIRECT_URI, $config);

        // Between the push and the redirect it is a bearer handle to a fully-formed
        // authorization request (§26.5). The URL it goes into is not secret; the bare
        // handle in a log line is.
        self::assertStringNotContainsString(self::REQUEST_URI, print_r($pushed->requestUri, true));
        parse_str(parse_url($pushed->url)['query'] ?? '', $query);
        self::assertSame(self::REQUEST_URI, $query['request_uri']);
    }

    public function testDiscoveryExposesThePushedAuthorizationRequestEndpoint(): void
    {
        $client = $this->client([$this->discoveryResponse()]);

        $config = $client->oidcDiscover();

        self::assertSame(self::BASE_URL . '/oauth2/par', $config->pushed_authorization_request_endpoint);
    }

    public function testADiscoveryDocumentWithoutParParsesWithANullEndpoint(): void
    {
        $client = $this->client([$this->discoveryResponse(withPar: false)]);

        // Absent, not empty: §26 is optional, and an SDK that synthesized an endpoint here
        // would POST a fully-formed authorization request at a 404.
        self::assertNull($client->oidcDiscover()->pushed_authorization_request_endpoint);
    }
}
