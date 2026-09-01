<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Oidc\FederationProvider;
use Axiam\Sdk\Oidc\FederationProviderList;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * The four public "Sign in with X" operations added by contract 1.38 —
 * `ssoProviders`, `ssoStartOauth2`, `ssoCompleteOauth2` and
 * `ssoCompleteHandoff` (CONTRACT.md §12.1).
 *
 * Two kinds of assertion live here, and both are needed.
 *
 * The **wire-shape** tests read the vendored `openapi.json` and assert the
 * method, path, content type and — for `ssoProviders` — the *parameter location*
 * the server declares, then assert that what this SDK actually puts on the wire
 * matches. Asserting only against the mock would pin the SDK to the test's own
 * idea of the endpoint; asserting only against the spec would not notice an SDK
 * that agrees with the spec and calls something else.
 *
 * The **rule** tests cover the four §12.1 notes easiest to get quietly wrong:
 * note 9 (an empty provider list is a success, not a not-found), note 10
 * (`protocol` selects the start operation), note 12 (a handoff `401` is terminal
 * and is never retried) and rule 12a (a `400` from a start call is a
 * configuration refusal, not something to retry).
 */
final class OidcLoginProvidersTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT_SLUG = 'acme-tenant';
    private const CONFIG_ID = 'fed-config-1';
    private const REDIRECT_URI = 'https://app.test/sso/callback';

    private const PROVIDERS_PATH = '/api/v1/auth/federation/providers';
    private const OIDC_START_PATH = '/api/v1/auth/federation/oidc/start';
    private const OAUTH2_START_PATH = '/api/v1/auth/federation/oauth2/start';
    private const OAUTH2_CALLBACK_PATH = '/api/v1/auth/federation/oauth2/callback';
    private const HANDOFF_PATH = '/api/v1/auth/federation/handoff';

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

    /** @return array<string,mixed> */
    private static function openApi(): array
    {
        /** @var array<string,mixed> $spec */
        $spec = json_decode((string) file_get_contents(__DIR__ . '/../openapi.json'), true);

        return $spec;
    }

    /** @return array<string,mixed> */
    private static function operation(string $path, string $method): array
    {
        /** @var array<string,mixed> $op */
        $op = self::openApi()['paths'][$path][$method];

        return $op;
    }

    /** @return array<string,mixed> */
    private static function schema(string $name): array
    {
        /** @var array<string,mixed> $schema */
        $schema = self::openApi()['components']['schemas'][$name];

        return $schema;
    }

    private static function startBody(): string
    {
        return (string) json_encode([
            'authorize_url' => 'https://github.com/login/oauth/authorize',
            'state' => 's-1',
            'expires_in_secs' => 600,
        ]);
    }

    private static function sessionBody(): string
    {
        return (string) json_encode([
            'user_id' => '99999999-8888-7777-6666-555555555555',
            'session_id' => '12121212-3434-5656-7878-909090909090',
            'expires_in' => 900,
            'redirect_uri' => self::REDIRECT_URI,
        ]);
    }

    /** @return array<string,mixed> */
    private static function provider(string $id, string $kind, string $protocol): array
    {
        return [
            'id' => $id,
            'provider_kind' => $kind,
            'display_name' => $kind,
            'protocol' => $protocol,
            'has_bundled_mark' => true,
            'inherited' => false,
        ];
    }

    // ===================================================================================
    // Wire shape, against openapi.json
    // ===================================================================================

    public function testOpenApiDeclaresSsoProvidersAsAGetWithNoBody(): void
    {
        $op = self::operation(self::PROVIDERS_PATH, 'get');

        self::assertArrayNotHasKey('requestBody', $op, 'ssoProviders is a GET and must have no request body (§12.1)');
        self::assertSame(
            '#/components/schemas/PublicFederationProvidersResponse',
            $op['responses']['200']['content']['application/json']['schema']['$ref'],
        );
    }

    /** @return list<array{0:string,1:string,2:string}> */
    public static function postOperationProvider(): array
    {
        return [
            [self::OAUTH2_START_PATH, 'OAuth2StartRequest', 'OAuth2StartResponse'],
            [self::OAUTH2_CALLBACK_PATH, 'OAuth2CallbackRequest', 'SsoLoginSuccessResponse'],
            [self::HANDOFF_PATH, 'SsoHandoffRequest', 'SsoLoginSuccessResponse'],
        ];
    }

    /** @dataProvider postOperationProvider */
    public function testOpenApiDeclaresTheThreePostsWithTheirContractSchemas(
        string $path,
        string $request,
        string $response,
    ): void {
        $op = self::operation($path, 'post');

        self::assertSame(
            '#/components/schemas/' . $request,
            $op['requestBody']['content']['application/json']['schema']['$ref'],
        );
        self::assertSame(
            '#/components/schemas/' . $response,
            $op['responses']['200']['content']['application/json']['schema']['$ref'],
        );
    }

    /**
     * §12.1: the provider identifiers are **query** parameters. Asserted because the
     * neighbouring start operations take the same four in a JSON body, and the two
     * are one copy-paste apart.
     */
    public function testOpenApiPutsTheProviderIdentifiersInTheQueryString(): void
    {
        $names = [];
        foreach (self::operation(self::PROVIDERS_PATH, 'get')['parameters'] as $parameter) {
            self::assertSame('query', $parameter['in'], $parameter['name'] . ' must be a query parameter');
            $names[] = $parameter['name'];
        }
        sort($names);

        self::assertSame(['org_id', 'org_slug', 'tenant_id', 'tenant_slug'], $names);
    }

    /**
     * The six required fields plus the nullable `button_icon`, and none of the
     * configuration a narrowed admin response would have leaked (§12.1 note 9).
     */
    public function testOpenApiPublicProviderShapeMatchesTheSdkClass(): void
    {
        $schema = self::schema('PublicFederationProvider');
        $required = $schema['required'];
        sort($required);

        self::assertSame(
            ['display_name', 'has_bundled_mark', 'id', 'inherited', 'protocol', 'provider_kind'],
            $required,
        );
        self::assertContains('null', $schema['properties']['button_icon']['type']);

        foreach (['client_id', 'client_secret', 'metadata_url', 'token_endpoint'] as $absent) {
            self::assertArrayNotHasKey(
                $absent,
                $schema['properties'],
                'the unauthenticated provider response must not carry ' . $absent,
            );
        }
    }

    /** @return list<array{0:string}> */
    public static function oauth2StartSchemaProvider(): array
    {
        return [['OAuth2StartRequest'], ['OAuth2StartResponse']];
    }

    /**
     * §12.1 note 11: the verifier is generated and held server-side, so neither
     * schema carries PKCE material and neither may the SDK.
     *
     * @dataProvider oauth2StartSchemaProvider
     */
    public function testOpenApiOauth2StartCarriesNoPkceMaterial(string $name): void
    {
        $properties = self::schema($name)['properties'];

        foreach (['code_verifier', 'code_challenge', 'code_challenge_method'] as $pkce) {
            self::assertArrayNotHasKey($pkce, $properties, $name . ' must not carry ' . $pkce);
        }
    }

    // ===================================================================================
    // ssoProviders — wire shape and §12.1 note 9
    // ===================================================================================

    public function testSsoProvidersSendsIdentifiersAsQueryParametersAndNoBody(): void
    {
        $history = [];
        $client = $this->client([new Response(200, [], (string) json_encode(['providers' => []]))], $history);

        $client->ssoProviders(orgSlug: 'other-org', tenantSlug: 'engineering');

        $request = $history[0]['request'];
        self::assertSame('GET', $request->getMethod());
        self::assertSame(self::PROVIDERS_PATH, $request->getUri()->getPath());
        parse_str($request->getUri()->getQuery(), $query);
        self::assertSame('other-org', $query['org_slug']);
        self::assertSame('engineering', $query['tenant_slug']);
        self::assertArrayNotHasKey('org_id', $query, 'an unset identifier is omitted, not sent empty');
        self::assertSame('', (string) $request->getBody(), 'ssoProviders is a GET with no body (§12.1)');
    }

    public function testSsoProvidersDefaultsTheWorkspaceFromTheClient(): void
    {
        $history = [];
        $client = $this->client([new Response(200, [], (string) json_encode(['providers' => []]))], $history);

        $client->ssoProviders();

        parse_str($history[0]['request']->getUri()->getQuery(), $query);
        self::assertSame('acme', $query['org_slug']);
        self::assertSame(self::TENANT_SLUG, $query['tenant_slug']);
    }

    /**
     * §12.1 note 9. The three cases the endpoint makes indistinguishable — unknown
     * organization, known-but-empty, and no workspace named — are all ordinary
     * successes. Mapping any of them to an error would restore the two-valued answer
     * the empty list removes, and with it the organization-slug oracle.
     */
    public function testAnEmptyProviderListIsASuccessNotAnError(): void
    {
        $empty = static fn (): Response => new Response(200, [], (string) json_encode(['providers' => []]));
        $client = $this->client([$empty(), $empty(), $empty()]);

        self::assertSame([], $client->ssoProviders(orgSlug: 'no-such-organization')->providers);
        self::assertSame([], $client->ssoProviders(orgSlug: 'acme', tenantSlug: self::TENANT_SLUG)->providers);
        self::assertSame([], $client->ssoProviders()->providers);
    }

    /**
     * The consequence of note 9 easiest to get wrong: unlike the start operations, a
     * request resolving no organization is **sent** rather than refused client-side.
     * A `400` for "you named nothing" against a `200 []` for an unknown slug would be
     * that same two-valued answer by another route.
     */
    public function testSsoProvidersSendsTheRequestEvenWithNoOrganizationContext(): void
    {
        $history = [];
        // orgSlug: null — ssoStart refuses this same client, client-side.
        $client = $this->client(
            [new Response(200, [], (string) json_encode(['providers' => []]))],
            $history,
            orgSlug: null,
        );

        $list = $client->ssoProviders();

        self::assertInstanceOf(FederationProviderList::class, $list);
        self::assertSame([], $list->providers);
        self::assertCount(1, $history, 'the request must reach the wire');
    }

    public function testSsoProvidersMapsEveryFieldIncludingTheNullableButtonIcon(): void
    {
        $client = $this->client([new Response(200, [], (string) json_encode(['providers' => [
            [
                'id' => '11111111-1111-1111-1111-111111111111',
                'provider_kind' => 'google',
                'display_name' => 'Google',
                'protocol' => FederationProvider::PROTOCOL_OIDC_CONNECT,
                'has_bundled_mark' => true,
                'inherited' => true,
                'button_icon' => null,
            ],
            [
                'id' => '22222222-2222-2222-2222-222222222222',
                'provider_kind' => 'generic_oauth2',
                'display_name' => 'Acme SSO',
                'protocol' => FederationProvider::PROTOCOL_OAUTH2,
                'has_bundled_mark' => false,
                'inherited' => false,
                'button_icon' => 'data:image/png;base64,iVBORw0KGgo=',
            ],
        ]]))]);

        $providers = $client->ssoProviders()->providers;

        self::assertCount(2, $providers);
        self::assertSame('google', $providers[0]->providerKind);
        self::assertSame(FederationProvider::PROTOCOL_OIDC_CONNECT, $providers[0]->protocol);
        self::assertTrue($providers[0]->hasBundledMark);
        // Reported so an admin surface can show that a provider is not the tenant's to
        // edit; nothing here computes it (§12.1 note 13).
        self::assertTrue($providers[0]->inherited);
        self::assertNull($providers[0]->buttonIcon, 'button_icon is absent for most providers');

        self::assertSame(FederationProvider::PROTOCOL_OAUTH2, $providers[1]->protocol);
        self::assertFalse($providers[1]->hasBundledMark);
        self::assertSame('data:image/png;base64,iVBORw0KGgo=', $providers[1]->buttonIcon);
    }

    public function testSsoProvidersNonOkStatusMapsThroughTheTaxonomy(): void
    {
        $client = $this->client([new Response(500, [], '{"message":"boom"}')]);

        $this->expectException(NetworkError::class);
        $client->ssoProviders();
    }

    // ===================================================================================
    // §12.1 note 10 — protocol selects the start operation
    // ===================================================================================

    /**
     * All three branches, asserted on which endpoint the resulting call reached.
     *
     * `provider_kind` is deliberately misleading in this fixture: the `Saml` row is
     * `google`, the kind whose OIDC connector everybody assumes. A dispatch that read
     * the kind would send it to the OIDC start endpoint and be caught by the recorded
     * paths below.
     */
    public function testProtocolSelectsTheStartOperationForAllThreeBranches(): void
    {
        $history = [];
        $client = $this->client([
            new Response(200, [], (string) json_encode(['providers' => [
                self::provider('11111111-1111-1111-1111-111111111111', 'microsoft', FederationProvider::PROTOCOL_OIDC_CONNECT),
                self::provider('22222222-2222-2222-2222-222222222222', 'github', FederationProvider::PROTOCOL_OAUTH2),
                self::provider('33333333-3333-3333-3333-333333333333', 'google', FederationProvider::PROTOCOL_SAML),
            ]])),
            new Response(200, [], self::startBody()),
            new Response(200, [], self::startBody()),
        ], $history);

        $samlSeen = false;
        foreach ($client->ssoProviders()->providers as $provider) {
            switch ($provider->protocol) {
                case FederationProvider::PROTOCOL_OIDC_CONNECT:
                    $client->ssoStart($provider->id, self::REDIRECT_URI);
                    break;
                case FederationProvider::PROTOCOL_OAUTH2:
                    $client->ssoStartOauth2($provider->id, self::REDIRECT_URI);
                    break;
                case FederationProvider::PROTOCOL_SAML:
                    // Saml goes to the SAML login endpoint, which §12.1 note 10 says is
                    // NOT a §12 vocabulary operation. The branch exists so a Saml
                    // provider is never quietly handed to one of the other two.
                    $samlSeen = true;
                    break;
                default:
                    self::fail('unknown protocol ' . $provider->protocol);
            }
        }

        self::assertTrue($samlSeen, 'the Saml branch must be reachable');
        $paths = array_map(
            static fn (array $entry): string => $entry['request']->getUri()->getPath(),
            $history,
        );
        self::assertSame(
            [self::PROVIDERS_PATH, self::OIDC_START_PATH, self::OAUTH2_START_PATH],
            $paths,
            'OidcConnect must reach the OIDC start endpoint and OAuth2 the OAuth2 one — and the Saml provider neither',
        );
    }

    // ===================================================================================
    // ssoStartOauth2
    // ===================================================================================

    public function testSsoStartOauth2PostsTheBodyAndSendsNoPkce(): void
    {
        $history = [];
        $client = $this->client([new Response(200, [], self::startBody())], $history);

        $result = $client->ssoStartOauth2(self::CONFIG_ID, self::REDIRECT_URI);

        self::assertSame('s-1', $result->state);
        self::assertSame(600, $result->expiresInSecs);

        $request = $history[0]['request'];
        self::assertSame(self::OAUTH2_START_PATH, $request->getUri()->getPath());
        self::assertSame('application/json', $request->getHeaderLine('Content-Type'));
        $body = json_decode((string) $request->getBody(), true);
        self::assertSame(self::CONFIG_ID, $body['federation_config_id']);
        self::assertSame(self::REDIRECT_URI, $body['redirect_uri']);
        self::assertSame(self::TENANT_SLUG, $body['tenant_slug']);
        self::assertSame('acme', $body['org_slug']);
        // §12.1 note 11: the verifier is server-side. Its absence is the contract.
        foreach (['code_verifier', 'code_challenge', 'code_challenge_method'] as $pkce) {
            self::assertArrayNotHasKey($pkce, $body, 'the SDK must not send ' . $pkce);
        }
    }

    public function testSsoStartOauth2WithoutOrgContextRaisesAuthErrorWithNoWireCall(): void
    {
        // An empty MockHandler queue proves no wire call: one would throw "queue empty".
        $client = $this->client([], orgSlug: null);

        $this->expectException(AuthError::class);
        $client->ssoStartOauth2(self::CONFIG_ID, self::REDIRECT_URI);
    }

    // ===================================================================================
    // §12.1 rule 12a — a 400 from a start call is a configuration refusal
    // ===================================================================================

    /**
     * On the SAML and Apple flows the identity provider never validates the SPA
     * `redirect_uri`, so the server confines it to its own issuer origin plus
     * `AXIAM__AUTH__SSO_SPA_ORIGINS` and answers `400` otherwise.
     *
     * That `400` is a **configuration** refusal — §2's `400` row, whose taxonomy
     * member in this SDK is {@see NetworkError}, as distinct from the {@see AuthError}
     * an unknown workspace gets. It must not be retried: the deployment will refuse
     * the same origin every time.
     */
    public function testA400FromSsoStartOauth2IsAConfigurationErrorAndIsNotRetried(): void
    {
        $history = [];
        $client = $this->client([new Response(400, [], '{"message":"redirect_uri origin refused"}')], $history);

        try {
            $client->ssoStartOauth2(self::CONFIG_ID, 'https://attacker.example/');
            self::fail('a refused redirect_uri origin is an error');
        } catch (NetworkError $e) {
            self::assertNotInstanceOf(AuthError::class, $e, 'rule 12a: not an authentication outcome');
        }

        self::assertCount(1, $history, 'rule 12a: the refusal must not be retried');
    }

    /** The same refusal is reachable from the OIDC start operation (Apple arrives there). */
    public function testA400FromSsoStartIsAlsoAConfigurationError(): void
    {
        $history = [];
        $client = $this->client([new Response(400, [], '{"message":"redirect_uri origin refused"}')], $history);

        $this->expectException(NetworkError::class);
        try {
            $client->ssoStart(self::CONFIG_ID, 'https://attacker.example/');
        } finally {
            self::assertCount(1, $history, 'rule 12a: the refusal must not be retried');
        }
    }

    /**
     * A `401` is the uniform "unknown workspace or provider" answer, and a *different*
     * taxonomy member from the rule-12a `400`. Asserted so the two cannot quietly
     * collapse into one.
     */
    public function testA401FromAStartCallStaysAnAuthError(): void
    {
        $client = $this->client([new Response(401, [], '{"message":"unauthorized"}')]);

        $this->expectException(AuthError::class);
        $client->ssoStartOauth2(self::CONFIG_ID, self::REDIRECT_URI);
    }

    // ===================================================================================
    // The two completions, and §12.1 note 12
    // ===================================================================================

    public function testSsoCompleteOauth2PostsStateAndCodeAndMapsTheSuccessBody(): void
    {
        $history = [];
        $client = $this->client([new Response(200, [], self::sessionBody())], $history);

        $result = $client->ssoCompleteOauth2('abc', 'provider-code');

        self::assertSame('99999999-8888-7777-6666-555555555555', $result->userId);
        self::assertSame(900, $result->expiresIn);
        self::assertSame(self::REDIRECT_URI, $result->redirectUri);

        $request = $history[0]['request'];
        self::assertSame(self::OAUTH2_CALLBACK_PATH, $request->getUri()->getPath());
        self::assertSame(
            ['state' => 'abc', 'code' => 'provider-code'],
            json_decode((string) $request->getBody(), true),
        );
    }

    public function testSsoCompleteHandoffPostsJustTheCode(): void
    {
        $history = [];
        $client = $this->client([new Response(200, [], self::sessionBody())], $history);

        $result = $client->ssoCompleteHandoff('handoff-code');

        self::assertSame('12121212-3434-5656-7878-909090909090', $result->sessionId);

        $request = $history[0]['request'];
        self::assertSame(self::HANDOFF_PATH, $request->getUri()->getPath());
        self::assertSame(['code' => 'handoff-code'], json_decode((string) $request->getBody(), true));
    }

    /**
     * §12.1 note 12. Unknown, expired and already-redeemed all answer the same `401`,
     * on purpose. The code is spent either way, so a retry cannot succeed and would
     * only widen the window in which it sits in a log.
     */
    public function testAHandoff401IsTerminalAndIsNotRetried(): void
    {
        $history = [];
        $client = $this->client([new Response(401, [], '{"message":"unauthorized"}')], $history);

        $this->expectException(AuthError::class);
        try {
            $client->ssoCompleteHandoff('spent-or-expired-or-never-existed');
        } finally {
            self::assertCount(1, $history, 'the redemption must not be retried: the code is gone either way');
        }
    }

    /**
     * The two values a caller codes against: it reads the code out of
     * `?axiam_handoff=` and has 60 seconds to spend it.
     */
    public function testTheHandoffParameterAndTtlAreWhatTheContractSays(): void
    {
        self::assertSame('axiam_handoff', FederationProviderList::HANDOFF_QUERY_PARAM);
        self::assertSame(60, FederationProviderList::HANDOFF_CODE_TTL_SECONDS);
    }
}
