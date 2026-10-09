<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Oidc\MtlsEndpointAliases;
use Axiam\Sdk\Oidc\OidcConfiguration;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * RFC 8705 §5 `mtls_endpoint_aliases` — CONTRACT.md §21.3 rule 2 (contract 1.40).
 *
 * The rule has one sentence and three named ways to get it wrong, and this class is
 * organised around them rather than around the SDK's method list:
 *
 * - a call going over mTLS prefers the alias;
 * - a call NOT going over mTLS keeps the top-level entry;
 * - an ABSENT member means "no separate mTLS host", never "unsupported";
 * - only the seven listed endpoints are ever aliased (six until contract 1.58 added CIBA's) — not `authorization_endpoint`,
 *   `end_session_endpoint` or `jwks_uri`;
 * - `issuer` is not an endpoint, does not move, and still governs `iss` validation by
 *   exact string.
 *
 * A recording transport handler stands in for both listeners a deployment runs: it answers
 * by path and records the full URI, so choosing the wrong host is a recorded call the
 * assertion can name. The §6.1 identity is a throwaway openssl-generated pair — what is
 * under test is *which URL the SDK chooses*, which the configured identity and the
 * document decide, not the socket.
 */
final class MtlsEndpointAliasesTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const MTLS_BASE_URL = 'https://mtls.api.test';
    private const TENANT = 'acme-tenant';
    private const TENANT_ID = '11111111-2222-3333-4444-555555555555';

    /** @var list<string> Every absolute URI the SDK requested, in order. */
    private array $requested = [];

    protected function setUp(): void
    {
        $this->requested = [];
    }

    /**
     * All seven aliases on the mTLS origin — shaped like CONTRACT.md §21.3.1 vector A but
     * without its queries; the vector itself is read from the vendored text by
     * {@see self::testVectorAReadFromTheVendoredContractRoutesEveryAliasedCallWithItsQueryIntact()}.
     *
     * @return array<string,string>
     */
    private function allAliases(): array
    {
        return [
            'token_endpoint' => self::MTLS_BASE_URL . '/oauth2/token',
            'userinfo_endpoint' => self::MTLS_BASE_URL . '/oauth2/userinfo',
            'revocation_endpoint' => self::MTLS_BASE_URL . '/oauth2/revoke',
            'introspection_endpoint' => self::MTLS_BASE_URL . '/oauth2/introspect',
            'device_authorization_endpoint' => self::MTLS_BASE_URL . '/oauth2/device_authorization',
            'pushed_authorization_request_endpoint' => self::MTLS_BASE_URL . '/oauth2/par',
            'backchannel_authentication_endpoint' => self::MTLS_BASE_URL . '/oauth2/bc-authorize',
        ];
    }

    /**
     * The discovery document, optionally carrying `$aliases`.
     *
     * @param array<string,string>|null $aliases
     * @return array<string,mixed>
     */
    private function discoveryWire(?array $aliases): array
    {
        $wire = [
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
            'claims_supported' => ['sub', 'iss'],
            'grant_types_supported' => ['authorization_code', 'refresh_token', 'client_credentials'],
            'device_authorization_endpoint' => self::BASE_URL . '/oauth2/device_authorization',
            'pushed_authorization_request_endpoint' => self::BASE_URL . '/oauth2/par',
            'backchannel_authentication_endpoint' => self::BASE_URL . '/oauth2/bc-authorize',
            'end_session_endpoint' => self::BASE_URL . '/oauth2/end_session',
            'backchannel_logout_supported' => true,
            'backchannel_logout_session_supported' => true,
        ];
        if ($aliases !== null) {
            $wire['mtls_endpoint_aliases'] = $aliases;
        }

        return $wire;
    }

    /** The reply each OAuth2 endpoint's caller will accept. */
    private function responseFor(string $path): Response
    {
        return match ($path) {
            '/oauth2/device_authorization' => new Response(200, [], (string) json_encode([
                'device_code' => 'device-code-value',
                'user_code' => 'WDJB-MJHT',
                'verification_uri' => 'https://example.test/device',
                'expires_in' => 30,
                'interval' => 1,
            ])),
            // RFC 9126 §2.2 specifies Created, and the SDK asserts exactly that.
            '/oauth2/par' => new Response(201, [], (string) json_encode([
                'request_uri' => 'urn:ietf:params:oauth:request_uri:x',
                'expires_in' => 60,
            ])),
            '/oauth2/introspect' => new Response(200, [], (string) json_encode(['active' => true])),
            '/oauth2/bc-authorize' => new Response(200, [], (string) json_encode([
                'auth_req_id' => bin2hex(random_bytes(16)),
                'expires_in' => 300,
            ])),
            '/oauth2/revoke' => new Response(200, [], '{}'),
            default => new Response(200, [], (string) json_encode([
                'access_token' => 'access-token-value',
                'token_type' => 'Bearer',
                'expires_in' => 900,
            ])),
        };
    }

    /**
     * A client against the conventional origin, optionally carrying a §6.1 identity so
     * §21.3 rule 2 applies to every call it makes.
     *
     * @param array<string,string>|null $aliases
     */
    private function client(?array $aliases, bool $mtls): AxiamClient
    {
        $wire = $this->discoveryWire($aliases);
        $handler = function (RequestInterface $request) use ($wire): \GuzzleHttp\Promise\PromiseInterface {
            $uri = $request->getUri();
            $this->requested[] = $uri->getScheme() . '://' . $uri->getAuthority() . $uri->getPath();
            $response = $uri->getPath() === '/.well-known/openid-configuration'
                ? new Response(200, [], (string) json_encode($wire))
                : $this->responseFor($uri->getPath());

            return \GuzzleHttp\Promise\Create::promiseFor($response);
        };

        $identity = $mtls ? $this->generateTestIdentity() : [null, null];

        return new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            oidcClientId: 'my-app',
            oidcClientSecret: 'my-secret',
            oidcTenantId: self::TENANT_ID,
            clientCert: $identity[0],
            clientKey: $identity[1],
            transportHandler: $handler,
        );
    }

    /**
     * A throwaway self-signed identity. Nothing is committed; the transport is a fake, so
     * no handshake ever uses it — the SDK only reads that an identity is configured.
     *
     * @return array{0:string,1:string}
     */
    private function generateTestIdentity(): array
    {
        if (!\function_exists('openssl_pkey_new')) {
            self::markTestSkipped('ext-openssl is required to generate the test client identity');
        }
        $config = ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
        $key = openssl_pkey_new($config);
        self::assertNotFalse($key);
        $csr = openssl_csr_new(['commonName' => 'axiam-alias-test'], $key, $config);
        self::assertNotFalse($csr);
        $cert = openssl_csr_sign($csr, null, $key, 1, $config);
        self::assertNotFalse($cert);
        $certPem = '';
        self::assertTrue(openssl_x509_export($cert, $certPem));
        $keyPem = '';
        self::assertTrue(openssl_pkey_export($key, $keyPem, null, $config));

        return [$certPem, $keyPem];
    }

    /**
     * Every origin `$path` was requested on, in order. Empty when it was never requested —
     * which is what a refusal that did not fall back looks like.
     *
     * @return list<string>
     */
    private function hostsFor(string $path): array
    {
        return array_values(array_filter(
            $this->requested,
            static fn (string $uri): bool => str_ends_with($uri, $path),
        ));
    }

    /**
     * A §6.1 client whose discovery document carries `$aliases` AND the given top-level
     * `token_endpoint`, so the §21.3.1 like-with-like scheme comparison can be exercised
     * against something other than the suite's https default.
     *
     * @param array<string,string> $aliases
     */
    private function clientWithTopLevelTokenEndpoint(array $aliases, string $tokenEndpoint): AxiamClient
    {
        $wire = $this->discoveryWire($aliases);
        $wire['token_endpoint'] = $tokenEndpoint;
        $handler = function (RequestInterface $request) use ($wire): \GuzzleHttp\Promise\PromiseInterface {
            $uri = $request->getUri();
            $this->requested[] = $uri->getScheme() . '://' . $uri->getAuthority() . $uri->getPath();
            $response = $uri->getPath() === '/.well-known/openid-configuration'
                ? new Response(200, [], (string) json_encode($wire))
                : $this->responseFor($uri->getPath());

            return \GuzzleHttp\Promise\Create::promiseFor($response);
        };
        $identity = $this->generateTestIdentity();

        return new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            oidcClientId: 'my-app',
            oidcClientSecret: 'my-secret',
            oidcTenantId: self::TENANT_ID,
            clientCert: $identity[0],
            clientKey: $identity[1],
            transportHandler: $handler,
        );
    }

    /** Assert `$path` was requested exactly once, on `$origin`. */
    private function assertOnly(string $path, string $origin): void
    {
        $hits = array_values(array_filter(
            $this->requested,
            static fn (string $uri): bool => str_ends_with($uri, $path),
        ));
        self::assertSame([$origin . $path], $hits, $path . ' went to the wrong host');
    }

    // --- The document round-trips the member ------------------------------------------

    public function testDiscoveryExposesTheMemberWhenPublished(): void
    {
        $configuration = $this->client($this->allAliases(), mtls: false)->oidcDiscover();

        self::assertInstanceOf(MtlsEndpointAliases::class, $configuration->mtls_endpoint_aliases);
        self::assertSame(
            self::MTLS_BASE_URL . '/oauth2/token',
            $configuration->mtls_endpoint_aliases->token_endpoint,
        );
        // Alongside, never instead of: the conventional entry is untouched.
        self::assertSame(self::BASE_URL . '/oauth2/token', $configuration->token_endpoint);
    }

    public function testAnAbsentMemberIsNullRatherThanAnError(): void
    {
        $configuration = $this->client(null, mtls: true)->oidcDiscover();

        self::assertNull($configuration->mtls_endpoint_aliases);
    }

    // --- A call over mTLS prefers the alias -------------------------------------------

    public function testEveryAliasableEndpointGoesToTheAliasHost(): void
    {
        $client = $this->client($this->allAliases(), mtls: true);

        $client->loginClientCredentials();
        $client->introspect(new Sensitive('t'));
        $client->revoke(new Sensitive('t'));
        $client->deviceAuthorize();
        $configuration = $client->oidcDiscover();
        $request = $client->oidcBegin($configuration, 'https://app.example.com/cb');
        $client->oidcPar($request, 'https://app.example.com/cb');
        $client->cibaInitiate(new \Axiam\Sdk\Oidc\CibaInitiateRequest('openid', loginHint: 'ada'));

        foreach (['/oauth2/token', '/oauth2/introspect', '/oauth2/revoke',
                  '/oauth2/device_authorization', '/oauth2/par', '/oauth2/bc-authorize'] as $path) {
            $this->assertOnly($path, self::MTLS_BASE_URL);
        }
    }

    // --- Consequence 1: absence means "no separate host" ------------------------------

    public function testAnMtlsClientWithNoAliasesKeepsTheTopLevelEndpoints(): void
    {
        // Not an error, and not the alias origin: a deployment running
        // `client_auth = optional` on one listener serves both populations at the
        // conventional endpoints and correctly publishes nothing.
        $this->client(null, mtls: true)->introspect(new Sensitive('t'));

        $this->assertOnly('/oauth2/introspect', self::BASE_URL);
    }

    public function testAClientNotDoingMtlsKeepsTheTopLevelEndpoints(): void
    {
        $this->client($this->allAliases(), mtls: false)->revoke(new Sensitive('t'));

        $this->assertOnly('/oauth2/revoke', self::BASE_URL);
    }

    public function testAPartialAliasObjectFallsBackPerEndpoint(): void
    {
        // RFC 8705 §5 does not require an OP to alias all six, and the shape of this
        // member must never be why a client stops working: an object naming only
        // token_endpoint is a valid document, and every endpoint it does not name falls
        // back to the top-level entry.
        $client = $this->client(['token_endpoint' => self::MTLS_BASE_URL . '/oauth2/token'], mtls: true);

        $client->loginClientCredentials();
        $client->introspect(new Sensitive('t'));

        $this->assertOnly('/oauth2/token', self::MTLS_BASE_URL);
        $this->assertOnly('/oauth2/introspect', self::BASE_URL);
    }

    public function testAnUnsupportedGrantIsStillReportedWhenNeitherLevelNamesIt(): void
    {
        $aliases = $this->allAliases();
        unset($aliases['device_authorization_endpoint']);
        $client = $this->client($aliases, mtls: true);
        $configuration = $client->oidcDiscover();
        // Neither level names the endpoint, so the answer is still "this server does not
        // support the device grant" — never a URL built by concatenation.
        $withoutDevice = new OidcConfiguration(
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
            token_endpoint_auth_methods_supported: $configuration->token_endpoint_auth_methods_supported,
            claims_supported: $configuration->claims_supported,
            grant_types_supported: $configuration->grant_types_supported,
            device_authorization_endpoint: null,
            pushed_authorization_request_endpoint: $configuration->pushed_authorization_request_endpoint,
            end_session_endpoint: $configuration->end_session_endpoint,
            mtls_endpoint_aliases: $configuration->mtls_endpoint_aliases,
        );

        $this->expectException(AuthError::class);
        $client->deviceAuthorize(configuration: $withoutDevice);
    }

    // --- Consequence 2: no alias is ever synthesised ----------------------------------

    public function testTheFrontChannelAndJwksEndpointsAreNeverAliased(): void
    {
        $client = $this->client($this->allAliases(), mtls: true);
        $configuration = $client->oidcDiscover();

        // A browser sent to an mTLS host raises a native certificate-chooser dialog most
        // users cannot answer, and jwks_uri is public key material that gains nothing from
        // a handshake.
        $request = $client->oidcBegin($configuration, 'https://app.example.com/cb');
        self::assertStringStartsWith(self::BASE_URL . '/oauth2/authorize', $request->url);

        $logout = $client->logoutUrl(new Sensitive('not-a-real-token'), configuration: $configuration);
        self::assertStringStartsWith(self::BASE_URL . '/oauth2/end_session', $logout);

        self::assertSame(self::BASE_URL . '/oauth2/jwks', $configuration->jwks_uri);
    }

    public function testTheAliasTypeCarriesOnlyTheSevenAliasableEndpoints(): void
    {
        // Naming them as a closed set is what makes authorization_endpoint,
        // end_session_endpoint and jwks_uri unrepresentable rather than merely unused. An
        // eighth property here would be an alias the SDK could synthesise. Seven since
        // contract 1.58 amended §21.3.1 vector A with CIBA's backchannel endpoint.
        $properties = array_map(
            static fn (\ReflectionProperty $p): string => $p->getName(),
            (new \ReflectionClass(MtlsEndpointAliases::class))->getProperties(),
        );
        sort($properties);

        self::assertSame([
            'backchannel_authentication_endpoint',
            'device_authorization_endpoint',
            'introspection_endpoint',
            'pushed_authorization_request_endpoint',
            'revocation_endpoint',
            'token_endpoint',
            'userinfo_endpoint',
        ], $properties);
    }

    // --- Consequence 3: issuer is never aliased ---------------------------------------

    public function testTheIssuerDoesNotMoveWithTheEndpoints(): void
    {
        $configuration = $this->client($this->allAliases(), mtls: true)->oidcDiscover();

        // §12.4 rule 3 compares `iss` against THIS value by exact string, for every token
        // — including one minted at an alias endpoint. An SDK that derived an expected
        // issuer from the host it called would reject every token it obtains over mTLS.
        self::assertSame(self::BASE_URL, $configuration->issuer);
        self::assertNotSame(self::MTLS_BASE_URL, $configuration->issuer);
    }

    // --- Vector C: a published-but-unusable alias is REFUSED, never fallen back -------
    // --- from (CONTRACT.md §21.3.1, contract 1.43) ------------------------------------

    public function testARelativeAliasIsRefusedAndNeverFallsBack(): void
    {
        // Vector C defect 1. A relative alias resolves against nothing the client holds,
        // and the one base that might seem obvious — the issuer's host — is precisely the
        // host the alias exists to name a different one from.
        $client = $this->client(['token_endpoint' => '/oauth2/token'], mtls: true);

        try {
            $client->loginClientCredentials();
            self::fail('an unusable alias must be refused, not fallen back from');
        } catch (AuthError $error) {
            self::assertStringContainsString('/oauth2/token', $error->getMessage());
            self::assertStringContainsString('§21.3.1', $error->getMessage());
        }

        // The refusal is the point: NOTHING was sent to either origin. Falling back would
        // have presented the client certificate to the front-channel host, which
        // authenticates nothing while appearing to work.
        self::assertSame([], $this->hostsFor('/oauth2/token'));
    }

    public function testASchemeDowngradingAliasIsRefusedAndNeverFallsBack(): void
    {
        // Vector C defect 2. The top-level endpoint is https; the alias is cleartext.
        // Mutual TLS over cleartext is a contradiction.
        $client = $this->client(
            ['introspection_endpoint' => 'http://mtls.api.test/oauth2/introspect'],
            mtls: true,
        );

        try {
            $client->introspect(new Sensitive('t'));
            self::fail('a scheme downgrade must be refused, not fallen back from');
        } catch (AuthError $error) {
            self::assertStringContainsString('http', $error->getMessage());
            self::assertStringContainsString('§21.3.1', $error->getMessage());
        }

        self::assertSame([], $this->hostsFor('/oauth2/introspect'));
    }

    public function testTheRefusalIsAnAuthErrorNotANetworkError(): void
    {
        // Not a stylistic choice. §16.3 retries NetworkError and ONLY NetworkError, so
        // classifying this as one would attempt a permanent, deterministic operator
        // misconfiguration three times and then report it as transient.
        $client = $this->client(['token_endpoint' => '/oauth2/token'], mtls: true);

        $this->expectException(AuthError::class);
        $client->loginClientCredentials();
    }

    public function testLikeForLikeCleartextIsAcceptedNotADowngrade(): void
    {
        // The I4 twin for the downgrade rule. A development deployment served over http
        // publishes http aliases; that is not a downgrade, and AXIAM's own
        // build_mtls_aliases produces exactly this. Refusing it would break a supported
        // configuration in the name of a rule about downgrades.
        //
        // The top-level token_endpoint is rewritten to http so the comparison is
        // like-with-like, which is the whole point of the rule.
        $client = $this->clientWithTopLevelTokenEndpoint(
            ['token_endpoint' => 'http://dev.api.test/oauth2/token'],
            'http://dev.api.test/oauth2/token',
        );

        $client->loginClientCredentials();

        $this->assertOnly('/oauth2/token', 'http://dev.api.test');
    }

    public function testAMalformedAliasIsInertForAClientNotDoingMtls(): void
    {
        // The I4 twin for the whole vector. A client with no §6.1 identity never reaches
        // an alias at all, so an operator publishing a broken one cannot break it. This is
        // what "configured as today behaves as today" means for the majority of callers.
        $this->client(['token_endpoint' => '/oauth2/token'], mtls: false)
            ->loginClientCredentials();

        $this->assertOnly('/oauth2/token', self::BASE_URL);
    }

    public function testAnUnusableAliasForOneEndpointDoesNotPoisonAnother(): void
    {
        // Only the member actually used is validated. An operator who breaks
        // `introspection_endpoint` has not thereby broken the token endpoint — the refusal
        // is scoped to the call that would have used the bad alias.
        $client = $this->client([
            'token_endpoint' => self::MTLS_BASE_URL . '/oauth2/token',
            'introspection_endpoint' => '/oauth2/introspect',
        ], mtls: true);

        $client->loginClientCredentials();

        $this->assertOnly('/oauth2/token', self::MTLS_BASE_URL);
    }

    // --- Vector A, read from the vendored contract (R-31, contract 1.59) --------------

    /**
     * CONTRACT.md §21.3.1 vector A exactly as the vendored text carries it — the first JSON
     * block after its heading — so the pin moves with the contract instead of with a fixture
     * someone retyped (and which lost the vector's `tenant_id` queries).
     *
     * @return array<string,mixed>
     */
    private static function vectorA(): array
    {
        $contract = file_get_contents(\dirname(__DIR__) . '/CONTRACT.md');
        self::assertIsString($contract);
        $start = strpos($contract, '**Vector A — a two-listener deployment.**');
        self::assertIsInt($start, 'CONTRACT.md carries §21.3.1 vector A');
        self::assertSame(1, preg_match('/```json\n(.*?)\n```/s', $contract, $m, 0, $start));
        $vector = json_decode($m[1], true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($vector);

        /** @var array<string,mixed> $vector */
        return $vector;
    }

    public function testVectorAReadFromTheVendoredContractRoutesEveryAliasedCallWithItsQueryIntact(): void
    {
        $vector = self::vectorA();
        $aliases = $vector['mtls_endpoint_aliases'];
        self::assertIsArray($aliases);
        self::assertCount(7, $aliases, 'the seven-key pin, from the vendored text');
        $issuer = $vector['issuer'];
        self::assertIsString($issuer);
        parse_str((string) parse_url((string) $vector['token_endpoint'], PHP_URL_QUERY), $topQuery);
        $tenantId = $topQuery['tenant_id'] ?? null;
        self::assertIsString($tenantId, 'vector A carries a tenant_id query');

        $requested = [];
        // The vector is abridged to the members that matter; the rest of a document this
        // SDK's discovery decoder requires is added beside it, never over it.
        $wire = $vector + [
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['EdDSA'],
            'scopes_supported' => ['openid'],
            'token_endpoint_auth_methods_supported' => ['client_secret_post', 'tls_client_auth'],
            'claims_supported' => ['sub', 'iss'],
            'grant_types_supported' => ['authorization_code', 'client_credentials'],
        ];
        $handler = function (RequestInterface $request) use ($wire, &$requested): \GuzzleHttp\Promise\PromiseInterface {
            $requested[] = (string) $request->getUri();
            $path = $request->getUri()->getPath();

            return \GuzzleHttp\Promise\Create::promiseFor($path === '/.well-known/openid-configuration'
                ? new Response(200, [], (string) json_encode($wire))
                : $this->responseFor($path));
        };
        $identity = $this->generateTestIdentity();
        $client = new AxiamClient(
            $issuer,
            self::TENANT,
            oidcClientId: 'my-app',
            oidcClientSecret: 'my-secret',
            oidcTenantId: $tenantId,
            clientCert: $identity[0],
            clientKey: $identity[1],
            transportHandler: $handler,
        );

        $client->loginClientCredentials();
        $client->introspect(new Sensitive('t'));
        $client->revoke(new Sensitive('t'));
        $client->deviceAuthorize();
        $configuration = $client->oidcDiscover();
        $request = $client->oidcBegin($configuration, 'https://app.example.com/cb');
        $client->oidcPar($request, 'https://app.example.com/cb');
        $client->cibaInitiate(new \Axiam\Sdk\Oidc\CibaInitiateRequest('openid', loginHint: 'ada'));

        // The aliased calls: the alias host, the alias path, and its query intact — one
        // tenant_id, the vector's, neither duplicated nor dropped.
        $calls = [
            'token_endpoint' => '/oauth2/token',
            'introspection_endpoint' => '/oauth2/introspect',
            'revocation_endpoint' => '/oauth2/revoke',
            'device_authorization_endpoint' => '/oauth2/device_authorization',
            'pushed_authorization_request_endpoint' => '/oauth2/par',
            'backchannel_authentication_endpoint' => '/oauth2/bc-authorize',
        ];
        foreach ($calls as $member => $path) {
            $alias = $aliases[$member];
            self::assertIsString($alias);
            $hits = array_values(array_filter($requested, static fn (string $u): bool => parse_url($u, PHP_URL_PATH) === $path));
            self::assertNotSame([], $hits, $path . ' was called');
            foreach ($hits as $hit) {
                self::assertSame(parse_url($alias, PHP_URL_HOST), parse_url($hit, PHP_URL_HOST), $path . ' went to the alias host');
                $query = (string) parse_url($hit, PHP_URL_QUERY);
                self::assertSame(1, substr_count($query, 'tenant_id='), $path . ': one tenant_id, not duplicated or dropped (' . $query . ')');
                parse_str($query, $q);
                self::assertSame($tenantId, $q['tenant_id'] ?? null, $path . ' keeps the vector\'s tenant_id');
            }
        }
        // UserInfo is aliased but never called by this SDK (§12.3 rule 5): the alias decodes verbatim.
        self::assertNotNull($configuration->mtls_endpoint_aliases);
        self::assertSame($aliases['userinfo_endpoint'], $configuration->mtls_endpoint_aliases->userinfo_endpoint);

        // Never aliased: authorization, end session, JWKS; and iss is the issuer, unchanged.
        self::assertStringStartsWith((string) $vector['authorization_endpoint'], $request->url);
        self::assertSame($vector['end_session_endpoint'], $configuration->end_session_endpoint);
        self::assertSame($vector['jwks_uri'], $configuration->jwks_uri);
        self::assertSame($issuer, $configuration->issuer);
    }
}
