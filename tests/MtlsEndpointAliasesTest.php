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
 * - only the six listed endpoints are ever aliased — not `authorization_endpoint`,
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

    /** All six aliases on the mTLS origin. @return array<string,string> */
    private function allAliases(): array
    {
        return [
            'token_endpoint' => self::MTLS_BASE_URL . '/oauth2/token',
            'userinfo_endpoint' => self::MTLS_BASE_URL . '/oauth2/userinfo',
            'revocation_endpoint' => self::MTLS_BASE_URL . '/oauth2/revoke',
            'introspection_endpoint' => self::MTLS_BASE_URL . '/oauth2/introspect',
            'device_authorization_endpoint' => self::MTLS_BASE_URL . '/oauth2/device_authorization',
            'pushed_authorization_request_endpoint' => self::MTLS_BASE_URL . '/oauth2/par',
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

        foreach (['/oauth2/token', '/oauth2/introspect', '/oauth2/revoke',
                  '/oauth2/device_authorization', '/oauth2/par'] as $path) {
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

    public function testTheAliasTypeCarriesOnlyTheSixAliasableEndpoints(): void
    {
        // Naming them as a closed set is what makes authorization_endpoint,
        // end_session_endpoint and jwks_uri unrepresentable rather than merely unused. A
        // seventh property here would be an alias the SDK could synthesise.
        $properties = array_map(
            static fn (\ReflectionProperty $p): string => $p->getName(),
            (new \ReflectionClass(MtlsEndpointAliases::class))->getProperties(),
        );
        sort($properties);

        self::assertSame([
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
}
