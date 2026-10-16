<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract162;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\OAuthProtocolError;
use Axiam\Sdk\Oidc\MtlsEndpointAliases;
use Axiam\Sdk\Oidc\OidcConfiguration;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * The device grant authenticates its client — CONTRACT.md §14.1 rules 2 to 4, §14.2 rules 5 and
 * 8, §14.6's contract-1.62 paragraph (items (m) and (t) of §34.6).
 *
 * A client configured with a credential sends it at BOTH `device_authorize` and every
 * `device_poll`, by the rules of its other token requests: the secret as `client_secret` in the
 * form body (never `Authorization: Basic`, whichever of `client_secret_post` and
 * `client_secret_basic` the client is registered for), the §6.1 certificate on the connection. A
 * public client sends no credential at either and is not refused. The poll names its client on
 * every attempt. A `401 invalid_client` is an `OAuthProtocolError`, one request, no refresh.
 *
 * This SDK implements two credential forms, `client_secret` and mTLS. It does not implement
 * `private_key_jwt` for token requests (§21.8 is optional) or generate DPoP proofs (§21.9), so
 * the tests below assert that neither a `client_assertion` nor a `DPoP` header is ever sent.
 */
final class DeviceGrantAuthenticationTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const MTLS_URL = 'https://mtls.api.test';
    private const CLIENT_ID = 'my-device';
    private const TENANT_UUID = '22222222-2222-4222-8222-222222222222';
    private const DEVICE_CODE = 'device-code-value';

    /** @var list<array{request: RequestInterface}> */
    private array $history = [];

    protected function setUp(): void
    {
        $this->history = [];
    }

    private function configuration(string $registeredMethod = 'client_secret_post', bool $aliases = false): OidcConfiguration
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
            token_endpoint_auth_methods_supported: [$registeredMethod],
            claims_supported: ['sub'],
            grant_types_supported: ['urn:ietf:params:oauth:grant-type:device_code'],
            device_authorization_endpoint: self::BASE_URL . '/oauth2/device_authorization',
            mtls_endpoint_aliases: $aliases ? new MtlsEndpointAliases(
                token_endpoint: self::MTLS_URL . '/oauth2/token',
                device_authorization_endpoint: self::MTLS_URL . '/oauth2/device_authorization',
            ) : null,
        );
    }

    /**
     * @param list<Response> $queue
     */
    private function client(array $queue, ?string $secret = null, bool $mtls = false): AxiamClient
    {
        $stack = HandlerStack::create(new MockHandler($queue));
        $stack->push(Middleware::history($this->history));
        $identity = $mtls ? self::identity() : [null, null];

        return new AxiamClient(
            self::BASE_URL,
            'acme-tenant',
            oidcClientId: self::CLIENT_ID,
            oidcClientSecret: $secret,
            oidcTenantId: self::TENANT_UUID,
            clientCert: $identity[0],
            clientKey: $identity[1],
            transportHandler: $stack,
        );
    }

    /** @return array{0:string,1:string} a throwaway self-signed identity; nothing is committed */
    private static function identity(): array
    {
        $config = ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
        $key = openssl_pkey_new($config);
        self::assertNotFalse($key);
        $csr = openssl_csr_new(['commonName' => 'axiam-device-grant-test'], $key, $config);
        self::assertNotFalse($csr);
        $cert = openssl_csr_sign($csr, null, $key, 1, $config);
        self::assertNotFalse($cert);
        $certPem = '';
        self::assertTrue(openssl_x509_export($cert, $certPem));
        $keyPem = '';
        self::assertTrue(openssl_pkey_export($key, $keyPem, null, $config));

        return [$certPem, $keyPem];
    }

    private static function authorization(): Response
    {
        return new Response(200, [], (string) json_encode([
            'device_code' => self::DEVICE_CODE, 'user_code' => 'WDJB-MJHT',
            'verification_uri' => self::BASE_URL . '/device', 'expires_in' => 600, 'interval' => 1,
        ]));
    }

    private static function pending(): Response
    {
        return new Response(400, [], (string) json_encode(['error' => 'authorization_pending']));
    }

    private static function token(string $type = 'Bearer'): Response
    {
        return new Response(200, [], (string) json_encode([
            'access_token' => 'device-access-token', 'token_type' => $type, 'expires_in' => 900,
        ]));
    }

    private static function invalidClient(): Response
    {
        return new Response(401, [], (string) json_encode([
            'error' => 'invalid_client', 'error_description' => 'client authentication failed',
        ]));
    }

    /**
     * The form of request `$index`, decoded.
     *
     * @return array<string,string>
     */
    private function form(int $index): array
    {
        parse_str((string) $this->history[$index]['request']->getBody(), $form);

        return array_map('strval', $form);
    }

    private function assertNoOtherCredential(int $index): void
    {
        $request = $this->history[$index]['request'];
        self::assertFalse($request->hasHeader('Authorization'), 'no Authorization header (Basic or otherwise) at ' . $request->getUri()->getPath());
        self::assertFalse($request->hasHeader('DPoP'), 'this SDK generates no DPoP proof (§21.9)');
        $form = $this->form($index);
        self::assertArrayNotHasKey('client_assertion', $form);
        self::assertArrayNotHasKey('client_assertion_type', $form);
    }

    /** @return iterable<string,array{0:string}> */
    public static function registrations(): iterable
    {
        yield 'registered client_secret_post' => ['client_secret_post'];
        yield 'registered client_secret_basic' => ['client_secret_basic'];
    }

    // -- a client configured with a secret ---------------------------------------------------

    /** @dataProvider registrations */
    public function testASecretIsSentInTheBodyAtBothEndpointsAndNeverAsAuthorizationBasic(string $registered): void
    {
        $client = $this->client([self::authorization(), self::pending(), self::token()], secret: 'the-secret');
        $configuration = $this->configuration($registered);

        $authorization = $client->deviceAuthorize(configuration: $configuration);
        try {
            $client->devicePoll($authorization->deviceCode, configuration: $configuration);
            self::fail('expected authorization_pending');
        } catch (OAuthProtocolError) {
            $this->addToAssertionCount(1);
        }
        $client->devicePoll($authorization->deviceCode, configuration: $configuration);

        self::assertCount(3, $this->history);
        self::assertSame('/oauth2/device_authorization', $this->history[0]['request']->getUri()->getPath());
        foreach ([0, 1, 2] as $i) {
            self::assertSame('the-secret', $this->form($i)['client_secret'] ?? null, "request $i carries client_secret in the form body");
            self::assertSame(self::CLIENT_ID, $this->form($i)['client_id'] ?? null);
            $this->assertNoOtherCredential($i);
            self::assertStringContainsString('tenant_id=' . self::TENANT_UUID, (string) $this->history[$i]['request']->getUri(), 'tenant_id stays a query parameter');
            self::assertArrayNotHasKey('tenant_id', $this->form($i));
        }
    }

    public function testDeviceLoginSendsTheSecretAndClientIdOnEveryPoll(): void
    {
        $client = $this->client([self::authorization(), self::pending(), self::pending(), self::token()], secret: 'the-secret');
        $slept = [];

        $client->deviceLogin(
            static function (): void {
            },
            configuration: $this->configuration(),
            sleep: static function (int $seconds) use (&$slept): void {
                $slept[] = $seconds;
            },
        );

        self::assertCount(4, $this->history, 'one authorization and three polls');
        foreach ([1, 2, 3] as $poll) {
            self::assertSame('/oauth2/token', $this->history[$poll]['request']->getUri()->getPath());
            self::assertSame(self::CLIENT_ID, $this->form($poll)['client_id'] ?? null, 'every poll names its client (§14.1 rule 3)');
            self::assertSame('the-secret', $this->form($poll)['client_secret'] ?? null);
            self::assertSame(self::DEVICE_CODE, $this->form($poll)['device_code'] ?? null);
            $this->assertNoOtherCredential($poll);
        }
    }

    public function testASignedInSessionDoesNotGetItsBearerOrCookieSentToTheDeviceEndpoints(): void
    {
        $client = $this->client([
            new Response(200, ['Set-Cookie' => 'axiam_access=' . bin2hex(random_bytes(8)) . '; Path=/'], (string) json_encode(['user' => ['id' => self::TENANT_UUID]])),
            self::authorization(),
            self::token(),
        ], secret: 'the-secret');
        $client->login('admin@example.test', bin2hex(random_bytes(8)));
        $configuration = $this->configuration();

        $authorization = $client->deviceAuthorize(configuration: $configuration);
        $client->devicePoll($authorization->deviceCode, configuration: $configuration);

        foreach ([1, 2] as $i) {
            $this->assertNoOtherCredential($i);
            self::assertFalse($this->history[$i]['request']->hasHeader('X-CSRF-Token'));
        }
    }

    // -- a public client -----------------------------------------------------------------------

    public function testAPublicClientSendsClientIdAndNoCredentialAtEitherEndpointAndIsNotRefused(): void
    {
        $client = $this->client([self::authorization(), self::token()]);
        $configuration = $this->configuration('none');

        $authorization = $client->deviceAuthorize(configuration: $configuration);
        $client->devicePoll($authorization->deviceCode, configuration: $configuration);

        foreach ([0, 1] as $i) {
            self::assertSame(['client_id'], array_values(array_intersect(array_keys($this->form($i)), ['client_id', 'client_secret'])), "request $i: client_id and no client_secret");
            self::assertSame(self::CLIENT_ID, $this->form($i)['client_id']);
            $this->assertNoOtherCredential($i);
        }
    }

    // -- mTLS ----------------------------------------------------------------------------------

    public function testAnMtlsClientPresentsItsCertificateOnTheAliasedEndpointsAndSendsNoSecret(): void
    {
        $client = $this->client([self::authorization(), self::token()], mtls: true);
        $configuration = $this->configuration('tls_client_auth', aliases: true);

        $authorization = $client->deviceAuthorize(configuration: $configuration);
        $client->devicePoll($authorization->deviceCode, configuration: $configuration);

        self::assertSame(self::MTLS_URL, $this->history[0]['request']->getUri()->getScheme() . '://' . $this->history[0]['request']->getUri()->getHost(), 'the certificate goes to the host that performs the handshake (§21.3 rule 2)');
        self::assertSame(self::MTLS_URL, $this->history[1]['request']->getUri()->getScheme() . '://' . $this->history[1]['request']->getUri()->getHost());
        foreach ([0, 1] as $i) {
            self::assertSame(self::CLIENT_ID, $this->form($i)['client_id'] ?? null);
            self::assertArrayNotHasKey('client_secret', $this->form($i), 'a certificate is the credential; a secret is never invented');
            $this->assertNoOtherCredential($i);
        }
    }

    // -- 401 invalid_client --------------------------------------------------------------------------

    public function testA401InvalidClientFromDeviceAuthorizeIsAnOAuthProtocolErrorAfterOneRequestAndNoRefresh(): void
    {
        $client = $this->client([self::invalidClient()], secret: 'wrong');

        try {
            $client->deviceAuthorize(configuration: $this->configuration());
            self::fail('expected OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame('invalid_client', $e->error);
        }
        self::assertCount(1, $this->history);
        self::assertNotSame('/api/v1/auth/refresh', $this->history[0]['request']->getUri()->getPath());
    }

    public function testA401InvalidClientFromThePollIsTerminalInDeviceLoginAndMakesNoFurtherRequest(): void
    {
        $client = $this->client([self::authorization(), self::invalidClient(), self::token()], secret: 'wrong');

        try {
            $client->deviceLogin(static function (): void {
            }, configuration: $this->configuration(), sleep: static function (int $seconds): void {
            });
            self::fail('expected OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame('invalid_client', $e->error);
        }
        self::assertCount(2, $this->history, 'the authorization and exactly one poll: never retried');
        foreach ($this->history as $entry) {
            self::assertNotSame('/api/v1/auth/refresh', $entry['request']->getUri()->getPath(), 'a failed client authentication is not an expired session (§12.3 rule 3)');
        }
    }

    public function testAnUnauthorizedClientFromDeviceAuthorizeIsTheServersAnswerAsGiven(): void
    {
        $client = $this->client([new Response(400, [], (string) json_encode(['error' => 'unauthorized_client']))]);

        try {
            $client->deviceAuthorize(configuration: $this->configuration());
            self::fail('expected OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame('unauthorized_client', $e->error);
        }
    }

    // -- sender-constrained tokens -------------------------------------------------------------------

    public function testAResponseWhoseTokenTypeIsDpopIsSurfacedAsSuchAndNoProofIsEverGenerated(): void
    {
        $client = $this->client([self::authorization(), self::token('DPoP')], secret: 'the-secret');
        $configuration = $this->configuration();

        $authorization = $client->deviceAuthorize(configuration: $configuration);
        $tokens = $client->devicePoll($authorization->deviceCode, configuration: $configuration);

        self::assertSame('DPoP', $tokens->tokenType, 'token_type is read as the server wrote it (§21.7.1), never assumed to be Bearer');
        self::assertFalse($this->history[1]['request']->hasHeader('DPoP'), 'this SDK declines proof generation (§21.7.3, §21.9)');
    }
}
