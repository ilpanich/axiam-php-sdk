<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract158;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\OAuthProtocolError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Management\ValidationError;
use Axiam\Sdk\Oidc\CibaClock;
use Axiam\Sdk\Oidc\CibaDeliveryMode;
use Axiam\Sdk\Oidc\CibaInitiateRequest;
use Axiam\Sdk\Oidc\CibaInitiateResponse;
use Axiam\Sdk\Oidc\CibaRequestSigner;
use Axiam\Sdk\Oidc\CibaSigningAlg;
use Axiam\Sdk\Oidc\OidcClient;
use Axiam\Sdk\Oidc\OidcConfiguration;
use Axiam\Sdk\Oidc\SystemCibaClock;
use Axiam\Sdk\Tests\Fixtures\CibaTestClock;
use Axiam\Sdk\Tests\Fixtures\RedactionAssertions;
use Axiam\Sdk\Tests\Fixtures\RoutedHandler;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * CIBA — CONTRACT.md §33.8's sixteen required tests (t01–t16, one-to-one with the Rust
 * reference port), plus §21.3.1's discovery members. The `auth_req_id`, the notification
 * token, the client secret and every signing key are generated at run time.
 */
final class CibaTest extends TestCase
{
    use RedactionAssertions;

    private const BASE_URL = 'https://iam.example.test';
    private const CLIENT_ID = 'teller-app';
    private const TENANT_ID = '22222222-2222-4222-8222-222222222222';
    private const BC = '/oauth2/bc-authorize';
    private const TOKEN = '/oauth2/token';

    private RoutedHandler $routes;

    private string $secret;

    protected function setUp(): void
    {
        $this->routes = new RoutedHandler();
        $this->secret = self::runtimeSecret('cs-');
    }

    private static function random(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    private static function configuration(bool $withCiba = true): OidcConfiguration
    {
        return new OidcConfiguration(
            issuer: self::BASE_URL,
            authorization_endpoint: self::BASE_URL . '/oauth2/authorize',
            token_endpoint: self::BASE_URL . self::TOKEN,
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
            grant_types_supported: [OidcClient::CIBA_GRANT_TYPE],
            backchannel_authentication_endpoint: $withCiba ? self::BASE_URL . self::BC : null,
        );
    }

    private function client(bool $withSecret = true, bool $retry = false): AxiamClient
    {
        return new AxiamClient(
            self::BASE_URL,
            'acme',
            oidcClientId: self::CLIENT_ID,
            oidcClientSecret: $withSecret ? new Sensitive($this->secret) : null,
            oidcTenantId: self::TENANT_ID,
            transportHandler: $this->routes,
            retryEnabled: $retry,
        );
    }

    private static function oauthError(int $status, string $code, string $description = 'd'): Response
    {
        return RoutedHandler::json($status, ['error' => $code, 'error_description' => $description]);
    }

    /**
     * The decoded form bodies sent to `$path`.
     *
     * @return list<array<string,mixed>>
     */
    private function forms(string $path): array
    {
        return array_map(static function (RequestInterface $r): array {
            parse_str((string) $r->getBody(), $form);

            return $form;
        }, $this->routes->sent('POST', $path));
    }

    /** A token answer carrying a real, verifiable ID token, with the JWKS served. */
    private function tokensWithIdToken(): Response
    {
        $pair = sodium_crypto_sign_keypair();
        $kid = 'k-' . bin2hex(random_bytes(6));
        $x = rtrim(strtr(base64_encode(sodium_crypto_sign_publickey($pair)), '+/', '-_'), '=');
        $this->routes->on('GET', '/.well-known/openid-configuration', RoutedHandler::json(200, [
            'jwks_uri' => self::BASE_URL . '/oauth2/jwks',
        ]));
        $this->routes->on('GET', '/oauth2/jwks', RoutedHandler::json(200, ['keys' => [
            ['kty' => 'OKP', 'crv' => 'Ed25519', 'alg' => 'EdDSA', 'kid' => $kid, 'x' => $x],
        ]]));
        $now = time();
        $idToken = JWT::encode([
            'iss' => self::BASE_URL, 'aud' => self::CLIENT_ID, 'sub' => 'user-1',
            'iat' => $now, 'exp' => $now + 300, 'acr' => 'urn:axiam:acr:mfa',
        ], base64_encode(sodium_crypto_sign_secretkey($pair)), 'EdDSA', $kid);

        return RoutedHandler::json(200, [
            'access_token' => self::random(), 'token_type' => 'Bearer', 'expires_in' => 900,
            'scope' => 'openid', 'id_token' => $idToken,
        ]);
    }

    private static function initiated(int $expiresIn, int $interval, float $at): CibaInitiateResponse
    {
        return new CibaInitiateResponse(new Sensitive(self::random()), $expiresIn, $interval, $at);
    }

    /** Route the token endpoint, recording the clock's time at each request. */
    private function tokenScript(CibaTestClock $clock, Response ...$answers): \ArrayObject
    {
        $at = new \ArrayObject();
        $queue = $answers;
        $this->routes->on('POST', self::TOKEN, static function (RequestInterface $r) use ($clock, $at, &$queue): Response {
            $at[] = $clock->now;

            return count($queue) > 1 ? array_shift($queue) : $queue[0];
        });

        return $at;
    }

    private static function expectThrows(callable $call, string $type): \Throwable
    {
        try {
            $call();
        } catch (\Throwable $e) {
            self::assertInstanceOf($type, $e);

            return $e;
        }
        self::fail('expected ' . $type);
    }

    // -- 1. Redaction ----------------------------------------------------------------

    public function testT01TheValuesAreOnTheWireAndInNoRendering(): void
    {
        $notification = self::random();
        $authReqId = self::random();
        $request = new CibaInitiateRequest('openid', loginHint: 'ada', delivery: CibaDeliveryMode::Ping, clientNotificationToken: new Sensitive($notification));
        self::assertNoFragment(self::renderings($request), $notification);

        $this->routes->on('POST', self::BC, RoutedHandler::json(200, ['auth_req_id' => $authReqId, 'expires_in' => 300, 'interval' => 5]), self::oauthError(400, 'invalid_request'));
        $client = $this->client();
        $response = $client->cibaInitiate($request, configuration: self::configuration());
        self::assertNoFragment(self::renderings($response), $authReqId);
        self::assertSecretEquals($authReqId, $response->authReqId->reveal(), 'auth_req_id');
        self::assertSecretEquals($notification, $this->forms(self::BC)[0]['client_notification_token'] ?? null, 'client_notification_token');

        $e = self::expectThrows(fn () => $client->cibaInitiate($request, configuration: self::configuration()), OAuthProtocolError::class);
        self::assertNoFragment(self::renderings($e), $notification);
        self::assertNoFragment(self::renderings($e), $this->secret);
    }

    // -- 2. Client authentication is mandatory -------------------------------------

    public function testT02NoCredentialIsRefusedLocallyAndOneIsSentWithTenantInTheQuery(): void
    {
        $public = $this->client(withSecret: false);
        $e = self::expectThrows(fn () => $public->cibaInitiate(new CibaInitiateRequest('openid', loginHint: 'ada'), configuration: self::configuration()), AuthError::class);
        self::assertStringContainsString('§33.1', $e->getMessage());
        self::expectThrows(fn () => $public->cibaPoll(new Sensitive(self::random()), configuration: self::configuration()), AuthError::class);
        self::assertSame([], $this->routes->requests, 'no request');

        $this->routes->on('POST', self::BC, RoutedHandler::json(200, ['auth_req_id' => self::random(), 'expires_in' => 300]));
        $this->routes->on('POST', self::TOKEN, self::oauthError(400, 'authorization_pending'));
        $client = $this->client();
        $client->cibaInitiate(new CibaInitiateRequest('openid', loginHint: 'ada'), configuration: self::configuration());
        self::expectThrows(fn () => $client->cibaPoll(new Sensitive(self::random()), configuration: self::configuration()), OAuthProtocolError::class);

        foreach ([self::BC, self::TOKEN] as $path) {
            $sent = $this->routes->sent('POST', $path)[0];
            parse_str((string) $sent->getBody(), $form);
            self::assertSame(self::CLIENT_ID, $form['client_id']);
            self::assertSecretEquals($this->secret, $form['client_secret'] ?? null, 'client_secret');
            self::assertArrayNotHasKey('tenant_id', $form, 'never a body field');
            self::assertSame('tenant_id=' . self::TENANT_ID, $sent->getUri()->getQuery());
            self::assertSame('acme', $sent->getHeaderLine('X-Tenant-ID'));
            self::assertSame('', $sent->getHeaderLine('Authorization'), 'no bearer on /oauth2/*');
        }
    }

    public function testT02AnMtlsOnlyClientSendsTheClientIdOnly(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($key);
        $csr = openssl_csr_new(['commonName' => 'ciba-mtls-test'], $key);
        self::assertNotFalse($csr);
        $cert = openssl_csr_sign($csr, null, $key, 1);
        self::assertNotFalse($cert);
        openssl_x509_export($cert, $certPem);
        openssl_pkey_export($key, $keyPem);
        $client = new AxiamClient(
            self::BASE_URL,
            'acme',
            clientCert: $certPem,
            clientKey: $keyPem,
            oidcClientId: self::CLIENT_ID,
            oidcTenantId: self::TENANT_ID,
            transportHandler: $this->routes,
        );
        $this->routes->on('POST', self::BC, RoutedHandler::json(200, ['auth_req_id' => self::random(), 'expires_in' => 300]));
        $client->cibaInitiate(new CibaInitiateRequest('openid', loginHint: 'ada'), configuration: self::configuration());

        $form = $this->forms(self::BC)[0];
        self::assertSame(self::CLIENT_ID, $form['client_id']);
        self::assertArrayNotHasKey('client_secret', $form);
    }

    // -- 3. The initiate request ---------------------------------------------------

    public function testT03ExactlyTheMembersSetAreSent(): void
    {
        $this->routes->on('POST', self::BC, RoutedHandler::json(200, ['auth_req_id' => self::random(), 'expires_in' => 300]));
        $client = $this->client();
        $token = self::random();
        $client->cibaInitiate(new CibaInitiateRequest('openid', loginHint: 'ada'), configuration: self::configuration());
        $client->cibaInitiate(new CibaInitiateRequest(
            'openid profile',
            idTokenHint: 'an.id.token',
            bindingMessage: 'W4SCT',
            requestedExpiry: 120,
            acrValues: 'urn:axiam:acr:mfa',
            resource: 'https://api.example.test',
            delivery: CibaDeliveryMode::Ping,
            clientNotificationToken: new Sensitive($token),
        ), configuration: self::configuration());

        [$first, $second] = $this->forms(self::BC);
        $keys = array_keys($first);
        sort($keys);
        self::assertSame(['client_id', 'client_secret', 'login_hint', 'scope'], $keys);
        $keys = array_keys($second);
        sort($keys);
        self::assertSame(['acr_values', 'binding_message', 'client_id', 'client_notification_token', 'client_secret',
            'id_token_hint', 'requested_expiry', 'resource', 'scope'], $keys);
        self::assertSame('120', $second['requested_expiry'], 'a string on the form');
        self::assertStringStartsWith('application/x-www-form-urlencoded', $this->routes->sent('POST', self::BC)[0]->getHeaderLine('Content-Type'));
        foreach (['login_hint_token', 'user_code', 'request_uri'] as $forbidden) {
            self::assertArrayNotHasKey($forbidden, $second);
        }
        $parameters = array_map(
            static fn (\ReflectionParameter $p): string => $p->getName(),
            (new \ReflectionMethod(CibaInitiateRequest::class, '__construct'))->getParameters(),
        );
        foreach (['loginHintToken', 'userCode', 'requestUri'] as $absent) {
            self::assertNotContains($absent, $parameters, $absent . ' cannot be set');
        }

        foreach ([
            fn () => new CibaInitiateRequest('openid', loginHint: 'ada', idTokenHint: 'x'),
            fn () => new CibaInitiateRequest('openid'),
            fn () => new CibaInitiateRequest('openid', loginHint: 'ada', delivery: CibaDeliveryMode::Ping),
            fn () => new CibaInitiateRequest('openid', loginHint: 'ada', delivery: CibaDeliveryMode::Ping, clientNotificationToken: new Sensitive('')),
            fn () => new CibaInitiateRequest('openid', loginHint: 'ada', clientNotificationToken: new Sensitive($token)),
        ] as $refused) {
            self::expectThrows($refused, ValidationError::class);
        }
        self::assertCount(2, $this->routes->requests, 'the refused requests sent nothing');
    }

    // -- 4. No retry on initiate ---------------------------------------------------

    public function testT04InitiateIsSentOnceOn503And429AndADroppedConnection(): void
    {
        $client = $this->client(retry: true);
        $request = new CibaInitiateRequest('openid', loginHint: 'ada');
        $this->routes->on('POST', self::BC, new Response(503));
        self::assertNotInstanceOf(ValidationError::class, self::expectThrows(fn () => $client->cibaInitiate($request, configuration: self::configuration()), NetworkError::class));
        self::assertCount(1, $this->routes->sent('POST', self::BC));

        $this->routes->on('POST', self::BC, self::oauthError(429, 'rate_limit_exceeded'));
        $e = self::expectThrows(fn () => $client->cibaInitiate($request, configuration: self::configuration()), OAuthProtocolError::class);
        self::assertSame('rate_limit_exceeded', $e->error);
        self::assertCount(2, $this->routes->sent('POST', self::BC));

        $this->routes->on('POST', self::BC, new ConnectException('connection reset by peer', new Request('POST', self::BC)));
        self::expectThrows(fn () => $client->cibaInitiate($request, configuration: self::configuration()), NetworkError::class);
        self::assertCount(3, $this->routes->sent('POST', self::BC), 'one connection, no retry');
    }

    // -- 5. Poll outcomes ------------------------------------------------------------

    public function testT05PendingLoopsSlowDownPersistsAndTheTerminalAnswersAreDistinct(): void
    {
        $clock = new CibaTestClock();
        $tokens = $this->tokensWithIdToken();
        $this->tokenScript($clock, self::oauthError(400, 'slow_down'), self::oauthError(400, 'slow_down'), self::oauthError(400, 'authorization_pending'), $tokens);
        $initiated = self::initiated(600, 5, $clock->now);

        $set = $this->client()->cibaAwait($initiated, configuration: self::configuration(), clock: $clock);
        self::assertNotNull($set->idClaims);
        self::assertSame([5, 10, 15, 15], $clock->sleeps, '+5 s twice, and pending lowers nothing');
        foreach ($this->forms(self::TOKEN) as $form) {
            self::assertSame(OidcClient::CIBA_GRANT_TYPE, $form['grant_type']);
            self::assertSecretEquals($initiated->authReqId->reveal(), $form['auth_req_id'] ?? null, 'auth_req_id');
        }

        foreach ([
            'access_denied' => static fn (OAuthProtocolError $e): bool => $e->isAccessDenied() && !$e->isExpiredToken(),
            'expired_token' => static fn (OAuthProtocolError $e): bool => $e->isExpiredToken() && !$e->isAccessDenied(),
            'invalid_grant' => static fn (OAuthProtocolError $e): bool => $e->error === 'invalid_grant',
            'a_code_nobody_defined' => static fn (OAuthProtocolError $e): bool => $e->error === 'a_code_nobody_defined',
        ] as $code => $check) {
            $this->routes = new RoutedHandler();
            $clock = new CibaTestClock();
            $this->tokenScript($clock, self::oauthError(400, $code));
            $e = self::expectThrows(fn () => $this->client()->cibaAwait(self::initiated(600, 5, $clock->now), configuration: self::configuration(), clock: $clock), OAuthProtocolError::class);
            self::assertTrue($check($e), $code);
            self::assertCount(1, $this->routes->sent('POST', self::TOKEN), $code . ' is terminal');
        }
    }

    // -- 6. The first poll waits ---------------------------------------------------

    public function testT06TheFirstPollWaitsTheIntervalOrFiveSeconds(): void
    {
        foreach ([[7, 7], [null, 5], [0, 5]] as [$intervalInResponse, $expected]) {
            $this->routes = new RoutedHandler();
            $clock = new CibaTestClock();
            $body = ['auth_req_id' => self::random(), 'expires_in' => 300];
            if ($intervalInResponse !== null) {
                $body['interval'] = $intervalInResponse;
            }
            $this->routes->on('POST', self::BC, RoutedHandler::json(200, $body));
            $at = $this->tokenScript($clock, self::oauthError(400, 'access_denied'));
            $client = $this->client();

            $response = $client->cibaInitiate(new CibaInitiateRequest('openid', loginHint: 'ada'), configuration: self::configuration(), clock: $clock);
            self::assertSame($expected, $response->interval);
            self::assertSame($clock->now, $response->receivedAt);
            try {
                $client->cibaAwait($response, configuration: self::configuration(), clock: $clock);
            } catch (OAuthProtocolError) {
            }
            self::assertSame(1000.0 + $expected, $at[0], 'the first poll is not sent before the interval');
        }
    }

    // -- 7. Deadline -------------------------------------------------------------------

    public function testT07NoRequestAfterExpiresInAndExpiredTokenIsRaisedLocally(): void
    {
        $clock = new CibaTestClock();
        $at = $this->tokenScript($clock, self::oauthError(400, 'authorization_pending'));
        $e = self::expectThrows(fn () => $this->client()->cibaAwait(self::initiated(12, 5, $clock->now), configuration: self::configuration(), clock: $clock), OAuthProtocolError::class);
        self::assertTrue($e->isExpiredToken());
        self::assertStringContainsString('§33.7 rule 4', $e->getMessage());
        self::assertSame([1005.0, 1010.0], $at->getArrayCopy(), 'nothing at 15 s, past the 12 s deadline');
    }

    // -- 8. Transient failure is not terminal --------------------------------------

    public function testT08A500AndA429MidLoopAreSurvived(): void
    {
        $clock = new CibaTestClock();
        $tokens = $this->tokensWithIdToken();
        // Contract 1.59 (§34.2 P8): the 500 carries the body AXIAM's token endpoint sends,
        // {"error":"server_error"}, and a 503 temporarily_unavailable is the same kind of
        // answer — a 5xx on ciba_poll is transient whatever its body.
        $this->tokenScript(
            $clock,
            self::oauthError(400, 'authorization_pending'),
            self::oauthError(500, 'server_error'),
            self::oauthError(429, 'rate_limit_exceeded'),
            new Response(429),
            self::oauthError(503, 'temporarily_unavailable'),
            $tokens,
        );

        $set = $this->client()->cibaAwait(self::initiated(600, 5, $clock->now), configuration: self::configuration(), clock: $clock);
        self::assertNotSame('', $set->accessToken->reveal());
        self::assertNotNull($set->idToken);
        self::assertNotNull($set->idClaims);
        self::assertSame('urn:axiam:acr:mfa', $set->idClaims['acr'] ?? null);
        self::assertCount(6, $this->routes->sent('POST', self::TOKEN));
    }

    public function testT08ABodiless4xxIsTerminalAndAPollRetriesTransientFailures(): void
    {
        $clock = new CibaTestClock();
        $this->tokenScript($clock, new Response(400));
        self::expectThrows(fn () => $this->client()->cibaAwait(self::initiated(600, 5, $clock->now), configuration: self::configuration(), clock: $clock), NetworkError::class);
        self::assertCount(1, $this->routes->sent('POST', self::TOKEN), 'an answer, not a fault');

        // Within one cibaPoll, §16 retries a 5xx (retry enabled) but never a protocol answer.
        $this->routes = new RoutedHandler();
        $this->routes->on('POST', self::TOKEN, new Response(503), self::oauthError(400, 'authorization_pending'));
        self::expectThrows(fn () => $this->client(retry: true)->cibaPoll(new Sensitive(self::random()), configuration: self::configuration()), OAuthProtocolError::class);
        self::assertCount(2, $this->routes->sent('POST', self::TOKEN));
    }

    // -- 9. Single use ---------------------------------------------------------------

    public function testT09ASecondRedemptionIsInvalidGrantAndNotRetried(): void
    {
        $this->routes->on('POST', self::TOKEN, $this->tokensWithIdToken(), self::oauthError(400, 'invalid_grant'));
        $client = $this->client(retry: true);
        $id = new Sensitive(self::random());
        $client->cibaPoll($id, configuration: self::configuration());
        $e = self::expectThrows(fn () => $client->cibaPoll($id, configuration: self::configuration()), OAuthProtocolError::class);
        self::assertSame('invalid_grant', $e->error);
        self::assertCount(2, $this->routes->sent('POST', self::TOKEN), 'no retry of the second');
    }

    // -- 10–13. The ping -----------------------------------------------------------

    public function testT10AValidPingReturnsItsAuthReqIdInAnySchemeCase(): void
    {
        $token = self::random();
        $id = self::random();
        foreach (['Bearer', 'bearer', 'BEARER', 'BeArEr'] as $scheme) {
            foreach ([
                ['Authorization' => $scheme . ' ' . $token],
                ['authorization' => [$scheme . ' ' . $token], 'Content-Type' => ['application/json']],
            ] as $headers) {
                $got = $this->client()->cibaHandlePing($headers, (string) json_encode(['auth_req_id' => $id]), new Sensitive($token));
                self::assertSecretEquals($id, $got->reveal(), 'auth_req_id');
                self::assertNoFragment(self::renderings($got), $id);
            }
        }
    }

    public function testT11AWrongAbsentEmptyDuplicateOrBasicAuthorizationIsRefused(): void
    {
        $token = self::random();
        $body = (string) json_encode(['auth_req_id' => self::random()]);
        $lastDiffers = substr($token, 0, -1) . (str_ends_with($token, 'A') ? 'B' : 'A');
        foreach ([
            ['Authorization' => 'Bearer ' . self::random()],
            [],
            ['Content-Type' => 'application/json'],
            ['Authorization' => ''],
            ['Authorization' => 'Bearer '],
            ['Authorization' => 'Bearer'],
            ['Authorization' => ['Bearer ' . $token, 'Bearer ' . $token]],
            ['Authorization' => 'Bearer ' . $token, 'authorization' => 'Bearer ' . $token],
            ['Authorization' => 'Basic ' . base64_encode(self::CLIENT_ID . ':' . $token)],
            ['Authorization' => 'Bearer ' . $lastDiffers],
            ['Authorization' => 'Bearer  ' . $token],
            ['Authorization' => 'Bearer ' . $token . ' '],
        ] as $i => $headers) {
            $e = self::expectThrows(fn () => OidcClient::cibaHandlePing($headers, $body, new Sensitive($token)), AuthError::class);
            self::assertNotInstanceOf(OAuthProtocolError::class, $e);
            self::assertNoFragment(self::renderings($e), $token);
            self::assertSame('ciba ping refused: the Authorization header is not the expected bearer (CONTRACT.md §33.1)', $e->getMessage(), 'case ' . $i);
        }
        self::expectThrows(fn () => OidcClient::cibaHandlePing(['Authorization' => 'Bearer x'], $body, new Sensitive('')), AuthError::class);

        // No timing harness in PHP: §33.8 test 11 is asserted structurally — the token is
        // compared with hash_equals(), the language's constant-time comparison.
        $source = (string) file_get_contents((string) (new \ReflectionClass(OidcClient::class))->getFileName());
        self::assertStringContainsString('hash_equals($expected, $presented)', $source);
    }

    public function testT12AMalformedBodyIsAValidationErrorAndExtrasAreIgnored(): void
    {
        $token = self::random();
        $headers = ['Authorization' => 'Bearer ' . $token];
        foreach (['not json', '[]', '"x"', '{}', '{"auth_req_id":""}', '{"auth_req_id":7}', '{"auth_req_id":null}'] as $body) {
            self::expectThrows(fn () => OidcClient::cibaHandlePing($headers, $body, new Sensitive($token)), ValidationError::class);
        }
        $id = self::random();
        $got = OidcClient::cibaHandlePing($headers, (string) json_encode(['auth_req_id' => $id, 'status' => 'approved', 'extra' => [1]]), new Sensitive($token));
        self::assertSecretEquals($id, $got->reveal(), 'auth_req_id');
    }

    public function testT13ThePingHelperMakesNoNetworkCall(): void
    {
        $token = self::random();
        $client = $this->client();
        $client->cibaHandlePing(['Authorization' => 'Bearer ' . $token], '{"auth_req_id":"x"}', new Sensitive($token));
        try {
            $client->cibaHandlePing([], '{}', new Sensitive($token));
        } catch (AuthError) {
        }
        self::assertSame([], $this->routes->requests, 'the transport was never touched');
    }

    // -- 14–16. The signed form ----------------------------------------------------

    /** @return array{0: string, 1: string} [PKCS#8 PEM, base64 public key] */
    private static function ed25519Pem(): array
    {
        $seed = random_bytes(32);
        $der = (string) hex2bin('302e020100300506032b657004220420') . $seed;
        $pem = "-----BEGIN PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PRIVATE KEY-----\n";

        return [$pem, base64_encode(sodium_crypto_sign_publickey(sodium_crypto_sign_seed_keypair($seed)))];
    }

    /** @return array{0: string, 1: string} [private PEM, public PEM] */
    private static function p256Pem(): array
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        self::assertNotFalse($key);
        openssl_pkey_export($key, $pem);
        $details = openssl_pkey_get_details($key);
        self::assertIsArray($details);

        return [$pem, $details['key']];
    }

    public function testT14TheSignedRequestIsOneMemberWithTheRegisteredAlgAndAFreshJti(): void
    {
        $this->routes->on('POST', self::BC, RoutedHandler::json(200, ['auth_req_id' => self::random(), 'expires_in' => 300]));
        $client = $this->client();
        [$pem, $public] = self::ed25519Pem();
        $notification = self::random();
        $signer = CibaRequestSigner::fromPem(CibaSigningAlg::EdDSA, new Sensitive($pem), 'client-key-1');
        self::assertSame(CibaSigningAlg::EdDSA, $signer->alg);
        $request = new CibaInitiateRequest(
            'openid',
            loginHint: 'ada',
            bindingMessage: 'W4SCT',
            requestedExpiry: 90,
            delivery: CibaDeliveryMode::Ping,
            clientNotificationToken: new Sensitive($notification),
            signer: $signer,
        );
        $client->cibaInitiate($request, configuration: self::configuration());
        $client->cibaInitiate($request, configuration: self::configuration());

        $jtis = [];
        foreach ($this->forms(self::BC) as $form) {
            $keys = array_keys($form);
            sort($keys);
            self::assertSame(['client_id', 'client_secret', 'request'], $keys, 'exactly request beside client authentication');
            $jws = (string) $form['request'];
            $header = json_decode((string) base64_decode(strtr(explode('.', $jws)[0], '-_', '+/')), true);
            self::assertIsArray($header);
            self::assertSame('EdDSA', $header['alg']);
            self::assertSame('client-key-1', $header['kid']);
            $claims = (array) JWT::decode($jws, new Key($public, 'EdDSA'));
            self::assertSame(self::CLIENT_ID, $claims['iss']);
            self::assertSame(self::BASE_URL, $claims['aud']);
            self::assertIsInt($claims['iat']);
            self::assertSame($claims['iat'], $claims['nbf']);
            self::assertTrue($claims['exp'] > $claims['nbf'] && $claims['exp'] - $claims['nbf'] <= 3600);
            self::assertSame('ada', $claims['login_hint']);
            self::assertSame('W4SCT', $claims['binding_message']);
            self::assertSame(90, $claims['requested_expiry'], 'a number inside the JWT');
            self::assertSecretEquals($notification, $claims['client_notification_token'] ?? null, 'client_notification_token');
            self::assertSame(32, strlen((string) $claims['jti']), '128 bits, hex');
            $jtis[] = $claims['jti'];
        }
        self::assertNotSame($jtis[0], $jtis[1], 'a fresh jti per request');

        // ES256 too.
        [$ecPem, $ecPublic] = self::p256Pem();
        $es = CibaRequestSigner::fromPem(CibaSigningAlg::ES256, new Sensitive($ecPem));
        $client->cibaInitiate(new CibaInitiateRequest('openid', loginHint: 'ada', signer: $es), configuration: self::configuration());
        $last = (string) $this->forms(self::BC)[2]['request'];
        $claims = (array) JWT::decode($last, new Key($ecPublic, 'ES256'));
        self::assertSame(self::CLIENT_ID, $claims['iss']);
        self::assertArrayNotHasKey('kid', (array) json_decode((string) base64_decode(strtr(explode('.', $last)[0], '-_', '+/')), true));
    }

    public function testT15NoKeyOrAKeyForAnotherAlgIsRefusedBeforeAnyRequest(): void
    {
        [$edPem] = self::ed25519Pem();
        [$ecPem] = self::p256Pem();
        $rsa = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($rsa);
        openssl_pkey_export($rsa, $rsaPem);
        foreach ([
            [CibaSigningAlg::EdDSA, ''],
            [CibaSigningAlg::ES256, ''],
            [CibaSigningAlg::EdDSA, $ecPem],
            [CibaSigningAlg::ES256, $edPem],
            [CibaSigningAlg::ES256, $rsaPem],
            [CibaSigningAlg::ES256, "-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----\n"],
            [CibaSigningAlg::PS256, $rsaPem],
        ] as [$alg, $pem]) {
            $e = self::expectThrows(fn () => CibaRequestSigner::fromPem($alg, new Sensitive($pem)), ValidationError::class);
            self::assertStringContainsString('§33.2', $e->getMessage());
        }
        self::assertSame([], $this->routes->requests);
        // No defaulting: a signer is built from an algorithm AND a key, both required —
        // and the request carries nothing but the signer to mix a form parameter into.
        $parameters = (new \ReflectionMethod(CibaRequestSigner::class, 'fromPem'))->getParameters();
        self::assertFalse($parameters[0]->isOptional());
        self::assertFalse($parameters[1]->isOptional());
    }

    public function testT16TheKeyAndTheRequestAppearInNoRendering(): void
    {
        [$pem] = self::ed25519Pem();
        $keyBody = trim(explode("\n", $pem)[1]);
        $signer = CibaRequestSigner::fromPem(CibaSigningAlg::EdDSA, new Sensitive($pem));
        $request = new CibaInitiateRequest('openid', loginHint: 'ada', signer: $signer);
        foreach ([$signer, $request] as $value) {
            self::assertNoFragment(self::renderings($value), $keyBody);
        }
        self::assertSame('{"alg":"EdDSA","kid":null,"key":"[SENSITIVE]"}', (string) json_encode($signer));

        $this->routes->on('POST', self::BC, self::oauthError(400, 'invalid_request', 'request object refused'));
        $e = self::expectThrows(fn () => $this->client()->cibaInitiate($request, configuration: self::configuration()), OAuthProtocolError::class);
        $sent = (string) $this->forms(self::BC)[0]['request'];
        self::assertNoFragment(self::renderings($e), $sent);
        self::assertNoFragment(self::renderings($e), $keyBody);
        self::assertSame('request object refused', $e->errorDescription);
    }

    // -- discovery, endpoint and clock -------------------------------------------------

    public function testTheFourCibaDiscoveryMembersDecodeAndAServerWithoutCibaIsRefused(): void
    {
        $this->routes->on('GET', '/.well-known/openid-configuration', RoutedHandler::json(200, [
            'issuer' => self::BASE_URL,
            'authorization_endpoint' => self::BASE_URL . '/oauth2/authorize',
            'token_endpoint' => self::BASE_URL . self::TOKEN,
            'userinfo_endpoint' => self::BASE_URL . '/oauth2/userinfo',
            'jwks_uri' => self::BASE_URL . '/oauth2/jwks',
            'revocation_endpoint' => self::BASE_URL . '/oauth2/revoke',
            'introspection_endpoint' => self::BASE_URL . '/oauth2/introspect',
            'response_types_supported' => ['code'], 'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['EdDSA'], 'scopes_supported' => ['openid'],
            'token_endpoint_auth_methods_supported' => ['client_secret_post'], 'claims_supported' => ['sub'],
            'grant_types_supported' => [OidcClient::CIBA_GRANT_TYPE],
            'backchannel_authentication_endpoint' => self::BASE_URL . self::BC,
            'backchannel_token_delivery_modes_supported' => ['poll', 'ping'],
            'backchannel_user_code_parameter_supported' => false,
            'backchannel_authentication_request_signing_alg_values_supported' => ['PS256', 'ES256', 'EdDSA'],
        ]));
        $this->routes->on('POST', self::BC, RoutedHandler::json(200, ['auth_req_id' => self::random(), 'expires_in' => 300]));
        $client = $this->client();
        $configuration = $client->oidcDiscover();
        self::assertSame(self::BASE_URL . self::BC, $configuration->backchannel_authentication_endpoint);
        self::assertSame(['poll', 'ping'], $configuration->backchannel_token_delivery_modes_supported);
        self::assertFalse($configuration->backchannel_user_code_parameter_supported);
        self::assertSame(['PS256', 'ES256', 'EdDSA'], $configuration->backchannel_authentication_request_signing_alg_values_supported);
        $client->cibaInitiate(new CibaInitiateRequest('openid', loginHint: 'ada'));
        self::assertCount(1, $this->routes->sent('POST', self::BC), 'the discovered endpoint is used');

        $e = self::expectThrows(fn () => $client->cibaInitiate(new CibaInitiateRequest('openid', loginHint: 'ada'), configuration: self::configuration(withCiba: false)), AuthError::class);
        self::assertStringContainsString('does not support CIBA', $e->getMessage());
        self::assertCount(1, $this->routes->sent('POST', self::BC), 'never a synthesised URL');
    }

    public function testAMalformedInitiateResponseIsANetworkErrorAndAClosedClientRefuses(): void
    {
        $this->routes->on('POST', self::BC, RoutedHandler::json(200, ['expires_in' => 300]));
        $client = $this->client();
        self::expectThrows(fn () => $client->cibaInitiate(new CibaInitiateRequest('openid', loginHint: 'ada'), configuration: self::configuration()), NetworkError::class);
        $client->close();
        self::expectThrows(fn () => $client->cibaPoll(new Sensitive(self::random()), configuration: self::configuration()), NetworkError::class);
        self::expectThrows(fn () => $client->cibaAwait(self::initiated(60, 5, 0.0), configuration: self::configuration()), NetworkError::class);
        self::expectThrows(fn () => $client->cibaInitiate(new CibaInitiateRequest('openid', loginHint: 'ada'), configuration: self::configuration()), NetworkError::class);
    }

    public function testTheSystemClockSleepsAndReadsTheTime(): void
    {
        $clock = new SystemCibaClock();
        $before = $clock->now();
        $clock->sleep(0);
        self::assertGreaterThanOrEqual($before, $clock->now());
        self::assertEqualsWithDelta(microtime(true), $clock->now(), 5.0);
    }

    public function testAwaitWithTheDefaultClockStopsAtAnAlreadyPassedDeadline(): void
    {
        $e = self::expectThrows(fn () => $this->client()->cibaAwait(self::initiated(1, 5, microtime(true)), configuration: self::configuration()), OAuthProtocolError::class);
        self::assertTrue($e->isExpiredToken());
        self::assertSame([], $this->routes->requests);
    }
}
