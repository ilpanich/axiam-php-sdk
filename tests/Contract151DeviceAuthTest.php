<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Auth\DeviceToken;
use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\NetworkError;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * `authenticateDevice()` — the mTLS device login (CONTRACT.md §6.1 rules 6-10,
 * contract 1.51): `POST /api/v1/auth/device`, no body, reachable only on a client
 * configured with a client certificate, adopting the returned token as this client's
 * credential while withholding any stale cookie, never entering the §9 refresh guard.
 */
final class Contract151DeviceAuthTest extends TestCase
{
    private const BASE_URL = 'https://axiam-device.test';
    private const TENANT = 'acme';

    /**
     * A throwaway self-signed identity — mirrors {@see ClientCertificateMtlsTest}'s
     * helper exactly (no private key or certificate is ever committed).
     *
     * @return array{0: string, 1: string}
     */
    private function generateTestIdentity(): array
    {
        if (!\function_exists('openssl_pkey_new')) {
            self::markTestSkipped('ext-openssl is required to generate the test client identity');
        }

        $config = ['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA];
        $key = openssl_pkey_new($config);
        self::assertNotFalse($key);
        $csr = openssl_csr_new(['commonName' => 'axiam-device-test'], $key, $config);
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
     * A client WITH a client certificate configured, its wire traffic recorded at the
     * bottom of the Guzzle stack — below the cookie-jar middleware, exactly where a
     * TypeScript sibling port's equivalent test was found to observe too high and pass
     * even with withholding removed. `$history` therefore reflects the REAL request as
     * it left the client, cookie header included or not.
     *
     * @param list<Response> $queue
     * @param list<array{request: RequestInterface}> $history
     */
    private function clientWithCertificate(array $queue, array &$history): AxiamClient
    {
        [$certPem, $keyPem] = $this->generateTestIdentity();

        $handler = new MockHandler($queue);
        $stack = HandlerStack::create($handler);
        $stack->push(Middleware::history($history));

        return new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            orgId: '11111111-1111-4111-8111-111111111111',
            clientCert: $certPem,
            clientKey: $keyPem,
            transportHandler: $stack,
            retryEnabled: false,
        );
    }

    private static function deviceAuthOk(string $token = 'device-tok-1', int $expiresIn = 900): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], (string) json_encode([
            'access_token' => $token,
            'token_type' => 'Bearer',
            'expires_in' => $expiresIn,
        ]));
    }

    // -----------------------------------------------------------------
    // §6.1 rule 7: reachable only with a certificate, zero wire calls otherwise
    // -----------------------------------------------------------------

    public function testUnreachableWithoutAClientCertificateAndMakesNoWireCall(): void
    {
        $handler = new MockHandler([]);
        $history = [];
        $stack = HandlerStack::create($handler);
        $stack->push(Middleware::history($history));

        $client = new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            orgId: '11111111-1111-4111-8111-111111111111',
            transportHandler: $stack,
            retryEnabled: false,
        );

        try {
            $client->authenticateDevice();
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertStringContainsString('client certificate', $e->getMessage());
        }

        self::assertSame([], $history, 'no wire call for a client-side refusal');
    }

    // -----------------------------------------------------------------
    // Happy path: no body, adopts the token, typed return
    // -----------------------------------------------------------------

    public function testSendsNoRequestBodyAndReturnsTheTypedToken(): void
    {
        $history = [];
        $client = $this->clientWithCertificate([self::deviceAuthOk('device-tok-1', 900)], $history);

        $token = $client->authenticateDevice();

        self::assertInstanceOf(DeviceToken::class, $token);
        self::assertSame('device-tok-1', $token->accessToken->reveal());
        self::assertSame('Bearer', $token->tokenType);
        self::assertSame(900, $token->expiresIn);

        self::assertCount(1, $history);
        $sent = $history[0]['request'];
        self::assertSame('/api/v1/auth/device', $sent->getUri()->getPath());
        self::assertSame('', (string) $sent->getBody(), 'no request body (§6.1 rule 6)');
    }

    /** The adopted token authenticates every later call — as Bearer, not as a cookie. */
    public function testTheAdoptedTokenAuthenticatesTheNextCall(): void
    {
        $history = [];
        $client = $this->clientWithCertificate([
            self::deviceAuthOk('device-tok-1'),
            new Response(200, ['Content-Type' => 'application/json'], '{"allowed":true}'),
        ], $history);

        $client->authenticateDevice();
        $client->checkAccess('read', 'doc-1');

        self::assertCount(2, $history);
        $checkRequest = $history[1]['request'];
        self::assertSame('Bearer device-tok-1', $checkRequest->getHeaderLine('Authorization'));
    }

    // -----------------------------------------------------------------
    // A stale cookie from an earlier session must not silently win
    // -----------------------------------------------------------------

    public function testWithholdsAStaleCookieFromAnEarlierSessionOnTheSameClient(): void
    {
        $history = [];
        $client = $this->clientWithCertificate([
            new Response(200, ['Set-Cookie' => 'axiam_access=stale-session-token; Path=/'], (string) json_encode(['user' => ['id' => 'u1']])),
            new Response(200, ['Content-Type' => 'application/json'], '{"allowed":true}'),
            self::deviceAuthOk('device-tok-1'),
            new Response(200, ['Content-Type' => 'application/json'], '{"allowed":true}'),
        ], $history);

        // An earlier cookie-sourced session exists on this client -- proved by a real
        // call that carries it, before the device login ever happens.
        $client->login('alice@example.test', 'pw');
        $client->checkAccess('read', 'doc-0');
        self::assertStringContainsString(
            'stale-session-token',
            $history[1]['request']->getHeaderLine('Cookie'),
            'sanity: the earlier session cookie really does reach the wire',
        );

        $client->authenticateDevice();
        $client->checkAccess('read', 'doc-1');

        // The request that actually left the client (below the cookie-jar middleware,
        // not a mock intercepted above it) must carry the DEVICE token, and no leftover
        // session cookie.
        $sent = $history[3]['request'];
        self::assertSame('Bearer device-tok-1', $sent->getHeaderLine('Authorization'));
        self::assertStringNotContainsString(
            'stale-session-token',
            $sent->getHeaderLine('Cookie'),
            'the stale cookie must not reach the wire once a device token is adopted',
        );
    }

    // -----------------------------------------------------------------
    // §6.1 rule 8: every refusal is 401 -> AuthError; §16: 429 is not AuthError
    // -----------------------------------------------------------------

    public function testA401IsAnAuthErrorWithTheServersMessage(): void
    {
        $history = [];
        $client = $this->clientWithCertificate([
            new Response(401, ['Content-Type' => 'application/json'], (string) json_encode(['message' => 'certificate is not bound to a service account'])),
        ], $history);

        try {
            $client->authenticateDevice();
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertStringContainsString('certificate is not bound', $e->getMessage());
        }
    }

    /** No refresh guard is ever entered — there is no refresh token to spend (§6.1 rule 6). */
    public function testA401MakesExactlyOneWireCallNeverEnteringTheRefreshGuard(): void
    {
        $history = [];
        $client = $this->clientWithCertificate([
            new Response(401, [], (string) json_encode(['message' => 'unknown certificate'])),
        ], $history);

        try {
            $client->authenticateDevice();
        } catch (AuthError) {
        }

        self::assertCount(1, $history, 'no retry, no refresh POST');
    }

    public function testA429IsNetworkErrorNotAuthErrorAndIsAttemptedOnlyOnce(): void
    {
        $history = [];
        $client = $this->clientWithCertificate([
            new Response(429, ['Retry-After' => '1'], (string) json_encode(['error' => 'rate_limit_exceeded'])),
        ], $history);

        try {
            $client->authenticateDevice();
            self::fail('expected NetworkError');
        } catch (NetworkError) {
        } catch (AuthError) {
            self::fail('a 429 must not be surfaced as AuthError');
        }

        self::assertCount(1, $history, 'a rate-limited login is not retried');
    }

    // -----------------------------------------------------------------
    // §5.2 rule 1: a device holds no LoginUserInfo — the acting-tenant gate resets
    // -----------------------------------------------------------------

    public function testResetsAnEarlierLoginsActingTenantRefusal(): void
    {
        $history = [];
        $client = $this->clientWithCertificate([
            new Response(
                200,
                ['Set-Cookie' => 'axiam_access=' . self::unsignedJwt(['tenant_id' => 't', 'org_id' => 'o']) . '; Path=/'],
                (string) json_encode(['user' => ['id' => 'u1', 'organization_level' => false]]),
            ),
            self::deviceAuthOk(),
        ], $history);

        $client->login('alice@example.test', 'pw');
        try {
            $client->actingTenant('33333333-3333-4333-8333-333333333333');
            self::fail('expected AuthzError before the device login');
        } catch (AuthzError) {
        }

        $client->authenticateDevice();

        // No exception now: authenticateDevice() reset the gate (nothing to gate on).
        $client->actingTenant('33333333-3333-4333-8333-333333333333');
        self::assertSame('33333333-3333-4333-8333-333333333333', $client->actingTenantId());
    }

    private static function unsignedJwt(array $claims): string
    {
        $segment = static fn (array $data): string => rtrim(
            strtr(base64_encode((string) json_encode($data)), '+/', '-_'),
            '=',
        );

        return $segment(['alg' => 'none', 'typ' => 'JWT']) . '.' . $segment($claims) . '.signature';
    }
}
