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
    private function clientWithCertificate(
        array $queue,
        array &$history,
        float $decisionMemoTtlMs = 0.0,
        ?string $actingTenant = null,
    ): AxiamClient {
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
            decisionMemoTtlMs: $decisionMemoTtlMs,
            actingTenant: $actingTenant,
        );
    }

    /** An unsigned but well-shaped JWT — enough for the SDK's own unverified claim reads. */
    private static function loginCookieResponse(array $user = []): Response
    {
        $token = self::unsignedJwt([
            'sub' => 'u1',
            'jti' => 'sid-1',
            'tenant_id' => '11111111-1111-4111-8111-111111111111',
            'org_id' => '11111111-1111-4111-8111-111111111111',
        ]);

        return new Response(
            200,
            [
                'Set-Cookie' => 'axiam_access=' . $token . '; Path=/',
                'Content-Type' => 'application/json',
                // Captured by Session::csrfToken() (§3) — present here so a test can
                // prove it is (or is not) echoed back on a later state-changing request.
                'X-CSRF-Token' => 'stale-csrf-from-prior-session',
            ],
            (string) json_encode(['user' => ['id' => 'u1'] + $user]),
        );
    }

    private static function checkAccessOk(): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], '{"allowed":true,"reason_code":"allowed"}');
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

    // -----------------------------------------------------------------
    // A refused device login must not destroy a working prior session
    // (CONTRACT.md §6.1 rules 6-10, §5.2 rule 1, §17)
    // -----------------------------------------------------------------

    /** The device POST itself — not just later requests — must carry no session cookie. */
    public function testTheDevicePostItselfCarriesNoCookieFromThePriorSession(): void
    {
        $history = [];
        $client = $this->clientWithCertificate([
            self::loginCookieResponse(),
            self::deviceAuthOk('device-tok-1'),
        ], $history);

        $client->login('alice@example.test', 'pw');
        $client->authenticateDevice();

        self::assertCount(2, $history);
        $deviceRequest = $history[1]['request'];
        self::assertSame('/api/v1/auth/device', $deviceRequest->getUri()->getPath());
        self::assertSame(
            '',
            $deviceRequest->getHeaderLine('Cookie'),
            'the device POST itself must carry no cookie from the prior session',
        );
    }

    /**
     * A 401 refusal must leave the prior session exactly as it was: the cookie jar
     * still holds the earlier session's cookie, the §5.2 acting-tenant gate is
     * unchanged, and the §17 decision memo is unchanged.
     *
     * Red on the unfixed code: `authenticateDevice()` calls `onCredentialChange()`,
     * `resetPrincipalScope()` and `cookieJar()->clear()` BEFORE the wire call, so all
     * three fire regardless of the response.
     */
    public function testA401LeavesCookieJarSessionScopeAndMemoUnchanged(): void
    {
        $history = [];
        $client = $this->clientWithCertificate([
            self::loginCookieResponse(['organization_level' => false]),
            self::checkAccessOk(), // memoizes ('read', 'doc-1')
            new Response(401, [], (string) json_encode(['message' => 'unknown certificate'])),
            self::checkAccessOk(), // ('read', 'doc-2') — a memo MISS, must reach the wire
        ], $history, decisionMemoTtlMs: 5000.0);

        $client->login('alice@example.test', 'pw');
        self::assertTrue($client->checkAccess('read', 'doc-1'));

        // §5.2 rule 1: organization_level=false gates the acting-tenant switch client-side.
        try {
            $client->actingTenant('33333333-3333-4333-8333-333333333333');
            self::fail('expected AuthzError before the refused device login');
        } catch (AuthzError) {
        }

        try {
            $client->authenticateDevice();
            self::fail('expected AuthError');
        } catch (AuthError) {
        }

        // The jar: a fresh (memo-missing) check must still reach the wire carrying the
        // ORIGINAL session cookie.
        self::assertTrue($client->checkAccess('read', 'doc-2'));
        self::assertCount(4, $history);
        $lastRequest = $history[3]['request'];
        self::assertStringContainsString(
            'axiam_access=',
            $lastRequest->getHeaderLine('Cookie'),
            'the prior session cookie must still reach the wire after a refused device login',
        );

        // The scope gate: unchanged by the refusal, so the same switch is refused again.
        try {
            $client->actingTenant('33333333-3333-4333-8333-333333333333');
            self::fail('expected AuthzError still — the gate must be unchanged by the refusal');
        } catch (AuthzError) {
        }

        // The memo: repeating the FIRST check makes no additional wire call.
        self::assertTrue($client->checkAccess('read', 'doc-1'));
        self::assertCount(4, $history, 'the memoized decision for doc-1 must still be served without a wire call');
    }

    /** The I3 twin of the 401 case: a 429 must be equally non-destructive. */
    public function testA429LeavesCookieJarSessionScopeAndMemoUnchanged(): void
    {
        $history = [];
        $client = $this->clientWithCertificate([
            self::loginCookieResponse(['organization_level' => false]),
            self::checkAccessOk(),
            new Response(429, ['Retry-After' => '1'], (string) json_encode(['error' => 'rate_limit_exceeded'])),
            self::checkAccessOk(),
        ], $history, decisionMemoTtlMs: 5000.0);

        $client->login('alice@example.test', 'pw');
        self::assertTrue($client->checkAccess('read', 'doc-1'));

        try {
            $client->actingTenant('33333333-3333-4333-8333-333333333333');
            self::fail('expected AuthzError before the refused device login');
        } catch (AuthzError) {
        }

        try {
            $client->authenticateDevice();
            self::fail('expected NetworkError');
        } catch (NetworkError) {
        }

        self::assertTrue($client->checkAccess('read', 'doc-2'));
        self::assertCount(4, $history);
        self::assertStringContainsString(
            'axiam_access=',
            $history[3]['request']->getHeaderLine('Cookie'),
            'the prior session cookie must still reach the wire after a 429-refused device login',
        );

        try {
            $client->actingTenant('33333333-3333-4333-8333-333333333333');
            self::fail('expected AuthzError still — the gate must be unchanged by the refusal');
        } catch (AuthzError) {
        }

        self::assertTrue($client->checkAccess('read', 'doc-1'));
        self::assertCount(4, $history, 'the memoized decision for doc-1 must still be served without a wire call');
    }

    /** The I3 twin again: a well-formed-status, malformed-body 200 is just as non-destructive. */
    public function testAMalformedTwoHundredBodyLeavesCookieJarSessionScopeAndMemoUnchanged(): void
    {
        $history = [];
        $client = $this->clientWithCertificate([
            self::loginCookieResponse(['organization_level' => false]),
            self::checkAccessOk(),
            new Response(200, ['Content-Type' => 'application/json'], '{"not_a_token_field":true}'),
            self::checkAccessOk(),
        ], $history, decisionMemoTtlMs: 5000.0);

        $client->login('alice@example.test', 'pw');
        self::assertTrue($client->checkAccess('read', 'doc-1'));

        try {
            $client->actingTenant('33333333-3333-4333-8333-333333333333');
            self::fail('expected AuthzError before the refused device login');
        } catch (AuthzError) {
        }

        try {
            $client->authenticateDevice();
            self::fail('expected NetworkError for a malformed body');
        } catch (NetworkError) {
        }

        self::assertTrue($client->checkAccess('read', 'doc-2'));
        self::assertCount(4, $history);
        self::assertStringContainsString(
            'axiam_access=',
            $history[3]['request']->getHeaderLine('Cookie'),
            'the prior session cookie must still reach the wire after a malformed-body device login',
        );

        try {
            $client->actingTenant('33333333-3333-4333-8333-333333333333');
            self::fail('expected AuthzError still — the gate must be unchanged by the refusal');
        } catch (AuthzError) {
        }

        self::assertTrue($client->checkAccess('read', 'doc-1'));
        self::assertCount(4, $history, 'the memoized decision for doc-1 must still be served without a wire call');
    }

    /**
     * The I4 twin: a SUCCESSFUL device login must still adopt the bearer token, and
     * later requests must carry it and no stale cookie — proving the fix does not
     * over-reach into withholding the reset on the path where it belongs.
     */
    public function testASuccessfulDeviceLoginStillAdoptsTheBearerAndClearsThePriorSession(): void
    {
        $history = [];
        $client = $this->clientWithCertificate([
            self::loginCookieResponse(['organization_level' => false]),
            self::checkAccessOk(), // memoizes ('read', 'doc-1') under the PRIOR subject
            self::deviceAuthOk('device-tok-1'),
            self::checkAccessOk(), // ('read', 'doc-1') again — must be a memo MISS: new subject
        ], $history, decisionMemoTtlMs: 5000.0);

        $client->login('alice@example.test', 'pw');
        self::assertTrue($client->checkAccess('read', 'doc-1'));

        $token = $client->authenticateDevice();
        self::assertSame('device-tok-1', $token->accessToken->reveal());

        // §5.2 rule 1: the gate resets to unknown — nothing to gate on for a device.
        $client->actingTenant('33333333-3333-4333-8333-333333333333');
        self::assertSame('33333333-3333-4333-8333-333333333333', $client->actingTenantId());

        // §17.1 rule 9: repeating the SAME check is a memo miss now (subject changed),
        // so it reaches the wire — and it must carry the device bearer, no stale cookie.
        self::assertTrue($client->checkAccess('read', 'doc-1'));
        self::assertCount(4, $history);
        $lastRequest = $history[3]['request'];
        self::assertSame('Bearer device-tok-1', $lastRequest->getHeaderLine('Authorization'));
        self::assertStringNotContainsString(
            'axiam_access=',
            $lastRequest->getHeaderLine('Cookie'),
            'no stale cookie once the device token is adopted',
        );
    }

    // -----------------------------------------------------------------
    // The device POST itself must carry no BEARER credential from an earlier
    // session either — AuthMiddleware attaches Authorization/X-CSRF-Token from
    // Session::accessToken()/csrfToken() to every same-origin request regardless
    // of the Cookie header, so withholding the cookie alone is not enough
    // (ilpanich/axiam-csharp-sdk#96 had the identical defect).
    // -----------------------------------------------------------------

    /**
     * A prior cookie session's access token must not ride the device POST as a
     * stale `Authorization: Bearer`, and its captured CSRF token must not ride it
     * as `X-CSRF-Token` either.
     */
    public function testTheDevicePostCarriesNoAuthorizationOrCsrfHeaderFromAPriorCookieSession(): void
    {
        $history = [];
        $client = $this->clientWithCertificate([
            self::loginCookieResponse(),
            self::deviceAuthOk('device-tok-1'),
        ], $history);

        $client->login('alice@example.test', 'pw');
        $client->authenticateDevice();

        self::assertCount(2, $history);
        $deviceRequest = $history[1]['request'];
        self::assertSame('/api/v1/auth/device', $deviceRequest->getUri()->getPath());
        self::assertFalse(
            $deviceRequest->hasHeader('Authorization'),
            'the device POST must not carry the prior cookie session\'s access token as a bearer credential',
        );
        self::assertFalse(
            $deviceRequest->hasHeader('X-CSRF-Token'),
            'the device POST must not echo the prior session\'s captured CSRF token',
        );
    }

    /**
     * The SAME defect, one call later: once a FIRST device login has adopted a
     * bearer credential, a SECOND `authenticateDevice()` call's own POST must not
     * carry that adopted token either — `Session::accessToken()` falls back to it
     * once the cookie jar is empty, and `cookieJar()->clear()`/`onCredentialChange()`
     * never touch `$adoptedAccessToken`, only `adoptBearerCredential()` overwrites
     * it (after a response). This case is also red on `origin/main`: the old
     * jar-clear-before-send order never addressed the adopted-token source either.
     */
    public function testTheDevicePostCarriesNoAuthorizationFromAnAdoptedBearerOfAnEarlierDeviceLogin(): void
    {
        $history = [];
        $client = $this->clientWithCertificate([
            self::deviceAuthOk('first-device-tok'),
            self::deviceAuthOk('second-device-tok'),
        ], $history);

        $client->authenticateDevice();
        $client->authenticateDevice();

        self::assertCount(2, $history);
        $secondDeviceRequest = $history[1]['request'];
        self::assertSame('/api/v1/auth/device', $secondDeviceRequest->getUri()->getPath());
        self::assertFalse(
            $secondDeviceRequest->hasHeader('Authorization'),
            'the second device POST must not carry the first device login\'s adopted bearer token',
        );
    }

    // -----------------------------------------------------------------
    // The I4 twin of the above: withholding session CREDENTIALS must not withhold
    // tenant ROUTING headers — CONTRACT.md §5.2 rule 1 / §5.2.2 rule 4 require
    // X-Tenant-ID and (when set) X-Axiam-Tenant on every /api/v1 request
    // regardless of session credentials.
    // -----------------------------------------------------------------

    public function testTheDevicePostStillCarriesTheTenantIdHeader(): void
    {
        $history = [];
        $client = $this->clientWithCertificate([self::deviceAuthOk()], $history);

        $client->authenticateDevice();

        self::assertCount(1, $history);
        self::assertSame(self::TENANT, $history[0]['request']->getHeaderLine('X-Tenant-ID'));
    }

    public function testTheDevicePostCarriesXAxiamTenantWhenAnActingTenantIsSetAndOmitsItOtherwise(): void
    {
        $withActing = [];
        $clientWithActing = $this->clientWithCertificate(
            [self::deviceAuthOk()],
            $withActing,
            actingTenant: '33333333-3333-4333-8333-333333333333',
        );
        $clientWithActing->authenticateDevice();
        self::assertCount(1, $withActing);
        self::assertSame(
            '33333333-3333-4333-8333-333333333333',
            $withActing[0]['request']->getHeaderLine('X-Axiam-Tenant'),
            'an acting tenant must still reach the device POST',
        );

        $withoutActing = [];
        $clientWithoutActing = $this->clientWithCertificate([self::deviceAuthOk()], $withoutActing);
        $clientWithoutActing->authenticateDevice();
        self::assertCount(1, $withoutActing);
        self::assertFalse(
            $withoutActing[0]['request']->hasHeader('X-Axiam-Tenant'),
            'no acting tenant configured means no X-Axiam-Tenant header, byte-for-byte as any other request',
        );
    }
}
