<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * Regression coverage for the H8 SDK-bench-harness fix (commit 1ee9776): a successful
 * `login()`/`verifyMfa()` MUST capture the response's `X-CSRF-Token` header onto
 * {@see \Axiam\Sdk\Session} via {@see \Axiam\Sdk\Session::captureCsrfTokenFromResponse()},
 * so that {@see \Axiam\Sdk\Session::csrfToken()} is non-null afterwards and every
 * subsequent state-changing request (`checkAccess`/`batchCheck`/`refresh`) carries the
 * `X-CSRF-Token` header {@see \Axiam\Sdk\Rest\AuthMiddleware} attaches from it.
 *
 * Before the fix, `handleLoginResponse()`'s 200 branch never called
 * `captureCsrfTokenFromResponse()`, so `Session::csrfToken()` stayed `null` for the
 * entire lifetime of a client that only ever logs in once, and every subsequent
 * mutating request omitted `X-CSRF-Token` — rejected by AXIAM's cookie double-submit
 * CSRF middleware with a 403 "Authorization denied: CSRF validation failed" that never
 * surfaces client-side as anything more specific than a mapped {@see
 * \Axiam\Sdk\Core\AxiamException} (the mock transport here never returns that 403 -- the
 * bug is INVISIBLE to the wire outcome under test unless the header itself is inspected,
 * which is exactly why this suite asserts the header directly rather than only the
 * `checkAccess`/`refresh` return value).
 *
 * Driven through the same `transportHandler` test seam every other REST test in this
 * suite uses, with a capturing wrapper around the {@see MockHandler} — mirrors
 * {@see AccessEnforcerTest}'s `clientWith()` idiom — so requests can be inspected AFTER
 * they have been fully decorated by {@see \Axiam\Sdk\Rest\AuthMiddleware} (that
 * middleware sits above the transport handler on `AxiamClient`'s internal
 * `HandlerStack`, which cannot otherwise be reached from outside the class -- `Axiam
 * \Sdk\AxiamClient` is `final` and exposes no `Session` accessor).
 */
final class CsrfCaptureAfterLoginTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';

    /** @param array<string,mixed> $claims */
    private function unsignedJwt(array $claims): string
    {
        $segment = static fn (array $data): string => rtrim(
            strtr(base64_encode((string) json_encode($data)), '+/', '-_'),
            '=',
        );

        return $segment(['alg' => 'none', 'typ' => 'JWT']) . '.' . $segment($claims) . '.signature';
    }

    /**
     * A login/verifyMfa 200 response carrying BOTH the `X-CSRF-Token` header AXIAM's
     * real server sets on a successful login (§3 non-browser CSRF capture) and a
     * `Set-Cookie: axiam_access=...` so the client also holds a live access token
     * afterwards (needed for the `refresh()` regression case below, which requires a
     * decodable `tenant_id`/`org_id` to even reach the transport).
     */
    private function loginResponseWithCsrf(string $csrfToken, ?string $accessToken = null): Response
    {
        $headers = ['X-CSRF-Token' => $csrfToken];
        if ($accessToken !== null) {
            $headers['Set-Cookie'] = 'axiam_access=' . $accessToken . '; Path=/';
        }

        return new Response(200, $headers, (string) json_encode(['user' => ['id' => 'user-1']]));
    }

    /**
     * @param list<Response|\Throwable> $queue
     * @param list<RequestInterface> $captured Populated, in order, with every request
     *        that reaches the transport (i.e. fully decorated by AuthMiddleware) —
     *        same idiom as {@see AccessEnforcerTest::clientWith()}.
     */
    private function client(array $queue, array &$captured = []): AxiamClient
    {
        $mock = new MockHandler($queue);
        $transportHandler = static function (RequestInterface $request, array $options) use ($mock, &$captured) {
            $captured[] = $request;

            return $mock($request, $options);
        };

        return new AxiamClient(self::BASE_URL, self::TENANT, transportHandler: $transportHandler);
    }

    /** Reads the private {@see \Axiam\Sdk\Session} this client owns — no public accessor exists. */
    private function sessionOf(AxiamClient $client): \Axiam\Sdk\Session
    {
        $ref = new \ReflectionProperty($client, 'session');
        $ref->setAccessible(true);
        $session = $ref->getValue($client);
        self::assertInstanceOf(\Axiam\Sdk\Session::class, $session);

        return $session;
    }

    // --- login(): Session::csrfToken() is populated from the response header --------

    public function testLoginPopulatesSessionCsrfToken(): void
    {
        $client = $this->client([$this->loginResponseWithCsrf('csrf-after-login')]);

        $client->login('user@example.test', 'secret');

        self::assertSame('csrf-after-login', $this->sessionOf($client)->csrfToken());
    }

    // --- verifyMfa(): same capture, on the OTHER caller of handleLoginResponse() ----

    public function testVerifyMfaPopulatesSessionCsrfToken(): void
    {
        $client = $this->client([
            new Response(202, [], (string) json_encode([
                'mfa_required' => true,
                'challenge_token' => 'challenge-abc',
                'available_methods' => ['totp'],
            ])),
            $this->loginResponseWithCsrf('csrf-after-mfa'),
        ]);

        $loginResult = $client->login('user@example.test', 'secret');
        self::assertTrue($loginResult->mfaRequired);
        self::assertNull($this->sessionOf($client)->csrfToken(), 'the 202 MFA challenge carries no CSRF token yet');

        $client->verifyMfa($loginResult->challengeToken, '123456');

        self::assertSame('csrf-after-mfa', $this->sessionOf($client)->csrfToken());
    }

    // --- login() -> checkAccess(): the captured token is SENT on the wire -----------

    public function testCheckAccessAfterLoginCarriesCapturedCsrfHeader(): void
    {
        $captured = [];
        $client = $this->client([
            $this->loginResponseWithCsrf('csrf-for-checkaccess'),
            new Response(200, [], (string) json_encode(['allowed' => true])),
        ], $captured);

        $client->login('user@example.test', 'secret');
        self::assertTrue($client->checkAccess('read', 'resource-1'));

        self::assertCount(2, $captured);
        self::assertSame('/api/v1/auth/login', $captured[0]->getUri()->getPath());
        self::assertFalse(
            $captured[0]->hasHeader('X-CSRF-Token'),
            'the login request itself precedes any captured token and must not carry one',
        );

        self::assertSame('/api/v1/authz/check', $captured[1]->getUri()->getPath());
        self::assertSame(
            'csrf-for-checkaccess',
            $captured[1]->getHeaderLine('X-CSRF-Token'),
            'checkAccess is a state-changing (POST) request and MUST echo the CSRF token '
                . 'captured at login, or AXIAM\'s double-submit CSRF middleware rejects it with 403',
        );
    }

    // --- login() -> batchCheck(): same wire-level guarantee, the OTHER authz call ---

    public function testBatchCheckAfterLoginCarriesCapturedCsrfHeader(): void
    {
        $captured = [];
        $client = $this->client([
            $this->loginResponseWithCsrf('csrf-for-batchcheck'),
            new Response(200, [], (string) json_encode(['results' => [['allowed' => true]]])),
        ], $captured);

        $client->login('user@example.test', 'secret');
        $client->batchCheck([['action' => 'read', 'resourceId' => 'r1']]);

        self::assertCount(2, $captured);
        self::assertSame(
            'csrf-for-batchcheck',
            $captured[1]->getHeaderLine('X-CSRF-Token'),
        );
    }

    // --- login() -> refresh(): the SAME guard's own POST also carries the header ----

    public function testRefreshAfterLoginCarriesCapturedCsrfHeader(): void
    {
        $accessToken = $this->unsignedJwt(['sub' => 'user-1', 'tenant_id' => 'tenant-uuid-1', 'org_id' => 'org-uuid-1']);

        $captured = [];
        $client = $this->client([
            $this->loginResponseWithCsrf('csrf-for-refresh', $accessToken),
            new Response(200, [], (string) json_encode(['ok' => true])),
        ], $captured);

        $client->login('user@example.test', 'secret');
        $client->refresh();

        self::assertCount(2, $captured);
        self::assertSame('/api/v1/auth/refresh', $captured[1]->getUri()->getPath());
        self::assertSame(
            'csrf-for-refresh',
            $captured[1]->getHeaderLine('X-CSRF-Token'),
            'refresh() is a state-changing (POST) request and MUST echo the CSRF token captured at login',
        );
    }
}
