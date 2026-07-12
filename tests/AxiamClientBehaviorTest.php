<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Core\NetworkError;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use PHPUnit\Framework\TestCase;

/**
 * Behavior coverage for {@see AxiamClient}'s auth/authz/error surface beyond the
 * construction + happy-path login already proven by {@see ClientConstructionTest}: the
 * org-identifier wire branches, the malformed/unexpected login-response mappings, the
 * transport-error translation ({@see NetworkError}), refresh/logout state transitions,
 * and the authz delegation methods (`checkAccess`/`can`/`batchCheck`). Everything is
 * driven through the documented `transportHandler` test seam with a `MockHandler`,
 * exactly as the rest of this suite does. Where a test needs the client to hold a live
 * access token (logout, unverified-claim decode), it seeds the shared cookie jar by
 * returning a `Set-Cookie: axiam_access=...` header from the login response — the same
 * mechanism the real server uses (§4 httpOnly cookies).
 */
final class AxiamClientBehaviorTest extends TestCase
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
     * A login 200 response that also delivers an `axiam_access` cookie, so the client
     * holds a live session token afterwards (mirrors the server's httpOnly cookie, §4).
     */
    private function loginResponseSettingToken(string $token): Response
    {
        return new Response(
            200,
            ['Set-Cookie' => 'axiam_access=' . $token . '; Path=/'],
            (string) json_encode(['user' => ['id' => 'user-1']]),
        );
    }

    /** @param array<int,Response|\Throwable> $queue */
    private function client(array $queue, ?string $orgSlug = null, ?string $orgId = null): AxiamClient
    {
        return new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            orgSlug: $orgSlug,
            orgId: $orgId,
            transportHandler: new MockHandler($queue),
        );
    }

    // --- Constructor: orgSlug / orgId are mutually exclusive ------------------------

    public function testOrgSlugAndOrgIdTogetherThrow(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new AxiamClient(self::BASE_URL, self::TENANT, orgSlug: 'acme', orgId: 'org-uuid-1');
    }

    // --- login(): org identifier wire branches -------------------------------------

    public function testLoginWithOrgIdSucceeds(): void
    {
        $client = $this->client(
            [new Response(200, [], (string) json_encode(['user' => ['id' => 'user-1']]))],
            orgId: 'org-uuid-1',
        );

        $result = $client->login('user@example.test', 'secret');

        self::assertFalse($result->mfaRequired);
        self::assertSame('user-1', $result->userId);
    }

    public function testLoginWithOrgSlugSucceeds(): void
    {
        $client = $this->client(
            [new Response(200, [], (string) json_encode(['user' => ['id' => 'user-1']]))],
            orgSlug: 'acme',
        );

        $result = $client->login('user@example.test', 'secret');

        self::assertFalse($result->mfaRequired);
    }

    // --- login(): malformed / unexpected response mappings -------------------------

    public function testLoginSuccessBodyWithoutUserIdThrowsNetworkError(): void
    {
        $client = $this->client([new Response(200, [], (string) json_encode(['user' => []]))]);

        $this->expectException(NetworkError::class);
        $client->login('user@example.test', 'secret');
    }

    public function testMfaChallengeWithoutChallengeTokenThrowsNetworkError(): void
    {
        $client = $this->client([new Response(202, [], (string) json_encode(['mfa' => 'required']))]);

        $this->expectException(NetworkError::class);
        $client->login('user@example.test', 'secret');
    }

    public function testUnexpectedSuccessStatusThrowsMappedError(): void
    {
        // 201 is a 2xx Guzzle does not throw on, but it is neither the 200 success nor
        // the 202 MFA-challenge outcome, so handleLoginResponse maps it to an error.
        $client = $this->client([new Response(201, [], (string) json_encode(['unexpected' => true]))]);

        $this->expectException(AxiamException::class);
        $client->login('user@example.test', 'secret');
    }

    // --- login(): transport-error translation --------------------------------------

    public function testLoginRequestExceptionWithoutResponseMapsToNetworkError(): void
    {
        $client = $this->client([
            new RequestException('dns failure', new Request('POST', self::BASE_URL)),
        ]);

        $this->expectException(NetworkError::class);
        $client->login('user@example.test', 'secret');
    }

    public function testLoginConnectExceptionMapsToNetworkError(): void
    {
        $client = $this->client([
            new ConnectException('connection refused', new Request('POST', self::BASE_URL)),
        ]);

        $this->expectException(NetworkError::class);
        $client->login('user@example.test', 'secret');
    }

    // --- refresh(): no token -> AuthError, no retry --------------------------------

    public function testRefreshWithoutTokenThrowsAuthError(): void
    {
        $client = $this->client([]);

        $this->expectException(AuthError::class);
        $client->refresh();
    }

    // --- logout(): session-state transitions ---------------------------------------

    public function testLogoutWithoutActiveSessionThrowsAuthError(): void
    {
        $client = $this->client([]);

        $this->expectException(AuthError::class);
        $client->logout();
    }

    public function testLogoutWithActiveSessionPostsAndClears(): void
    {
        $token = $this->unsignedJwt(['jti' => 'session-1', 'sub' => 'user-1', 'tenant_id' => self::TENANT]);
        $client = $this->client([
            $this->loginResponseSettingToken($token),
            new Response(204),
        ]);

        $result = $client->login('user@example.test', 'secret');
        self::assertFalse($result->mfaRequired);

        // Decodes the jti from the seeded token, POSTs logout, clears local state.
        $client->logout();
    }

    public function testLogoutSurfacesServerRejection(): void
    {
        $token = $this->unsignedJwt(['jti' => 'session-1', 'sub' => 'user-1']);
        $client = $this->client([
            $this->loginResponseSettingToken($token),
            // 304 is >= 300 but is not a redirect Guzzle follows and not an http-error
            // it throws on, so logout()'s own status check maps it to an error.
            new Response(304),
        ]);

        $client->login('user@example.test', 'secret');

        $this->expectException(AxiamException::class);
        $client->logout();
    }

    public function testLogoutWithNonThreePartTokenThrowsAuthError(): void
    {
        // A seeded token that cannot be decoded yields no jti -> "no active session".
        $client = $this->client([
            new Response(
                200,
                ['Set-Cookie' => 'axiam_access=not-a-jwt; Path=/'],
                (string) json_encode(['user' => ['id' => 'user-1']]),
            ),
        ]);

        $client->login('user@example.test', 'secret');

        $this->expectException(AuthError::class);
        $client->logout();
    }

    // --- authz delegation: checkAccess / can / batchCheck --------------------------

    public function testCheckAccessDelegatesToRestTransport(): void
    {
        $client = $this->client([new Response(200, [], (string) json_encode(['allowed' => true]))]);

        self::assertTrue($client->checkAccess('read', 'resource-1'));
    }

    public function testCanDelegatesToRestTransport(): void
    {
        $client = $this->client([new Response(200, [], (string) json_encode(['allowed' => false]))]);

        self::assertFalse($client->can('read', 'documents'));
    }

    public function testBatchCheckDelegatesAndPreservesOrder(): void
    {
        $client = $this->client([
            new Response(200, [], (string) json_encode([
                'results' => [['allowed' => true], ['allowed' => false]],
            ])),
        ]);

        self::assertSame(
            [true, false],
            $client->batchCheck([
                ['action' => 'read', 'resourceId' => 'r1'],
                ['action' => 'write', 'resourceId' => 'r2'],
            ]),
        );
    }
}
