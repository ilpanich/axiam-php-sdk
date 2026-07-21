<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AuthzDispatcher;
use Axiam\Sdk\Auth\UserInfo;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Grpc\Gen\GetUserInfoResponse;
use Axiam\Sdk\Rest\AuthzRestClient;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use PHPUnit\Framework\TestCase;

/**
 * Unit-tests {@see AuthzDispatcher}'s new gRPC-only `getUserInfo` orchestration
 * (CONTRACT.md §1.1, contract 1.3) WITHOUT the `ext-grpc` PECL extension — which is
 * genuinely absent in this sandbox ({@see AuthzDispatcherFallbackTest} asserts
 * `extension_loaded('grpc')` is false). This mirrors the split the existing suite already
 * uses: the wire transport ({@see \Axiam\Sdk\Grpc\UserInfoGrpcClient}) is exercised against
 * `\Grpc\*` doubles in {@see GrpcUserInfoClientTest}, while the dispatcher's own
 * precondition / gRPC-only / claim-mapping / refresh-retry logic is exercised here through
 * seams that do not need the extension.
 *
 * The claim-mapping ({@see AuthzDispatcher::toUserInfo()}) and refresh-retry
 * ({@see AuthzDispatcher::getUserInfoWithRefreshRetry()}) helpers are invoked via reflection
 * — the same technique {@see GrpcAuthzClientTest} uses to drive `unary()` — because the
 * public `getUserInfo()` short-circuits to a {@see NetworkError} on this extension-less
 * runtime (§1.1.6: gRPC-only, no REST fallback) before it can reach them.
 */
final class UserInfoDispatcherTest extends TestCase
{
    /** A dispatcher whose REST client is never actually called by these gRPC-path tests. */
    private function makeDispatcher(
        mixed $tokenAccessor = null,
        mixed $refreshAccessor = null,
        bool $restOnly = false,
    ): AuthzDispatcher {
        $http = new Client(['handler' => HandlerStack::create(new MockHandler([]))]);

        return new AuthzDispatcher(
            restClient: new AuthzRestClient($http),
            restOnly: $restOnly,
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: $tokenAccessor,
            refreshAccessor: $refreshAccessor,
        );
    }

    /** @return mixed the return value of the invoked private method */
    private function invokePrivate(AuthzDispatcher $dispatcher, string $method, mixed ...$args): mixed
    {
        $ref = new \ReflectionMethod($dispatcher, $method);
        $ref->setAccessible(true);

        return $ref->invoke($dispatcher, ...$args);
    }

    // --- §1.1.3 precondition: no token -> AuthError, client-side, no wire call ----------

    public function testGetUserInfoWithoutTokenRaisesAuthErrorAndMakesNoWireCall(): void
    {
        // tokenAccessor returns null -> the precondition fires before any transport work.
        $dispatcher = $this->makeDispatcher(tokenAccessor: static fn (): ?string => null);

        $this->expectException(AuthError::class);
        $this->expectExceptionMessage('prior successful login');
        $dispatcher->getUserInfo();
    }

    // --- §1.1.6 gRPC-only: no REST /oauth2/userinfo substitution -----------------------

    public function testGetUserInfoIsGrpcOnlyAndRaisesNetworkErrorWithoutTheExtension(): void
    {
        self::assertFalse(
            extension_loaded('grpc'),
            'this test only proves what it claims when the grpc extension is genuinely absent',
        );

        // A valid token is present, so the precondition passes; the gRPC-only guard then
        // refuses to fall back to REST (§1.1.6) on this extension-less runtime.
        $dispatcher = $this->makeDispatcher(tokenAccessor: static fn (): ?string => 'tok');

        $this->expectException(NetworkError::class);
        $this->expectExceptionMessage('getUserInfo unavailable');
        $dispatcher->getUserInfo();
    }

    public function testGetUserInfoRestOnlyFlagAlsoRaisesNetworkError(): void
    {
        $dispatcher = $this->makeDispatcher(
            tokenAccessor: static fn (): ?string => 'tok',
            restOnly: true,
        );

        $this->expectException(NetworkError::class);
        $dispatcher->getUserInfo();
    }

    public function testGetUserInfoNeverAutoloadsTheGrpcServiceClientOnTheGrpcOnlyErrorPath(): void
    {
        // §1.1.6 short-circuits to NetworkError before userInfoClient() is ever reached, so
        // UserInfoGrpcClient (which extends the non-existent \Grpc\BaseStub) must not be
        // autoloaded — Pitfall 4 / T-22-16, mirroring AuthzDispatcherFallbackTest.
        $dispatcher = $this->makeDispatcher(tokenAccessor: static fn (): ?string => 'tok');
        try {
            $dispatcher->getUserInfo();
        } catch (NetworkError) {
            // expected
        }

        self::assertFalse(
            class_exists(\Axiam\Sdk\Grpc\UserInfoGrpcClient::class, false),
            'UserInfoGrpcClient must never be autoloaded on the gRPC-only error path (Pitfall 4 / T-22-16)',
        );
    }

    // --- §1.1.5 claim mapping (GetUserInfoResponse -> UserInfo) -------------------------

    public function testToUserInfoMapsEveryClaimIncludingBothOptionals(): void
    {
        $response = (new GetUserInfoResponse())
            ->setSub('11111111-1111-1111-1111-111111111111')
            ->setTenantId('22222222-2222-2222-2222-222222222222')
            ->setOrgId('33333333-3333-3333-3333-333333333333')
            ->setEmail('alice@acme.test')
            ->setPreferredUsername('alice');

        $userInfo = $this->invokePrivate($this->makeDispatcher(), 'toUserInfo', $response);

        self::assertInstanceOf(UserInfo::class, $userInfo);
        self::assertSame('11111111-1111-1111-1111-111111111111', $userInfo->sub);
        self::assertSame('22222222-2222-2222-2222-222222222222', $userInfo->tenantId);
        self::assertSame('33333333-3333-3333-3333-333333333333', $userInfo->orgId);
        self::assertSame('alice@acme.test', $userInfo->email);
        self::assertSame('alice', $userInfo->preferredUsername);
    }

    public function testToUserInfoSurfacesAbsentOptionalScopedClaimsAsNull(): void
    {
        // No "email"/"profile" scope on the token -> the server omits these optional fields;
        // the SDK must surface them as null (never ''), so callers can tell "scope not
        // granted" from "granted but empty" (§1.1.5).
        $response = (new GetUserInfoResponse())
            ->setSub('sub-1')
            ->setTenantId('tenant-1')
            ->setOrgId('org-1');

        $userInfo = $this->invokePrivate($this->makeDispatcher(), 'toUserInfo', $response);

        self::assertSame('sub-1', $userInfo->sub);
        self::assertSame('tenant-1', $userInfo->tenantId);
        self::assertSame('org-1', $userInfo->orgId);
        self::assertNull($userInfo->email);
        self::assertNull($userInfo->preferredUsername);
    }

    // --- §1.1.4 UNAUTHENTICATED -> single-flight refresh -> retry once ------------------

    public function testUnauthenticatedDrivesExactlyOneRefreshThenRetriesAndSucceeds(): void
    {
        $refreshCalls = 0;
        $dispatcher = $this->makeDispatcher(
            tokenAccessor: static fn (): ?string => 'tok',
            refreshAccessor: function () use (&$refreshCalls): void {
                ++$refreshCalls;
            },
        );

        $success = (new GetUserInfoResponse())->setSub('after-refresh');

        // First RPC attempt fails UNAUTHENTICATED (AuthError, as UserInfoGrpcClient maps it);
        // the retry — after exactly one refresh — succeeds.
        $attempts = 0;
        $rpc = function () use (&$attempts, $success): GetUserInfoResponse {
            ++$attempts;
            if ($attempts === 1) {
                throw new AuthError('userinfo gRPC call failed: unauthenticated — token expired');
            }

            return $success;
        };

        $result = $this->invokePrivate($dispatcher, 'getUserInfoWithRefreshRetry', $rpc);

        self::assertSame($success, $result);
        self::assertSame(1, $refreshCalls, 'refresh must run exactly once (single-flight, §9)');
        self::assertSame(2, $attempts, 'the RPC must be retried exactly once after refresh');
    }

    public function testUnauthenticatedRetryThatFailsAgainPropagatesWithoutLooping(): void
    {
        $refreshCalls = 0;
        $dispatcher = $this->makeDispatcher(
            tokenAccessor: static fn (): ?string => 'tok',
            refreshAccessor: function () use (&$refreshCalls): void {
                ++$refreshCalls;
            },
        );

        $attempts = 0;
        $rpc = function () use (&$attempts): GetUserInfoResponse {
            ++$attempts;
            throw new AuthError('userinfo gRPC call failed: unauthenticated — still expired');
        };

        try {
            $this->invokePrivate($dispatcher, 'getUserInfoWithRefreshRetry', $rpc);
            self::fail('expected AuthError to propagate after the single retry');
        } catch (AuthError) {
            // expected
        }

        self::assertSame(1, $refreshCalls, 'refresh runs once; a failed refresh is never retried (§9.3)');
        self::assertSame(2, $attempts, 'exactly one retry — no loop');
    }

    public function testUnauthenticatedWithoutRefreshAccessorPropagatesImmediately(): void
    {
        $dispatcher = $this->makeDispatcher(
            tokenAccessor: static fn (): ?string => 'tok',
            refreshAccessor: null,
        );

        $attempts = 0;
        $rpc = function () use (&$attempts): GetUserInfoResponse {
            ++$attempts;
            throw new AuthError('unauthenticated');
        };

        try {
            $this->invokePrivate($dispatcher, 'getUserInfoWithRefreshRetry', $rpc);
            self::fail('expected AuthError');
        } catch (AuthError) {
            // expected
        }

        self::assertSame(1, $attempts, 'with no refresh accessor the RPC runs once and the error propagates');
    }
}
