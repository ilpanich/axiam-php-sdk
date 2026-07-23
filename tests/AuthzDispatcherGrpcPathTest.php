<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use PHPUnit\Framework\TestCase;

// ---------------------------------------------------------------------------
// This file drives {@see \Axiam\Sdk\AuthzDispatcher}'s `!$this->restOnly &&
// extension_loaded('grpc')` branches — the TRUE side of the guard that
// {@see AuthzDispatcherFallbackTest}/{@see UserInfoDispatcherTest} prove the FALSE
// side of (the extension is genuinely absent in this sandbox). Two test-only seams
// make that possible without the real `ext-grpc` PECL extension:
//
//  1. `\Grpc\BaseStub`/`\Grpc\ChannelCredentials` doubles — the same idiom as every
//     other `\Grpc\*`-doubles file in this suite (see GrpcAuthzClientTest).
//  2. A namespace-scoped `Axiam\Sdk\extension_loaded()` FUNCTION. PHP resolves an
//     unqualified function call from within a namespace by first looking for that
//     name IN the calling code's OWN namespace before falling back to the global
//     one — AuthzDispatcher.php calls `extension_loaded('grpc')` unqualified from
//     `namespace Axiam\Sdk`, so declaring `Axiam\Sdk\extension_loaded()` shadows the
//     real global `extension_loaded()` for THAT ONE call site only.
//
// CRITICAL: this function is declared via `eval()` inside {@see self::setUp()},
// NOT as ordinary top-level file code. PHPUnit's test-suite DISCOVERY pass loads
// (`include_once`s) every test file — including this one — in the shared MAIN
// process merely to enumerate its test methods, regardless of
// `@runTestsInSeparateProcesses` (that annotation only affects how the test
// METHOD BODY later executes). An ordinary top-level `function extension_loaded()`
// declaration would therefore be registered in the MAIN process the instant this
// file is discovered — permanently shadowing the real `extension_loaded()` for
// EVERY OTHER test sharing that process (breaking, e.g., AuthzDispatcherFallbackTest
// and UserInfoDispatcherTest's non-vacuousness proofs that the extension is
// genuinely absent). Confirmed empirically: an earlier top-level version of this
// override broke exactly those two sibling suites when run together. `setUp()`
// only ever executes when a test method actually RUNS — which, thanks to
// `@runTestsInSeparateProcesses` on every test below, happens exclusively inside a
// freshly-forked, isolated child PHP process — so the `eval()` (and the function it
// defines) never touches the shared main process at all.
// ---------------------------------------------------------------------------

namespace Grpc;

if (!\class_exists(\Grpc\ChannelCredentials::class, false)) {
    if (!\defined('Grpc\\STATUS_OK')) {
        \define('Grpc\\STATUS_OK', 0);
    }
    if (!\defined('Grpc\\STATUS_UNAUTHENTICATED')) {
        \define('Grpc\\STATUS_UNAUTHENTICATED', 16);
    }

    final class ChannelCredentials
    {
        public static int $createCount = 0;

        public static function createSsl(?string $pemRootCerts = null): object
        {
            self::$createCount++;

            return new \stdClass();
        }
    }

    /**
     * Round-trips the queued response through real wire bytes (like
     * AuthzGrpcClientWrapperTest's double) AND tracks how many `BaseStub` instances
     * are actually constructed, so tests below can prove {@see AuthzDispatcher}'s
     * `??=` lazy-construction caches the gRPC/userinfo clients rather than rebuilding
     * them on every call.
     */
    class BaseStub
    {
        public static int $instanceCount = 0;

        /** @var list<array{method: string, argument: object, metadata: array<string, list<string>>}> */
        public array $calls = [];

        /** @var list<object|null> */
        public array $queuedResponses = [];

        /** @var list<object> */
        public array $queuedStatuses = [];

        /** @param array<string, mixed> $options */
        public function __construct(string $hostname, array $options = [])
        {
            self::$instanceCount++;
        }

        public function _simpleRequest(string $method, object $argument, callable $deserialize, array $metadata = [], array $options = []): object
        {
            $this->calls[] = ['method' => $method, 'argument' => $argument, 'metadata' => $metadata];

            $queuedResponse = \array_shift($this->queuedResponses);
            $status = \array_shift($this->queuedStatuses) ?? (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];
            $decoded = $queuedResponse !== null ? $deserialize($queuedResponse->serializeToString()) : null;

            return new class($decoded, $status) {
                public function __construct(private ?object $response, private object $status)
                {
                }

                /** @return array{0: object|null, 1: object} */
                public function wait(): array
                {
                    return [$this->response, $this->status];
                }
            };
        }
    }
}

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AuthzDispatcher;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Grpc\Gen\CheckAccessResponse;
use Axiam\Sdk\Grpc\Gen\GetUserInfoResponse;
use Axiam\Sdk\Rest\AuthzRestClient;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
final class AuthzDispatcherGrpcPathTest extends TestCase
{
    /**
     * Lazily declares `Axiam\Sdk\extension_loaded()` — see the top-of-file comment
     * for why this MUST happen here (inside a method body, only reached when a
     * test actually runs) rather than as top-level file code.
     */
    protected function setUp(): void
    {
        if (!\function_exists('Axiam\\Sdk\\extension_loaded')) {
            eval(
                'namespace Axiam\\Sdk; '
                . 'function extension_loaded(string $name): bool { '
                . 'return $name === \'grpc\' ? true : \\extension_loaded($name); '
                . '}'
            );
        }
    }

    private function restClient(): AuthzRestClient
    {
        $http = new Client(['handler' => HandlerStack::create(new MockHandler([]))]);

        return new AuthzRestClient($http);
    }

    private function invokePrivate(AuthzDispatcher $dispatcher, string $method, mixed ...$args): mixed
    {
        $ref = new \ReflectionMethod($dispatcher, $method);
        $ref->setAccessible(true);

        return $ref->invoke($dispatcher, ...$args);
    }

    public function testExtensionLoadedOverrideIsActiveForThisFile(): void
    {
        // Non-vacuousness: proves the override actually took effect, and that it is
        // scoped to Axiam\Sdk only (the real global function is untouched).
        self::assertTrue(\Axiam\Sdk\extension_loaded('grpc'));
        self::assertFalse(\extension_loaded('grpc'), 'the REAL global extension_loaded() must be unaffected');
    }

    // --- checkAccess(): gRPC assembly + unwrap, incl. optional scope + subjectId ----

    public function testCheckAccessRoutesOverGrpcAndUsesExplicitSubjectIdWhenGiven(): void
    {
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: static fn (): ?string => 'tok',
            subjectIdAccessor: static fn (): string => 'session-subject', // must be ignored below
        );

        $grpc = $this->invokePrivate($dispatcher, 'grpcClient');
        $grpc->queuedResponses[] = (new CheckAccessResponse())->setAllowed(true);
        $grpc->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $result = $dispatcher->checkAccess('read', 'resource-1', 'admin', 'explicit-subject');

        self::assertTrue($result);
        self::assertCount(1, $grpc->calls);
        self::assertSame('explicit-subject', $grpc->calls[0]['argument']->getSubjectId());
        self::assertSame('read', $grpc->calls[0]['argument']->getAction());
        self::assertSame('resource-1', $grpc->calls[0]['argument']->getResourceId());
        self::assertSame('admin', $grpc->calls[0]['argument']->getScope());
    }

    public function testCheckAccessFallsBackToCurrentSubjectIdWhenNoneGiven(): void
    {
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: static fn (): ?string => 'tok',
            subjectIdAccessor: static fn (): string => 'session-subject',
        );

        $grpc = $this->invokePrivate($dispatcher, 'grpcClient');
        $grpc->queuedResponses[] = (new CheckAccessResponse())->setAllowed(false);
        $grpc->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $result = $dispatcher->checkAccess('read', 'resource-1');

        self::assertFalse($result);
        self::assertSame('session-subject', $grpc->calls[0]['argument']->getSubjectId());
        self::assertFalse($grpc->calls[0]['argument']->hasScope());
    }

    public function testCanAliasRoutesOverGrpcToo(): void
    {
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: static fn (): ?string => 'tok',
            subjectIdAccessor: static fn (): string => 'sub-1',
        );

        $grpc = $this->invokePrivate($dispatcher, 'grpcClient');
        $grpc->queuedResponses[] = (new CheckAccessResponse())->setAllowed(true);
        $grpc->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        self::assertTrue($dispatcher->can('documents', 'read'));
    }

    // --- batchCheck(): gRPC assembly (multi-item, mixed scope) + unwrap -------------

    public function testBatchCheckAssemblesEveryItemPreservingOrderAndOptionalScope(): void
    {
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: static fn (): ?string => 'tok',
            subjectIdAccessor: static fn (): string => 'sub-1',
        );

        $grpc = $this->invokePrivate($dispatcher, 'grpcClient');
        $batchResponse = new \Axiam\Sdk\Grpc\Gen\BatchCheckAccessResponse();
        $batchResponse->setResults([
            (new CheckAccessResponse())->setAllowed(true),
            (new CheckAccessResponse())->setAllowed(false),
        ]);
        $grpc->queuedResponses[] = $batchResponse;
        $grpc->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $result = $dispatcher->batchCheck([
            ['action' => 'read', 'resourceId' => 'res-1'],
            ['action' => 'write', 'resourceId' => 'res-2', 'scope' => 'admin'],
        ]);

        self::assertSame([true, false], $result);
        $sentRequest = $grpc->calls[0]['argument'];
        $items = iterator_to_array($sentRequest->getRequests());
        self::assertCount(2, $items);
        self::assertSame('sub-1', $items[0]->getSubjectId());
        self::assertFalse($items[0]->hasScope());
        self::assertSame('admin', $items[1]->getScope());
        self::assertSame('tenant-1', $items[1]->getTenantId());
    }

    // --- lazy grpcClient()/userInfoClient() construction: cached across calls -------

    public function testGrpcClientIsConstructedOnceAndCachedAcrossCalls(): void
    {
        \Grpc\BaseStub::$instanceCount = 0;
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: static fn (): ?string => 'tok',
            subjectIdAccessor: static fn (): string => 'sub-1',
        );

        $first = $this->invokePrivate($dispatcher, 'grpcClient');
        $second = $this->invokePrivate($dispatcher, 'grpcClient');

        self::assertSame($first, $second, '??= must cache the constructed client');
        self::assertSame(1, \Grpc\BaseStub::$instanceCount, 'the underlying gRPC channel must be built exactly once');
    }

    public function testUserInfoClientIsConstructedOnceAndCachedAcrossCalls(): void
    {
        \Grpc\BaseStub::$instanceCount = 0;
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: static fn (): ?string => 'tok',
        );

        $first = $this->invokePrivate($dispatcher, 'userInfoClient');
        $second = $this->invokePrivate($dispatcher, 'userInfoClient');

        self::assertSame($first, $second);
        self::assertSame(1, \Grpc\BaseStub::$instanceCount);
    }

    public function testGrpcClientAndUserInfoClientAreConstructedIndependently(): void
    {
        \Grpc\BaseStub::$instanceCount = 0;
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: static fn (): ?string => 'tok',
            subjectIdAccessor: static fn (): string => 'sub-1',
        );

        $this->invokePrivate($dispatcher, 'grpcClient');
        $this->invokePrivate($dispatcher, 'userInfoClient');

        self::assertSame(2, \Grpc\BaseStub::$instanceCount, 'the authz and userinfo channels are distinct instances');
    }

    // --- grpcClient()/userInfoClient(): AxiamException when misconfigured ----------

    public function testGrpcClientThrowsWhenGrpcTargetIsNull(): void
    {
        $dispatcher = new AuthzDispatcher(restClient: $this->restClient(), tenantId: 'tenant-1');

        $this->expectException(AxiamException::class);
        $this->expectExceptionMessage('grpcTarget must be configured');
        $this->invokePrivate($dispatcher, 'grpcClient');
    }

    public function testGrpcClientThrowsWhenTenantIdIsNull(): void
    {
        $dispatcher = new AuthzDispatcher(restClient: $this->restClient(), grpcTarget: 'api.axiam.test:9443');

        $this->expectException(AxiamException::class);
        $this->expectExceptionMessage('tenantId must be configured');
        $this->invokePrivate($dispatcher, 'grpcClient');
    }

    public function testUserInfoClientThrowsWhenGrpcTargetIsNull(): void
    {
        $dispatcher = new AuthzDispatcher(restClient: $this->restClient(), tenantId: 'tenant-1');

        $this->expectException(AxiamException::class);
        $this->expectExceptionMessage('grpcTarget must be configured');
        $this->invokePrivate($dispatcher, 'userInfoClient');
    }

    public function testUserInfoClientThrowsWhenTenantIdIsNull(): void
    {
        $dispatcher = new AuthzDispatcher(restClient: $this->restClient(), grpcTarget: 'api.axiam.test:9443');

        $this->expectException(AxiamException::class);
        $this->expectExceptionMessage('tenantId must be configured');
        $this->invokePrivate($dispatcher, 'userInfoClient');
    }

    // --- currentSubjectId(): the dispatcher's own private helper --------------------

    public function testCurrentSubjectIdReturnsAccessorResultCastToString(): void
    {
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            subjectIdAccessor: static fn (): string => 'sub-42',
        );

        self::assertSame('sub-42', $this->invokePrivate($dispatcher, 'currentSubjectId'));
    }

    public function testCurrentSubjectIdReturnsEmptyStringWhenNoAccessorConfigured(): void
    {
        $dispatcher = new AuthzDispatcher(restClient: $this->restClient());

        self::assertSame('', $this->invokePrivate($dispatcher, 'currentSubjectId'));
    }

    // --- getUserInfo(): full gRPC-path success + UNAUTHENTICATED-retry integration ---

    public function testGetUserInfoSucceedsOverGrpcWhenExtensionAndTargetArePresent(): void
    {
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: static fn (): ?string => 'tok',
        );

        $userInfoClient = $this->invokePrivate($dispatcher, 'userInfoClient');
        $userInfoClient->queuedResponses[] = (new GetUserInfoResponse())
            ->setSub('sub-1')
            ->setTenantId('tenant-1')
            ->setOrgId('org-1');
        $userInfoClient->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $userInfo = $dispatcher->getUserInfo();

        self::assertSame('sub-1', $userInfo->sub);
        self::assertSame('tenant-1', $userInfo->tenantId);
        self::assertSame('org-1', $userInfo->orgId);
        self::assertNull($userInfo->email);
    }

    public function testGetUserInfoRetriesOnceAfterUnauthenticatedThenSucceeds(): void
    {
        $refreshCalls = 0;
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: static fn (): ?string => 'tok',
            refreshAccessor: function () use (&$refreshCalls): void {
                ++$refreshCalls;
            },
        );

        $userInfoClient = $this->invokePrivate($dispatcher, 'userInfoClient');
        // First call: UNAUTHENTICATED. Second call (post-refresh retry): success.
        $userInfoClient->queuedResponses[] = null;
        $userInfoClient->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_UNAUTHENTICATED, 'details' => 'expired'];
        $userInfoClient->queuedResponses[] = (new GetUserInfoResponse())->setSub('sub-after-refresh')->setTenantId('t')->setOrgId('o');
        $userInfoClient->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $userInfo = $dispatcher->getUserInfo();

        self::assertSame('sub-after-refresh', $userInfo->sub);
        self::assertSame(1, $refreshCalls);
        self::assertCount(2, $userInfoClient->calls);
    }

    public function testGetUserInfoWithoutTokenNeverConstructsTheGrpcClient(): void
    {
        \Grpc\BaseStub::$instanceCount = 0;
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: static fn (): ?string => null,
        );

        try {
            $dispatcher->getUserInfo();
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertStringContainsString('prior successful login', $e->getMessage());
        }

        self::assertSame(0, \Grpc\BaseStub::$instanceCount, 'the §1.1.3 precondition must short-circuit before any channel is built');
    }
}
