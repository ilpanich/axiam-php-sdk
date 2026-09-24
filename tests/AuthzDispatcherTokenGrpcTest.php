<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use PHPUnit\Framework\TestCase;

// ---------------------------------------------------------------------------
// {@see \Axiam\Sdk\AuthzDispatcher::validateToken()}/`introspectToken()` — the
// `!$this->restOnly && extension_loaded('grpc')` integration, the same idiom as
// {@see AuthzDispatcherGrpcPathTest} (its own file's top comment explains why the
// `Axiam\Sdk\extension_loaded()` override is declared inside `setUp()` via `eval()`
// rather than as top-level file code, and why every test here runs in its own
// process).
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
        public static function createSsl(?string $pemRootCerts = null): object
        {
            return new \stdClass();
        }
    }

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
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Grpc\Gen\ValidateTokenResponse;
use Axiam\Sdk\Rest\AuthzRestClient;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
final class AuthzDispatcherTokenGrpcTest extends TestCase
{
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

    public function testValidateTokenSucceedsOverGrpcWhenExtensionAndTargetArePresent(): void
    {
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: static fn (): ?string => 'caller-tok',
        );

        $tokenClient = $this->invokePrivate($dispatcher, 'tokenClient');
        $tokenClient->queuedResponses[] = (new ValidateTokenResponse())->setValid(true)->setSubjectId('sub-1');
        $tokenClient->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $result = $dispatcher->validateToken(new Sensitive('inspected'));

        self::assertTrue($result->valid);
        self::assertSame('sub-1', $result->subjectId);
    }

    public function testValidateTokenRetriesOnceAfterUnauthenticatedThenSucceeds(): void
    {
        $refreshCalls = 0;
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: static fn (): ?string => 'caller-tok',
            refreshAccessor: function () use (&$refreshCalls): void {
                ++$refreshCalls;
            },
        );

        $tokenClient = $this->invokePrivate($dispatcher, 'tokenClient');
        $tokenClient->queuedResponses[] = null;
        $tokenClient->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_UNAUTHENTICATED, 'details' => 'expired'];
        $tokenClient->queuedResponses[] = (new ValidateTokenResponse())->setValid(true)->setSubjectId('sub-after-refresh');
        $tokenClient->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $result = $dispatcher->validateToken(new Sensitive('inspected'));

        self::assertSame('sub-after-refresh', $result->subjectId);
        self::assertSame(1, $refreshCalls);
        self::assertCount(2, $tokenClient->calls);
    }

    public function testValidateTokenWithNoCallerTokenNeverConstructsTheGrpcClient(): void
    {
        \Grpc\BaseStub::$instanceCount = 0;
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: static fn (): ?string => null,
        );

        try {
            $dispatcher->validateToken(new Sensitive('inspected'));
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertStringContainsString('prior successful login', $e->getMessage());
        }

        self::assertSame(0, \Grpc\BaseStub::$instanceCount, 'the §1.1 rule 3 precondition must short-circuit before any channel is built');
    }

    public function testIntrospectTokenWithNoCallerTokenNeverConstructsTheGrpcClient(): void
    {
        \Grpc\BaseStub::$instanceCount = 0;
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: static fn (): ?string => '',
        );

        try {
            $dispatcher->introspectToken(new Sensitive('inspected'));
            self::fail('expected AuthError');
        } catch (AuthError) {
        }

        self::assertSame(0, \Grpc\BaseStub::$instanceCount);
    }

    /** REST-only: gRPC-only operation has NO REST substitution (§1.1.1 rule 7). */
    public function testValidateTokenOnARestOnlyDispatcherRaisesNetworkErrorNotGrpc(): void
    {
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            restOnly: true,
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: static fn (): ?string => 'caller-tok',
        );

        $this->expectException(NetworkError::class);
        $dispatcher->validateToken(new Sensitive('inspected'));
    }

    public function testTokenClientIsConstructedOnceAndCachedAcrossCalls(): void
    {
        $dispatcher = new AuthzDispatcher(
            restClient: $this->restClient(),
            grpcTarget: 'api.axiam.test:9443',
            tenantId: 'tenant-1',
            tokenAccessor: static fn (): ?string => 'caller-tok',
        );

        $first = $this->invokePrivate($dispatcher, 'tokenClient');
        $second = $this->invokePrivate($dispatcher, 'tokenClient');

        self::assertSame($first, $second);
    }
}
