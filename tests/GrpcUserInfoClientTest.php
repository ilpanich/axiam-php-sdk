<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use PHPUnit\Framework\TestCase;

// ---------------------------------------------------------------------------
// Test-only doubles for the `ext-grpc` PECL classes that `UserInfoGrpcClient`
// extends/uses — the exact same shape GrpcAuthzClientTest defines for
// `AuthzGrpcClient`. The extension is genuinely absent in this sandbox (see
// AuthzDispatcherFallbackTest), so `\Grpc\BaseStub` / `\Grpc\ChannelCredentials`
// and the `\Grpc\STATUS_*` constants do not exist. These fakes let us load and
// unit-test the hand-written `UserInfoGrpcClient` transport WITHOUT the extension.
//
// This whole test runs in an ISOLATED PROCESS (@runTestsInSeparateProcesses +
// @preserveGlobalState disabled) so defining these `\Grpc\*` doubles — and
// autoloading `UserInfoGrpcClient` (which `extends \Grpc\BaseStub`) — never leaks
// into the main test process, where AuthzDispatcherFallbackTest asserts the gRPC
// service clients are NOT loaded on the REST-only path (Pitfall 4 / T-22-16). The
// `if (!class_exists(...))` guards also make this coexist with GrpcAuthzClientTest's
// identical doubles regardless of test-file load order.
// ---------------------------------------------------------------------------

namespace Grpc;

if (!\class_exists(\Grpc\ChannelCredentials::class, false)) {
    if (!\defined('Grpc\\STATUS_OK')) {
        \define('Grpc\\STATUS_OK', 0);
    }
    if (!\defined('Grpc\\STATUS_PERMISSION_DENIED')) {
        \define('Grpc\\STATUS_PERMISSION_DENIED', 7);
    }
    if (!\defined('Grpc\\STATUS_UNAUTHENTICATED')) {
        \define('Grpc\\STATUS_UNAUTHENTICATED', 16);
    }

    /** Records the last createSsl(...) call so the constructor's §6/D-12 TLS path is observable. */
    final class ChannelCredentials
    {
        /** @var array{called: bool, pem: string|null} */
        public static array $lastCreateSsl = ['called' => false, 'pem' => null];

        public static function createSsl(?string $pemRootCerts = null): object
        {
            self::$lastCreateSsl = ['called' => true, 'pem' => $pemRootCerts];

            return new \stdClass();
        }
    }

    /**
     * Minimal stand-in for `\Grpc\BaseStub`. Captures the constructor args and every
     * `_simpleRequest()` invocation, and returns a caller-programmed `(response, status)`
     * pair via a `wait()`-able unary call object.
     */
    class BaseStub
    {
        public string $capturedHostname = '';

        /** @var array<string, mixed> */
        public array $capturedOptions = [];

        /** @var list<array{method: string, argument: object, metadata: array<string, list<string>>}> */
        public array $calls = [];

        /** @var list<array{0: object|null, 1: object}> queued (response, status) results */
        public array $queuedResults = [];

        /** @param array<string, mixed> $options */
        public function __construct(string $hostname, array $options = [])
        {
            $this->capturedHostname = $hostname;
            $this->capturedOptions = $options;
        }

        /**
         * @param array<string, list<string>> $metadata
         */
        public function _simpleRequest(string $method, object $argument, callable $deserialize, array $metadata = [], array $options = []): object
        {
            $this->calls[] = ['method' => $method, 'argument' => $argument, 'metadata' => $metadata];
            $result = \array_shift($this->queuedResults) ?? [null, (object) ['code' => \Grpc\STATUS_OK, 'details' => '']];

            return new class($result) {
                /** @param array{0: object|null, 1: object} $result */
                public function __construct(private array $result)
                {
                }

                /** @return array{0: object|null, 1: object} */
                public function wait(): array
                {
                    return $this->result;
                }
            };
        }
    }
}

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Grpc\Gen\GetUserInfoRequest;
use Axiam\Sdk\Grpc\Gen\GetUserInfoResponse;
use Axiam\Sdk\Grpc\UserInfoGrpcClient;
use PHPUnit\Framework\TestCase;

/**
 * Unit-tests the gRPC userinfo transport ({@see UserInfoGrpcClient}, CONTRACT.md
 * §1.1/§2/§5/§6) against the test-only `\Grpc\*` doubles defined above — the exact
 * sibling of {@see GrpcAuthzClientTest} for the new gRPC-only `get_user_info` operation.
 *
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
final class GrpcUserInfoClientTest extends TestCase
{
    private function status(int $code, string $details = ''): object
    {
        return (object) ['code' => $code, 'details' => $details];
    }

    public function testConstructorUsesSystemTrustRootsWhenNoCustomCa(): void
    {
        \Grpc\ChannelCredentials::$lastCreateSsl = ['called' => false, 'pem' => null];

        $client = new UserInfoGrpcClient('api.axiam.test:9443', static fn (): ?string => null, 'tenant-1');

        self::assertSame('api.axiam.test:9443', $client->capturedHostname);
        self::assertTrue(\Grpc\ChannelCredentials::$lastCreateSsl['called']);
        self::assertNull(\Grpc\ChannelCredentials::$lastCreateSsl['pem']);
        self::assertArrayHasKey('credentials', $client->capturedOptions);
    }

    public function testConstructorUsesCustomCaPemWhenSupplied(): void
    {
        \Grpc\ChannelCredentials::$lastCreateSsl = ['called' => false, 'pem' => null];

        new UserInfoGrpcClient(
            'api.axiam.test:9443',
            static fn (): ?string => null,
            'tenant-1',
            "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
        );

        self::assertSame(
            "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
            \Grpc\ChannelCredentials::$lastCreateSsl['pem'],
        );
    }

    /**
     * Invokes the private `unary()` with a real deserialize callable.
     *
     * NOTE (identical to GrpcAuthzClientTest): the public `getUserInfo()` wrapper cannot be
     * driven in this environment — it hands `unary()` the literal
     * `[GetUserInfoResponse::class, 'decode']` pair, and the committed `src/Grpc/Gen/*`
     * protobuf stubs (which extend `Google\Protobuf\Internal\Message`) expose no `decode`
     * method, so that array is not `callable` and PHP raises a `TypeError` at `unary()`'s
     * typed parameter before any RPC runs. Driving `unary()` directly with a valid callable
     * is the only way to exercise the transport's dispatch/metadata/status-mapping logic
     * here without the `ext-grpc` PECL extension.
     *
     * @param array{0: object|null, 1: object} $result
     */
    private function invokeUnary(UserInfoGrpcClient $client, array $result): mixed
    {
        $client->queuedResults[] = $result;
        $ref = new \ReflectionMethod($client, 'unary');
        $ref->setAccessible(true);

        return $ref->invoke(
            $client,
            '/axiam.v1.UserInfoService/GetUserInfo',
            new GetUserInfoRequest(),
            static fn (string $body): string => $body,
        );
    }

    public function testUnarySuccessReturnsResponseAndSendsTenantAndAuthMetadata(): void
    {
        $response = (new GetUserInfoResponse())->setSub('user-7');
        $client = new UserInfoGrpcClient('api.axiam.test:9443', static fn (): ?string => 'tok-abc', 'tenant-9');

        $out = $this->invokeUnary($client, [$response, $this->status(\Grpc\STATUS_OK)]);

        self::assertSame($response, $out);
        self::assertCount(1, $client->calls);
        $call = $client->calls[0];
        self::assertSame('/axiam.v1.UserInfoService/GetUserInfo', $call['method']);
        // §5/§1.1.2: x-tenant-id + authorization metadata on every RPC.
        self::assertSame(['tenant-9'], $call['metadata']['x-tenant-id']);
        self::assertSame(['Bearer tok-abc'], $call['metadata']['authorization']);
    }

    public function testUnaryOmitsAuthorizationMetadataWhenTokenEmpty(): void
    {
        $response = new GetUserInfoResponse();
        $client = new UserInfoGrpcClient('api.axiam.test:9443', static fn (): ?string => '', 'tenant-2');

        $this->invokeUnary($client, [$response, $this->status(\Grpc\STATUS_OK)]);

        $call = $client->calls[0];
        self::assertArrayNotHasKey('authorization', $call['metadata']);
        self::assertSame(['tenant-2'], $call['metadata']['x-tenant-id']);
    }

    public function testUnaryMapsUnauthenticatedStatusToAuthError(): void
    {
        $client = new UserInfoGrpcClient('api.axiam.test:9443', static fn (): ?string => 'tok', 'tenant-1');

        try {
            $this->invokeUnary($client, [null, $this->status(\Grpc\STATUS_UNAUTHENTICATED, 'token expired')]);
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            self::assertStringContainsString('unauthenticated', $e->getMessage());
            self::assertStringContainsString('token expired', $e->getMessage());
        }
    }

    public function testUnaryMapsPermissionDeniedStatusToAuthzError(): void
    {
        $client = new UserInfoGrpcClient('api.axiam.test:9443', static fn (): ?string => 'tok', 'tenant-1');

        try {
            $this->invokeUnary($client, [null, $this->status(\Grpc\STATUS_PERMISSION_DENIED, 'tenant mismatch')]);
            self::fail('expected AuthzError');
        } catch (AuthzError $e) {
            self::assertStringContainsString('permission denied', $e->getMessage());
            self::assertStringContainsString('tenant mismatch', $e->getMessage());
        }
    }

    public function testUnaryMapsOtherStatusToNetworkError(): void
    {
        $client = new UserInfoGrpcClient('api.axiam.test:9443', static fn (): ?string => 'tok', 'tenant-1');

        try {
            $this->invokeUnary($client, [null, $this->status(14, 'unavailable')]);
            self::fail('expected NetworkError');
        } catch (NetworkError $e) {
            self::assertStringContainsString('unavailable', $e->getMessage());
        }
    }
}
