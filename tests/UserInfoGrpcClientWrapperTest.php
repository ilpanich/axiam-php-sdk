<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use PHPUnit\Framework\TestCase;

// ---------------------------------------------------------------------------
// Test-only doubles for the `ext-grpc` PECL classes, identical in shape to
// {@see AuthzGrpcClientWrapperTest}'s doubles: `_simpleRequest()` round-trips the
// queued response through real `serializeToString()`/the `$deserialize` callable
// so this file can drive {@see \Axiam\Sdk\Grpc\UserInfoGrpcClient}'s PUBLIC
// `getUserInfo()` wrapper end-to-end (see AuthzGrpcClientWrapperTest's docblock for
// the full "why" — the `decoder()` bug fix this proves).
//
// @runTestsInSeparateProcesses / @preserveGlobalState disabled.
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

    final class ChannelCredentials
    {
        public static function createSsl(?string $pemRootCerts = null): object
        {
            return new \stdClass();
        }
    }

    class BaseStub
    {
        public string $capturedHostname = '';

        /** @var array<string, mixed> */
        public array $capturedOptions = [];

        /** @var list<array{method: string, metadata: array<string, list<string>>}> */
        public array $calls = [];

        /** @var list<object|null> */
        public array $queuedResponses = [];

        /** @var list<object> */
        public array $queuedStatuses = [];

        /** @param array<string, mixed> $options */
        public function __construct(string $hostname, array $options = [])
        {
            $this->capturedHostname = $hostname;
            $this->capturedOptions = $options;
        }

        public function _simpleRequest(string $method, object $argument, callable $deserialize, array $metadata = [], array $options = []): object
        {
            $this->calls[] = ['method' => $method, 'metadata' => $metadata];

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

use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Grpc\Gen\GetUserInfoResponse;
use Axiam\Sdk\Grpc\UserInfoGrpcClient;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end tests of {@see UserInfoGrpcClient}'s PUBLIC `getUserInfo()` wrapper —
 * the sibling of {@see AuthzGrpcClientWrapperTest} for the userinfo transport, now that
 * {@see UserInfoGrpcClient::decoder()} builds a genuinely callable deserializer.
 *
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
final class UserInfoGrpcClientWrapperTest extends TestCase
{
    private function client(?string $token = 'tok-1'): UserInfoGrpcClient
    {
        return new UserInfoGrpcClient('api.axiam.test:9443', static fn (): ?string => $token, 'tenant-1');
    }

    public function testGetUserInfoReturnsDecodedResponseAndSendsMetadata(): void
    {
        $client = $this->client();
        $client->queuedResponses[] = (new GetUserInfoResponse())
            ->setSub('sub-1')
            ->setTenantId('tenant-1')
            ->setOrgId('org-1')
            ->setEmail('alice@acme.test');
        $client->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $response = $client->getUserInfo();

        self::assertInstanceOf(GetUserInfoResponse::class, $response);
        self::assertSame('sub-1', $response->getSub());
        self::assertSame('tenant-1', $response->getTenantId());
        self::assertSame('org-1', $response->getOrgId());
        self::assertTrue($response->hasEmail());
        self::assertSame('alice@acme.test', $response->getEmail());
        self::assertCount(1, $client->calls);
        self::assertSame('/axiam.v1.UserInfoService/GetUserInfo', $client->calls[0]['method']);
        self::assertSame(['tenant-1'], $client->calls[0]['metadata']['x-tenant-id']);
        self::assertSame(['Bearer tok-1'], $client->calls[0]['metadata']['authorization']);
    }

    public function testGetUserInfoOmitsAuthorizationMetadataWithNoToken(): void
    {
        $client = $this->client(null);
        $client->queuedResponses[] = new GetUserInfoResponse();
        $client->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $client->getUserInfo();

        self::assertArrayNotHasKey('authorization', $client->calls[0]['metadata']);
    }

    public function testGetUserInfoMapsUnauthenticatedStatusToAuthError(): void
    {
        $client = $this->client();
        $client->queuedResponses[] = null;
        $client->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_UNAUTHENTICATED, 'details' => 'expired'];

        $this->expectException(AuthError::class);
        $client->getUserInfo();
    }

    public function testGetUserInfoMapsPermissionDeniedStatusToAuthzError(): void
    {
        $client = $this->client();
        $client->queuedResponses[] = null;
        $client->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_PERMISSION_DENIED, 'details' => 'denied'];

        $this->expectException(AuthzError::class);
        $client->getUserInfo();
    }

    public function testGetUserInfoMapsOtherStatusToNetworkError(): void
    {
        $client = $this->client();
        $client->queuedResponses[] = null;
        $client->queuedStatuses[] = (object) ['code' => 14, 'details' => 'unavailable'];

        $this->expectException(NetworkError::class);
        $client->getUserInfo();
    }
}
