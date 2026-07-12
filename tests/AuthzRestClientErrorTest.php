<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Rest\AuthzRestClient;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use PHPUnit\Framework\TestCase;

/**
 * Error-path coverage for {@see AuthzRestClient} (CONTRACT.md §1/§2, D-10): the happy
 * checkAccess/can/batchCheck paths are already proven through {@see AuthzDispatcherFallbackTest}
 * (via the dispatcher), so this drives the transport-error and malformed-body branches that
 * only surface when the server rejects, the connection fails, or the response body does not
 * match the documented `allowed`/`results` shape. Each client is wired with a `MockHandler`
 * — with `http_errors` disabled where a non-2xx STATUS (not an exception) must reach the
 * client's own status check — mirroring the transport-seam idiom used across this suite.
 */
final class AuthzRestClientErrorTest extends TestCase
{
    /**
     * @param list<Response|\Throwable> $queue
     */
    private function client(array $queue, bool $httpErrors = true): Client
    {
        $stack = HandlerStack::create(new MockHandler($queue));

        return new Client(['handler' => $stack, 'http_errors' => $httpErrors]);
    }

    private function request(): Request
    {
        return new Request('POST', '/api/v1/authz/check');
    }

    public function testCanDelegatesToCheckAccessAndDecodesAllowed(): void
    {
        $rest = new AuthzRestClient($this->client([
            new Response(200, [], (string) json_encode(['allowed' => true])),
        ]));

        self::assertTrue($rest->can('documents', 'read'));
    }

    public function testCheckAccessMalformedBodyThrowsNetworkError(): void
    {
        // A 200 whose body is a JSON scalar (not an object) must fail closed via
        // NetworkError rather than being silently treated as `allowed = false`.
        $rest = new AuthzRestClient($this->client([
            new Response(200, [], '"not-an-object"'),
        ]));

        $this->expectException(NetworkError::class);
        $rest->checkAccess('read', 'resource-1');
    }

    public function testCheckAccessForbiddenStatusMapsToAuthzError(): void
    {
        $rest = new AuthzRestClient($this->client(
            [new Response(403, [], (string) json_encode(['error' => 'forbidden']))],
            httpErrors: false,
        ));

        $this->expectException(AuthzError::class);
        $rest->checkAccess('delete', 'resource-1');
    }

    public function testCheckAccessRequestExceptionWithResponseMapsToAuthError(): void
    {
        $rest = new AuthzRestClient($this->client([
            new RequestException(
                'unauthorized',
                $this->request(),
                new Response(401, [], (string) json_encode(['error' => 'unauthorized'])),
            ),
        ]));

        $this->expectException(AuthError::class);
        $rest->checkAccess('read', 'resource-1');
    }

    public function testCheckAccessConnectExceptionMapsToNetworkError(): void
    {
        $rest = new AuthzRestClient($this->client([
            new ConnectException('connection refused', $this->request()),
        ]));

        $this->expectException(NetworkError::class);
        $rest->checkAccess('read', 'resource-1');
    }

    public function testBatchCheckServerErrorStatusMapsToNetworkError(): void
    {
        $rest = new AuthzRestClient($this->client(
            [new Response(500, [], (string) json_encode(['error' => 'boom']))],
            httpErrors: false,
        ));

        $this->expectException(NetworkError::class);
        $rest->batchCheck([['action' => 'read', 'resourceId' => 'r1']]);
    }

    public function testBatchCheckMalformedBodyThrowsNetworkError(): void
    {
        // 200 but the `results` key is absent — the documented order/length guarantee
        // cannot be honoured, so this must fail closed rather than return [].
        $rest = new AuthzRestClient($this->client([
            new Response(200, [], (string) json_encode(['unexpected' => true])),
        ]));

        $this->expectException(NetworkError::class);
        $rest->batchCheck([['action' => 'read', 'resourceId' => 'r1']]);
    }

    public function testBatchCheckRequestExceptionWithResponseMapsToAuthzError(): void
    {
        $rest = new AuthzRestClient($this->client([
            new RequestException(
                'forbidden',
                new Request('POST', '/api/v1/authz/check/batch'),
                new Response(403, [], (string) json_encode(['error' => 'forbidden'])),
            ),
        ]));

        $this->expectException(AuthzError::class);
        $rest->batchCheck([['action' => 'read', 'resourceId' => 'r1', 'scope' => 'child']]);
    }

    public function testBatchCheckConnectExceptionMapsToNetworkError(): void
    {
        $rest = new AuthzRestClient($this->client([
            new ConnectException('connection refused', new Request('POST', '/api/v1/authz/check/batch')),
        ]));

        $this->expectException(NetworkError::class);
        $rest->batchCheck([['action' => 'read', 'resourceId' => 'r1']]);
    }

    public function testBatchCheckDecodesAllowedFlagsPreservingOrder(): void
    {
        $rest = new AuthzRestClient($this->client([
            new Response(200, [], (string) json_encode([
                'results' => [
                    ['allowed' => true],
                    ['allowed' => false],
                    ['not_allowed_key' => true],
                ],
            ])),
        ]));

        self::assertSame(
            [true, false, false],
            $rest->batchCheck([
                ['action' => 'read', 'resourceId' => 'r1'],
                ['action' => 'write', 'resourceId' => 'r2'],
                ['action' => 'delete', 'resourceId' => 'r3'],
            ]),
        );
    }
}
