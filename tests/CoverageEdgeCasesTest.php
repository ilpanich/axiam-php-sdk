<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Amqp\ReplayGuard;
use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\ErrorMapper;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Rest\AuthzRestClient;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * Targeted coverage for narrow error/edge branches that the broader behavior suites
 * don't reach: the no-response {@see RequestException} transport-error branch, the
 * malformed authorization-denied body branch of {@see ErrorMapper}, the `issued_at`
 * replay-gate, and {@see AxiamClient}'s unverified-token decode + local-verify-with-
 * refresh-fallback paths. Everything is driven through the same `MockHandler`
 * transport-seam idiom used across this suite — no live services.
 */
final class CoverageEdgeCasesTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';

    /** @param array<int, Response|\Throwable> $queue */
    private function client(array $queue): AxiamClient
    {
        return new AxiamClient(self::BASE_URL, self::TENANT, transportHandler: new MockHandler($queue));
    }

    private function loginSettingToken(string $token): Response
    {
        return new Response(
            200,
            ['Set-Cookie' => 'axiam_access=' . $token . '; Path=/'],
            (string) json_encode(['user' => ['id' => 'user-1']]),
        );
    }

    /** A JWT-shaped string with the `alg: none` header so JwksVerifier rejects it with no HTTP fetch. */
    private function unsignedJwt(array $claims): string
    {
        $segment = static fn (array $data): string => rtrim(
            strtr(base64_encode((string) json_encode($data)), '+/', '-_'),
            '=',
        );

        return $segment(['alg' => 'none', 'typ' => 'JWT']) . '.' . $segment($claims) . '.signature';
    }

    // --- AuthzRestClient: RequestException carrying no response (line 147) ----------

    public function testCheckAccessRequestExceptionWithoutResponseMapsToNetworkError(): void
    {
        $stack = HandlerStack::create(new MockHandler([
            new RequestException('name resolution failed', new Request('POST', '/api/v1/authz/check')),
        ]));
        $rest = new AuthzRestClient(new Client(['handler' => $stack]));

        $this->expectException(NetworkError::class);
        $rest->checkAccess('read', 'resource-1');
    }

    // --- ErrorMapper: 403/409 body that is valid JSON but not an object (line 52) ---

    public function testAuthzErrorFromNonArrayBodyStillBuildsAuthzError(): void
    {
        // A 403 whose body decodes to a JSON scalar (not an object) must still yield a
        // well-formed AuthzError with null action/resource_id rather than fataling.
        $error = ErrorMapper::fromStatus(403, new Response(403, [], '42'), 'authz denied');

        self::assertInstanceOf(AuthzError::class, $error);
        self::assertStringContainsString('forbidden (HTTP 403)', $error->getMessage());
    }

    public function testAuthzErrorFrom409NonArrayBody(): void
    {
        $error = ErrorMapper::fromStatus(409, new Response(409, [], 'null'), 'conflict');

        self::assertInstanceOf(AuthzError::class, $error);
    }

    // --- ReplayGuard: missing/empty issued_at after a valid key_version (line 97) ---

    public function testReplayGuardRejectsMissingIssuedAt(): void
    {
        $guard = new ReplayGuard(300, static fn (): int => 1_800_000_000);

        self::assertSame('issued_at', $guard->check([
            'key_version' => 2,
            'nonce' => 'n-1',
            // issued_at absent
        ]));
    }

    public function testReplayGuardRejectsEmptyIssuedAt(): void
    {
        $guard = new ReplayGuard(300, static fn (): int => 1_800_000_000);

        self::assertSame('issued_at', $guard->check([
            'key_version' => 2,
            'nonce' => 'n-2',
            'issued_at' => '',
        ]));
    }

    // --- AxiamClient::currentClaimsOrNull decode edges via logout() -----------------

    public function testLogoutWithNonBase64TokenPayloadThrowsAuthError(): void
    {
        // Middle segment '@@@' fails strict base64_decode -> claims null -> no jti.
        $client = $this->client([$this->loginSettingToken('aaa.@@@.bbb')]);
        $client->login('user@example.test', 'secret');

        $this->expectException(AuthError::class);
        $client->logout();
    }

    public function testLogoutWithNonJsonTokenPayloadThrowsAuthError(): void
    {
        // Middle segment base64-decodes to 'hello' which is not valid JSON -> claims null.
        $client = $this->client([$this->loginSettingToken('aaa.aGVsbG8.bbb')]);
        $client->login('user@example.test', 'secret');

        $this->expectException(AuthError::class);
        $client->logout();
    }

    // --- AxiamClient::verifyLocallyOrFallback refresh-fallback branches -------------

    public function testVerifyLocallyOrFallbackReturnsNullWhenRefreshYieldsNoToken(): void
    {
        // Local verify fails (alg:none), the refresh call succeeds (200) but carries no
        // new access-token cookie, so accessToken() stays null -> return null.
        $client = $this->client([new Response(200, [], (string) json_encode(['ok' => true]))]);

        $result = $client->verifyLocallyOrFallback(
            $this->unsignedJwt(['sub' => 'user-1', 'tenant_id' => self::TENANT]),
            self::TENANT,
        );

        self::assertNull($result);
    }

    public function testVerifyLocallyOrFallbackReverifiesRefreshedToken(): void
    {
        // Refresh succeeds AND delivers a new token, so the method re-verifies it; that
        // second (still alg:none) token also fails verification -> return null, but the
        // re-verify branch (the refreshed-token path) is exercised.
        $refreshed = $this->unsignedJwt(['sub' => 'user-1', 'tenant_id' => self::TENANT]);
        $client = $this->client([
            new Response(
                200,
                ['Set-Cookie' => 'axiam_access=' . $refreshed . '; Path=/'],
                (string) json_encode(['ok' => true]),
            ),
        ]);

        $result = $client->verifyLocallyOrFallback(
            $this->unsignedJwt(['sub' => 'user-1', 'tenant_id' => self::TENANT]),
            self::TENANT,
        );

        self::assertNull($result);
    }
}
