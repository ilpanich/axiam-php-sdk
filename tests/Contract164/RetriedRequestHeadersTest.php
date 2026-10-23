<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract164;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Management\Models\CreateGroupRequest;
use Axiam\Sdk\Rest\AuthMiddleware;
use Axiam\Sdk\Rest\RefreshMiddleware;
use Axiam\Sdk\Session;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Cookie\SetCookie;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * C163-18: `HandlerStack` runs the first pushed middleware first, and `AxiamClient` pushes
 * `RefreshMiddleware` before `AuthMiddleware`, so a request replayed after a refresh passes
 * through `AuthMiddleware` again and carries the FRESH bearer token and CSRF value, and a
 * `Cookie` rebuilt from the jar, never the headers of the 401'd attempt.
 */
final class RetriedRequestHeadersTest extends TestCase
{
    /** A JWT-shaped (unsigned) access token: the refresh body reads `tenant_id` and `org_id` from it. */
    private static function accessToken(string $generation): string
    {
        $b64 = static fn (array $part): string => rtrim(strtr(base64_encode((string) json_encode($part)), '+/', '-_'), '=');

        return $b64(['alg' => 'EdDSA', 'typ' => 'JWT']) . '.' . $b64([
            'sub' => 'user-1',
            'jti' => $generation,
            'tenant_id' => '11111111-1111-1111-1111-111111111111',
            'org_id' => '22222222-2222-2222-2222-222222222222',
            'exp' => 9999999999,
        ]) . '.unsigned';
    }

    public function testARetriedRequestCarriesTheRefreshedAccessTokenAndCsrfToken(): void
    {
        /** @var list<RequestInterface> $seen what the base handler received, in order */
        $seen = [];
        $jar = new CookieJar();
        // A later expiry on each write, as a real rotation has: the jar replaces a cookie only
        // when the new one does not expire sooner.
        $lifetime = 3600;
        $setAccess = static function (string $value) use ($jar, &$lifetime): void {
            $jar->setCookie(new SetCookie([
                'Name' => 'axiam_access',
                'Value' => $value,
                'Domain' => 'api.test',
                'Path' => '/',
                'Expires' => time() + ($lifetime += 60),
            ]));
        };
        $setAccess(self::accessToken('old'));

        $mock = new MockHandler([
            static function (RequestInterface $r) use (&$seen): Response {
                $seen[] = $r;

                return new Response(401);
            },
            // The refresh: the server rotates the cookie and the CSRF token.
            static function (RequestInterface $r) use (&$seen, $setAccess): Response {
                $seen[] = $r;
                $setAccess(self::accessToken('new'));

                return new Response(200, ['X-CSRF-Token' => 'csrf-new'], '{}');
            },
            static function (RequestInterface $r) use (&$seen): Response {
                $seen[] = $r;

                return new Response(200);
            },
        ]);

        $stack = HandlerStack::create($mock);
        $session = new Session('https://api.test', 'acme', new Client(['handler' => $stack]), $jar);
        $session->captureCsrfTokenFromResponse(new Response(200, ['X-CSRF-Token' => 'csrf-old']));

        // The order AxiamClient builds for $authzStack.
        $stack->push(new RefreshMiddleware($session), 'axiam_refresh');
        $stack->push(new AuthMiddleware($session), 'axiam_auth');

        $response = (new Client(['handler' => $stack, 'http_errors' => false, 'cookies' => $jar]))->post('https://api.test/api/v1/authz/check');

        self::assertSame(200, $response->getStatusCode());
        self::assertCount(3, $seen, 'original, refresh, replay');
        [$original, $refresh, $replay] = $seen;
        self::assertSame('/api/v1/auth/refresh', $refresh->getUri()->getPath());

        self::assertSame('Bearer ' . self::accessToken('old'), $original->getHeaderLine('Authorization'));
        self::assertSame('csrf-old', $original->getHeaderLine('X-CSRF-Token'));
        self::assertSame('Bearer ' . self::accessToken('new'), $replay->getHeaderLine('Authorization'));
        self::assertSame('csrf-new', $replay->getHeaderLine('X-CSRF-Token'));
        self::assertSame('axiam_access=' . self::accessToken('old'), $original->getHeaderLine('Cookie'));
        self::assertSame('axiam_access=' . self::accessToken('new'), $replay->getHeaderLine('Cookie'));
    }

    /**
     * C164-10: the same through the SHIPPED wiring. An `AxiamClient` on a mock transport signs in,
     * a management write is refused with `401`, the session refreshes (rotating the cookies and
     * the CSRF token) and the write is replayed. Reverting the push order in `AxiamClient` makes the
     * replay carry the refused attempt's headers and this test fail.
     */
    public function testAnAxiamClientReplaysAfterARefreshWithFreshCredentials(): void
    {
        /** @var list<RequestInterface> $seen */
        $seen = [];
        $record = static function (Response $response) use (&$seen): callable {
            return static function (RequestInterface $request) use (&$seen, $response): Response {
                $seen[] = $request;

                return $response;
            };
        };
        $group = new Response(200, ['Content-Type' => 'application/json'], (string) json_encode([
            'id' => 'g1', 'tenant_id' => 't1', 'name' => 'staff', 'description' => '', 'metadata' => null,
            'created_at' => '2026-10-23T00:00:00Z', 'updated_at' => '2026-10-23T00:00:00Z',
        ]));
        $mock = new MockHandler([
            $record(new Response(200, [
                'Set-Cookie' => 'axiam_access=' . self::accessToken('old') . '; Path=/',
                'X-CSRF-Token' => 'csrf-old',
                'Content-Type' => 'application/json',
            ], (string) json_encode(['user' => ['id' => 'u1']]))),
            $record(new Response(401)),
            $record(new Response(200, [
                'Set-Cookie' => 'axiam_access=' . self::accessToken('new') . '; Path=/',
                'X-CSRF-Token' => 'csrf-new',
            ], '{}')),
            $record($group),
        ]);
        $client = new AxiamClient(
            'https://api.test',
            'acme',
            transportHandler: HandlerStack::create($mock),
            retryEnabled: false,
        );

        $client->login('alice@example.test', 'pw');
        $client->management()->groups()->create(new CreateGroupRequest(description: '', name: 'staff'));

        self::assertCount(4, $seen, 'login, refused write, refresh, replay');
        [, $refused, $refresh, $replay] = $seen;
        self::assertSame('/api/v1/groups', $refused->getUri()->getPath());
        self::assertSame('/api/v1/auth/refresh', $refresh->getUri()->getPath());
        self::assertSame('/api/v1/groups', $replay->getUri()->getPath());

        self::assertSame('Bearer ' . self::accessToken('old'), $refused->getHeaderLine('Authorization'));
        self::assertSame('csrf-old', $refused->getHeaderLine('X-CSRF-Token'));
        self::assertStringContainsString('axiam_access=' . self::accessToken('old'), $refused->getHeaderLine('Cookie'));

        self::assertSame('Bearer ' . self::accessToken('new'), $replay->getHeaderLine('Authorization'));
        self::assertSame('csrf-new', $replay->getHeaderLine('X-CSRF-Token'));
        self::assertStringContainsString('axiam_access=' . self::accessToken('new'), $replay->getHeaderLine('Cookie'));
        self::assertStringNotContainsString(self::accessToken('old'), $replay->getHeaderLine('Cookie'));
    }
}
