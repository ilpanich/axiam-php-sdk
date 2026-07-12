<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Rest\AuthMiddleware;
use Axiam\Sdk\Session;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Cookie\SetCookie;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * Covers the two host-isolation / CSRF branches of {@see AuthMiddleware} (CONTRACT.md
 * §3/§5) that the AxiamClient-level tests do not reach directly: a cross-host request is
 * forwarded completely undecorated (no tenant/bearer/CSRF leak to a third-party URL), and
 * a same-origin state-changing request carries the `X-CSRF-Token` header once a prior
 * refresh has captured one via {@see Session}. The middleware is driven in isolation with
 * a captured inner handler, mirroring Guzzle's own documented handler-stack test idiom.
 */
final class RestAuthDecorationTest extends TestCase
{
    private const BASE_URL = 'https://api.test';

    /** @param array<string,mixed> $claims */
    private function jwtWithClaims(array $claims): string
    {
        $segment = static fn (array $data): string => rtrim(
            strtr(base64_encode((string) json_encode($data)), '+/', '-_'),
            '=',
        );

        return $segment(['alg' => 'none', 'typ' => 'JWT']) . '.' . $segment($claims) . '.signature';
    }

    private function jarWith(string $accessToken): CookieJar
    {
        $jar = new CookieJar();
        $jar->setCookie(new SetCookie([
            'Name' => 'axiam_access',
            'Value' => $accessToken,
            'Domain' => 'api.test',
            'Path' => '/',
        ]));

        return $jar;
    }

    public function testCrossHostRequestIsForwardedUndecorated(): void
    {
        $session = new Session(
            self::BASE_URL,
            'acme-tenant',
            new Client(['handler' => HandlerStack::create(new MockHandler([]))]),
            $this->jarWith($this->jwtWithClaims(['tenant_id' => 't-uuid', 'org_id' => 'o-uuid'])),
        );

        $captured = null;
        $decorated = (new AuthMiddleware($session))(
            function (RequestInterface $request, array $options) use (&$captured) {
                $captured = $request;

                return Create::promiseFor(new Response(200));
            },
        );

        $decorated(new Request('GET', 'https://other.example/resource'), []);

        self::assertNotNull($captured);
        self::assertFalse($captured->hasHeader('X-Tenant-ID'), 'cross-host request must not carry the tenant header');
        self::assertFalse($captured->hasHeader('Authorization'), 'cross-host request must not carry the bearer token');
    }

    public function testStateChangingRequestCarriesCapturedCsrfToken(): void
    {
        // Drive a successful refresh so the session captures an X-CSRF-Token header.
        $http = new Client([
            'handler' => HandlerStack::create(new MockHandler([
                new Response(200, ['X-CSRF-Token' => 'csrf-abc'], '{}'),
            ])),
        ]);
        $session = new Session(
            self::BASE_URL,
            'acme-tenant',
            $http,
            $this->jarWith($this->jwtWithClaims(['tenant_id' => 't-uuid', 'org_id' => 'o-uuid'])),
        );
        $session->refreshIfNeeded()->wait();
        self::assertSame('csrf-abc', $session->csrfToken());

        $captured = null;
        $decorated = (new AuthMiddleware($session))(
            function (RequestInterface $request, array $options) use (&$captured) {
                $captured = $request;

                return Create::promiseFor(new Response(200));
            },
        );

        $decorated(new Request('POST', self::BASE_URL . '/api/v1/authz/check'), []);

        self::assertNotNull($captured);
        self::assertSame('csrf-abc', $captured->getHeaderLine('X-CSRF-Token'));
        self::assertStringStartsWith('Bearer ', $captured->getHeaderLine('Authorization'));
    }
}
