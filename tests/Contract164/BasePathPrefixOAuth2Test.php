<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract164;

use Axiam\Sdk\Rest\AuthMiddleware;
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
 * C163-19: the `/oauth2/*` rule (CONTRACT.md §6.1 rule 11, §12.1 rule 3) holds for a base URL
 * that carries a path prefix, under which the endpoints live at `<prefix>/oauth2/*`.
 */
final class BasePathPrefixOAuth2Test extends TestCase
{
    /** @return iterable<string,array{string,string,bool}> */
    public static function paths(): iterable
    {
        yield 'unprefixed oauth2' => ['https://api.test', '/oauth2/token', true];
        yield 'prefixed oauth2' => ['https://gw.test/axiam', '/axiam/oauth2/token', true];
        yield 'prefix with trailing slash' => ['https://gw.test/axiam/', '/axiam/oauth2/device_authorization', true];
        yield 'prefixed API request keeps its credentials' => ['https://gw.test/axiam', '/axiam/api/v1/groups', false];
        yield 'oauth2 outside the prefix is not one' => ['https://gw.test/axiam', '/oauth2/token', false];
    }

    /** @dataProvider paths */
    public function testOAuth2RequestsCarryNoSessionCredentialsUnderAnyBasePath(string $base, string $path, bool $oauth2): void
    {
        // The request as the base handler receives it, after every middleware (Guzzle's cookie
        // middleware included) has run.
        $seen = null;
        $stack = HandlerStack::create(new MockHandler([
            static function (RequestInterface $request) use (&$seen): Response {
                $seen = $request;

                return new Response(200);
            },
        ]));

        $host = (string) parse_url($base, PHP_URL_HOST);
        $jar = new CookieJar();
        $jar->setCookie(new SetCookie(['Name' => 'axiam_access', 'Value' => 'at', 'Domain' => $host, 'Path' => '/']));
        $session = new Session($base, 'acme', new Client(['handler' => $stack]), $jar);
        $session->captureCsrfTokenFromResponse(new Response(200, ['X-CSRF-Token' => 'csrf']));
        $stack->push(new AuthMiddleware($session), 'axiam_auth');

        (new Client(['handler' => $stack, 'cookies' => $jar]))->post('https://' . $host . $path);

        $request = $seen;
        self::assertInstanceOf(RequestInterface::class, $request);
        self::assertSame(!$oauth2, $request->hasHeader('Authorization'), 'Authorization on ' . $path);
        self::assertSame(!$oauth2, $request->hasHeader('X-CSRF-Token'), 'X-CSRF-Token on ' . $path);
        self::assertSame(!$oauth2, $request->hasHeader('Cookie'), 'Cookie on ' . $path);
    }
}
