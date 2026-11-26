<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract168;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Laravel\OidcCallbackController as LaravelCallback;
use Axiam\Sdk\Laravel\OidcLoginController as LaravelLogin;
use Axiam\Sdk\Oidc\MemoryOidcStateStore;
use Axiam\Sdk\Oidc\OidcLoginFlow;
use Axiam\Sdk\Symfony\OidcCallbackController as SymfonyCallback;
use Axiam\Sdk\Symfony\OidcLoginController as SymfonyLogin;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response as PsrResponse;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * CONTRACT.md §12.8 (contract 1.68; C7, C6) at the controller layer: the Laravel and Symfony
 * login controllers SET the browser-binding cookie and read the `return_to` the user supplied
 * through the one validating flow, and the callback controllers read that cookie back and CLEAR
 * it. Both frameworks run every case, against the same flow, so they cannot drift.
 *
 * Lives with the framework-bridge tests: it needs the dev-only symfony/http-foundation.
 */
final class OidcLoginGlueControllersMiddlewareTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const REDIRECT = 'https://app.test/callback';
    private const COOKIE = '__Host-axiam_oidc_bind';

    /** @var list<array<string,mixed>> */
    private array $history = [];

    /** @return iterable<string, array{class-string, class-string}> */
    public static function frameworks(): iterable
    {
        yield 'Laravel' => [LaravelLogin::class, LaravelCallback::class];
        yield 'Symfony' => [SymfonyLogin::class, SymfonyCallback::class];
    }

    private function flow(?\Closure $allowReturnTo = null): OidcLoginFlow
    {
        $discovery = new PsrResponse(200, [], (string) json_encode([
            'issuer' => self::BASE_URL,
            'authorization_endpoint' => self::BASE_URL . '/oauth2/authorize',
            'token_endpoint' => self::BASE_URL . '/oauth2/token',
            'userinfo_endpoint' => self::BASE_URL . '/oauth2/userinfo',
            'jwks_uri' => self::BASE_URL . '/oauth2/jwks',
            'revocation_endpoint' => self::BASE_URL . '/oauth2/revoke',
            'introspection_endpoint' => self::BASE_URL . '/oauth2/introspect',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['EdDSA'],
            'scopes_supported' => ['openid'],
            'token_endpoint_auth_methods_supported' => ['client_secret_post'],
            'claims_supported' => ['sub'],
            'grant_types_supported' => ['authorization_code'],
        ]));
        $token = new PsrResponse(200, [], (string) json_encode(['access_token' => 'a', 'token_type' => 'Bearer', 'expires_in' => 900]));
        $this->history = [];
        $stack = HandlerStack::create(new MockHandler([$discovery, $token, $token]));
        $stack->push(Middleware::history($this->history));
        $client = new AxiamClient(self::BASE_URL, 'acme-tenant', oidcClientId: 'my-app', oidcTenantId: '55555555-5555-5555-5555-555555555555', transportHandler: $stack);

        return new OidcLoginFlow($client, new MemoryOidcStateStore(), self::REDIRECT, null, new \Psr\Log\NullLogger(), $allowReturnTo);
    }

    private function tokenRequests(): int
    {
        return count(array_filter($this->history, static fn (array $t): bool => str_ends_with($t['request']->getUri()->getPath(), '/oauth2/token')));
    }

    /** @return array{0:string,1:string} [state, binding cookie value] of a login response */
    private static function parseLogin(Response $response): array
    {
        self::assertInstanceOf(RedirectResponse::class, $response);
        parse_str((string) parse_url($response->getTargetUrl(), PHP_URL_QUERY), $query);
        $cookies = $response->headers->getCookies();
        self::assertCount(1, $cookies, 'the login response sets exactly the binding cookie');
        self::assertSame(self::COOKIE, $cookies[0]->getName());

        return [(string) $query['state'], (string) $cookies[0]->getValue()];
    }

    /**
     * @dataProvider frameworks
     *
     * @param class-string $login
     */
    public function testTheLoginResponseSetsTheBindingCookieWithTheRequiredAttributes(string $login): void
    {
        $response = (new $login($this->flow()))(Request::create('/login'));

        [, $value] = self::parseLogin($response);
        $cookie = $response->headers->getCookies()[0];
        self::assertSame(1, preg_match('/^[A-Za-z0-9_-]{43}$/', $value));
        self::assertTrue($cookie->isHttpOnly());
        self::assertTrue($cookie->isSecure());
        self::assertSame('lax', $cookie->getSameSite());
        self::assertSame('/', $cookie->getPath());
        self::assertNull($cookie->getDomain(), '__Host- forbids a Domain attribute');
        self::assertLessThanOrEqual(600, $cookie->getMaxAge());
        self::assertGreaterThan(0, $cookie->getMaxAge());
    }

    /**
     * @dataProvider frameworks
     *
     * @param class-string $login
     * @param class-string $callback
     */
    public function testACallbackCarryingTheLoginsCookieSucceedsAndClearsIt(string $login, string $callback): void
    {
        $flow = $this->flow();
        [$state, $value] = self::parseLogin((new $login($flow))(Request::create('/login?return_to=/dashboard')));

        $request = Request::create('/callback?state=' . $state . '&code=a-code', 'GET', [], [self::COOKIE => $value]);
        $response = (new $callback($flow))($request);

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('/dashboard', $response->getTargetUrl());
        self::assertSame(1, $this->tokenRequests());
        $cleared = $response->headers->getCookies()[0];
        self::assertSame(self::COOKIE, $cleared->getName());
        self::assertSame('', (string) $cleared->getValue());
        self::assertLessThan(time(), $cleared->getExpiresTime() ?: 1, 'a clearing cookie is already expired');
        self::assertTrue($cleared->isSecure());
        self::assertTrue($cleared->isHttpOnly());
    }

    /**
     * @dataProvider frameworks
     *
     * @param class-string $login
     * @param class-string $callback
     */
    public function testACallbackFromAnotherBrowserIsTheUniform401WithNoTokenRequestAndClearsTheCookie(string $login, string $callback): void
    {
        $flow = $this->flow();
        [$state] = self::parseLogin((new $login($flow))(Request::create('/login')));

        // No cookie at all, then (the state being single-use) the same with another login's value.
        $response = (new $callback($flow))(Request::create('/callback?state=' . $state . '&code=attackers-code'));

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
        self::assertSame(
            ['error' => 'authentication_failed', 'message' => 'unknown, expired, or already-used login state'],
            json_decode((string) $response->getContent(), true),
        );
        self::assertSame(0, $this->tokenRequests(), 'the attacker\'s code must not be exchanged');
        self::assertSame('', (string) $response->headers->getCookies()[0]->getValue());
    }

    /**
     * @dataProvider frameworks
     *
     * @param class-string $login
     * @param class-string $callback
     */
    public function testACallbackWithADifferentCookieValueIsRefused(string $login, string $callback): void
    {
        $flow = $this->flow();
        [$state] = self::parseLogin((new $login($flow))(Request::create('/login')));

        $response = (new $callback($flow))(Request::create('/callback?state=' . $state . '&code=c', 'GET', [], [self::COOKIE => 'another-logins-value']));

        self::assertSame(401, $response->getStatusCode());
        self::assertSame(0, $this->tokenRequests());
    }

    /**
     * @dataProvider frameworks
     *
     * @param class-string $login
     * @param class-string $callback
     */
    public function testAnAbsoluteReturnToFromTheQueryStringIsNeverRedirectedTo(string $login, string $callback): void
    {
        $flow = $this->flow();
        [$state, $value] = self::parseLogin((new $login($flow))(Request::create('/login?return_to=' . rawurlencode('https://evil.example/phish'))));

        $response = (new $callback($flow))(Request::create('/callback?state=' . $state . '&code=a-code', 'GET', [], [self::COOKIE => $value]));

        self::assertInstanceOf(JsonResponse::class, $response, 'no redirect: the JSON summary');
        self::assertSame(200, $response->getStatusCode());
        self::assertStringNotContainsString('evil.example', (string) $response->headers->get('Location'));
    }

    /**
     * Decision 7 (login-glue-binding.md, TYP-R3-1): the `Location` of the callback's redirect
     * carries the percent-encoded form of the destination, produced by the adapter where it
     * writes the header, whatever the application's `allowReturnTo` admitted. The destination
     * reaches the flow DECODED (the framework already decoded the `return_to` query parameter).
     *
     * @return iterable<string, array{string, string}> [raw return_to, expected Location]
     */
    public static function redirectTargets(): iterable
    {
        yield 'a space' => ['/a b', '/a%20b'];
        yield 'a non-ASCII character' => ['/café', '/caf%C3%A9'];
        yield 'a three-byte character' => ['/€', '/%E2%82%AC'];
        yield 'an existing escape is kept' => ['/a%20b', '/a%20b'];
        yield 'a percent that starts no escape' => ['/100%', '/100%25'];
        yield 'a CR/LF an integrator predicate admitted' => ["/a\r\nSet-Cookie: x=y", '/a%0D%0ASet-Cookie:%20x=y'];
        yield 'quote, angle brackets and backtick' => ['/a"<>`', '/a%22%3C%3E%60'];
        yield 'a percent before a percent-escape' => ['/%%41', '/%25%41'];
        yield 'a truncated escape' => ['/a%2', '/a%252'];
        yield 'a backslash an integrator predicate admitted is kept' => ['/a\\b', '/a\\b'];
        yield 'invalid UTF-8 becomes U+FFFD' => ["/a\xffb", '/a%EF%BF%BDb'];
        yield 'a raw 0xFF byte (returnTo=%FF) is U+FFFD, not %FF' => ["/\xff", '/%EF%BF%BD'];
        yield 'plain path with query is untouched' => ['/dashboard?tab=1&x=2#top', '/dashboard?tab=1&x=2#top'];
    }

    /**
     * @dataProvider redirectTargets
     */
    public function testTheCallbackRedirectLocationIsPercentEncodedAsciiInBothFrameworks(string $returnTo, string $expected): void
    {
        foreach ([[LaravelLogin::class, LaravelCallback::class], [SymfonyLogin::class, SymfonyCallback::class]] as [$login, $callback]) {
            // A predicate that admits everything, standing in for an integrator who widened the rule.
            $flow = $this->flow(static fn (string $candidate): bool => true);
            $loginRequest = Request::create('/login');
            $loginRequest->query->set('return_to', $returnTo);
            [$state, $value] = self::parseLogin((new $login($flow))($loginRequest));

            $response = (new $callback($flow))(Request::create('/callback?state=' . $state . '&code=a-code', 'GET', [], [self::COOKIE => $value]));

            self::assertInstanceOf(RedirectResponse::class, $response, $login);
            $location = (string) $response->headers->get('Location');
            self::assertSame($expected, $location, $callback);
            self::assertSame(1, preg_match('/^[\x21-\x7e]*$/', $location), 'pure visible ASCII: no space, CR, LF or byte above 0x7e');
            self::assertCount(1, $response->headers->getCookies(), 'no header was injected; only the clearing cookie is set');
            self::assertSame(self::COOKIE, $response->headers->getCookies()[0]->getName());
            self::assertSame(1, $this->tokenRequests(), 'the sign-in completed once');
        }
    }
}
