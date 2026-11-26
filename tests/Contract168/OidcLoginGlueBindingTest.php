<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract168;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Oidc\MemoryOidcStateStore;
use Axiam\Sdk\Oidc\OidcLoginFlow;
use Axiam\Sdk\Oidc\OidcLoginOutcome;
use Axiam\Sdk\Oidc\OidcStateEntry;
use Axiam\Sdk\Oidc\OidcStateStoreInterface;
use Axiam\Sdk\Oidc\OidcTokenSet;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;

/**
 * Security audit 2026-11-14, C7 and C6 (CONTRACT.md §12.8, contract 1.68): the "Login with
 * AXIAM" glue binds the callback to the browser that called the login route, and follows a
 * `return_to` only when it is a same-origin relative path.
 *
 * Driven at the {@see OidcLoginFlow} level (the one begin/complete path both framework
 * controllers call). The controllers' own cookie I/O is covered by
 * {@see OidcLoginGlueControllersMiddlewareTest}.
 *
 * `complete()` is called positionally here — (state, code, error, errorDescription,
 * successRedirect, onSuccess, bindingCookie, request) — so that the SAME test also runs, and
 * fails on its assertions rather than on an unknown named parameter, against the code that
 * predates the binding.
 */
final class OidcLoginGlueBindingTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const REDIRECT = 'https://app.test/callback';
    private const HOST_COOKIE = '__Host-axiam_oidc_bind';
    private const UNIFORM_MESSAGE = 'unknown, expired, or already-used login state';

    /** @var list<array<string,mixed>> */
    private array $history = [];

    private function discovery(): Response
    {
        return new Response(200, [], (string) json_encode([
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
    }

    private function tokenResponse(): Response
    {
        return new Response(200, [], (string) json_encode(['access_token' => 'a', 'token_type' => 'Bearer', 'expires_in' => 900]));
    }

    /** @param list<Response> $queue */
    private function client(array $queue): AxiamClient
    {
        $this->history = [];
        $stack = HandlerStack::create(new MockHandler($queue));
        $stack->push(Middleware::history($this->history));

        return new AxiamClient(self::BASE_URL, 'acme-tenant', oidcClientId: 'my-app', oidcTenantId: '55555555-5555-5555-5555-555555555555', transportHandler: $stack);
    }

    private function tokenRequests(): int
    {
        return count(array_filter($this->history, static fn (array $t): bool => str_ends_with($t['request']->getUri()->getPath(), '/oauth2/token')));
    }

    /** The binding cookie's VALUE out of a login's `Set-Cookie`. */
    private static function cookieValue(OidcLoginOutcome $outcome, string $name = self::HOST_COOKIE): string
    {
        self::assertNotNull(($outcome->setCookie ?? null), 'the login response must set the binding cookie');
        self::assertSame(1, preg_match('/^' . preg_quote($name, '/') . '=([^;]*);/', (string) ($outcome->setCookie ?? null), $m), (string) ($outcome->setCookie ?? null));

        return $m[1];
    }

    /** The binding cookie's value when the login set one, else `null` — for the tests that are about `return_to`, not the binding. */
    private static function cookieIfAny(OidcLoginOutcome $outcome, string $name = self::HOST_COOKIE): ?string
    {
        $setCookie = $outcome->setCookie ?? null;

        return is_string($setCookie) && preg_match('/^' . preg_quote($name, '/') . '=([^;]*);/', $setCookie, $m) === 1 ? $m[1] : null;
    }

    private static function stateOf(OidcLoginOutcome $outcome): string
    {
        parse_str((string) parse_url((string) $outcome->redirectUrl, PHP_URL_QUERY), $query);

        return (string) $query['state'];
    }

    /** A flow whose begin() has run; returns [flow, store, cookie value, state]. @return array{0:OidcLoginFlow,1:MemoryOidcStateStore,2:string,3:string} */
    private function begun(): array
    {
        // Discovery is fetched once and cached per client, so begin() consumes the one
        // discovery response and a callback's exchange consumes the token response.
        $store = new MemoryOidcStateStore();
        $flow = new OidcLoginFlow($this->client([$this->discovery(), $this->tokenResponse()]), $store, self::REDIRECT);
        $login = $flow->begin('/dashboard');

        return [$flow, $store, self::cookieValue($login), self::stateOf($login)];
    }

    // ==================================================================================
    // C7 — the login response sets the binding cookie
    // ==================================================================================

    public function testLoginSetsTheHostPrefixedBindingCookieAndStoresItsDigest(): void
    {
        $recorded = [];
        $store = new class ($recorded) implements OidcStateStoreInterface {
            /** @param list<OidcStateEntry> $saved */
            public function __construct(public array &$saved)
            {
            }

            public function save(OidcStateEntry $entry): void
            {
                $this->saved[] = $entry;
            }

            public function consume(string $state): ?OidcStateEntry
            {
                return null;
            }
        };
        $flow = new OidcLoginFlow($this->client([$this->discovery()]), $store, self::REDIRECT);

        $outcome = $flow->begin();

        self::assertSame(OidcLoginOutcome::KIND_REDIRECT, $outcome->kind);
        $cookie = (string) ($outcome->setCookie ?? null);
        $value = self::cookieValue($outcome);
        self::assertSame(1, preg_match('/^[A-Za-z0-9_-]{43}$/', $value), '32 random bytes, base64url without padding');
        foreach (['Path=/', 'HttpOnly', 'Secure', 'SameSite=Lax', 'Max-Age=600'] as $attribute) {
            self::assertStringContainsString('; ' . $attribute, $cookie);
        }
        self::assertStringNotContainsString('Domain', $cookie);
        self::assertCount(1, $store->saved);
        self::assertSame(hash('sha256', $value), $store->saved[0]->bindingDigest, 'the entry holds the SHA-256, never the value');
    }

    public function testEveryLoginDrawsAFreshValue(): void
    {
        $flow = new OidcLoginFlow($this->client([$this->discovery()]), new MemoryOidcStateStore(), self::REDIRECT);

        self::assertNotSame(self::cookieValue($flow->begin()), self::cookieValue($flow->begin()));
    }

    public function testLoopbackPlainHttpUsesTheFallbackNameWithoutSecureAndNowhereElseDoes(): void
    {
        foreach (['http://localhost:8080/cb', 'http://127.0.0.1/cb', 'http://[::1]:3000/cb', 'HTTP://LocalHost/cb'] as $uri) {
            $flow = new OidcLoginFlow($this->client([$this->discovery()]), new MemoryOidcStateStore(), $uri);
            $outcome = $flow->begin();
            $cookie = (string) ($outcome->setCookie ?? null);
            self::assertSame('axiam_oidc_bind', $flow->bindingCookieName(), $uri);
            self::assertStringStartsWith('axiam_oidc_bind=', $cookie, $uri);
            self::assertStringNotContainsString('Secure', $cookie, $uri);
            self::assertStringContainsString('HttpOnly; SameSite=Lax', $cookie, $uri);
        }

        foreach ([
            'https://localhost/cb',                 // https on loopback: the __Host- name
            'http://app.test/cb',                   // plain HTTP to another host: the browser drops it, the callback fails closed
            'http://localhost.evil.example/cb',     // a host that merely starts with localhost
            'http://127.0.0.1.evil.example/cb',
            'http://evil.example/cb?x=http://localhost/',
            'http://localhost@evil.example/cb',     // userinfo, host is evil.example
        ] as $uri) {
            self::assertSame(self::HOST_COOKIE, OidcLoginFlow::bindingCookieNameFor($uri), $uri);
        }
    }

    // ==================================================================================
    // C7 — the callback
    // ==================================================================================

    /**
     * The C7 reproduction, using nothing but the API that existed before the binding: an
     * attacker's login, completed by a request that never touched the login route (no cookie of
     * any kind), must NOT complete.
     */
    public function testALoginCompletedByARequestWithNoCookieIsRefused(): void
    {
        $flow = new OidcLoginFlow($this->client([$this->discovery(), $this->tokenResponse()]), new MemoryOidcStateStore(), self::REDIRECT);
        $login = $flow->begin();
        $called = false;

        $outcome = $flow->complete(self::stateOf($login), 'attackers-code', null, null, null, function () use (&$called): void {
            $called = true;
        });

        self::assertSame(401, $outcome->status, 'the victim\'s request completed the attacker\'s login');
        self::assertFalse($called, 'onSuccess ran with the attacker\'s tokens during the victim\'s request');
        self::assertSame(0, $this->tokenRequests(), 'the attacker\'s code was exchanged');
    }

    public function testCallbackWithNoBindingCookieIsTheUniform401WithNoExchangeAndNoOnSuccess(): void
    {
        [$flow, , $cookie, $state] = $this->begun();
        $before = count($this->history);
        $called = false;

        $refused = $flow->complete($state, 'attackers-code', null, null, null, function () use (&$called): void {
            $called = true;
        }, null, new \stdClass());

        self::assertSame(401, $refused->status);
        self::assertSame('authentication_failed', $refused->error);
        self::assertSame(self::UNIFORM_MESSAGE, $refused->message);
        self::assertFalse($called, 'onSuccess must not run');
        self::assertCount($before, $this->history, 'the code must not be exchanged: no request of any kind');
        self::assertSame(0, $this->tokenRequests());
        self::assertNotNull(($refused->setCookie ?? null));
        self::assertStringContainsString('Max-Age=0', (string) ($refused->setCookie ?? null));

        // The state is single-use whatever happened: the right browser, retrying, is refused too.
        $retry = $flow->complete($state, 'attackers-code', null, null, null, null, $cookie);
        self::assertSame(401, $retry->status);
        self::assertSame(0, $this->tokenRequests());
    }

    public function testCallbackWithAnotherLoginsCookieIsTheSame401(): void
    {
        [$flow, , , $state] = $this->begun();
        $before = count($this->history);
        $called = false;

        $otherBrowsersCookie = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $refused = $flow->complete($state, 'code', null, null, null, function () use (&$called): void {
            $called = true;
        }, $otherBrowsersCookie);

        self::assertSame(401, $refused->status);
        self::assertSame(self::UNIFORM_MESSAGE, $refused->message);
        self::assertFalse($called);
        self::assertCount($before, $this->history);
    }

    public function testTheBindingRefusalIsByteForByteTheUnknownStateRefusal(): void
    {
        [$flow, , , $state] = $this->begun();

        $unbound = $flow->complete($state, 'code', null, null, null, null, null);
        $unknown = $flow->complete('never-issued', 'code', null, null, null, null, 'whatever');

        self::assertSame($unknown->status, $unbound->status);
        self::assertSame($unknown->errorBody(), $unbound->errorBody(), 'the refusal must not say which check failed');
    }

    public function testCallbackFromTheBrowserThatStartedTheLoginSucceedsAndOnSuccessGetsTheRequest(): void
    {
        [$flow, , $cookie, $state] = $this->begun();
        $request = new \stdClass();
        $received = null;
        $entryReturnTo = null;

        $outcome = $flow->complete($state, 'a-code', null, null, null, function (OidcTokenSet $tokens, OidcStateEntry $entry, mixed $req = null) use (&$received, &$entryReturnTo): void {
            $received = $req;
            $entryReturnTo = $entry->returnTo;
            self::assertSame('a', $tokens->accessToken->reveal());
        }, $cookie, $request);

        self::assertSame(OidcLoginOutcome::KIND_REDIRECT, $outcome->kind);
        self::assertSame('/dashboard', $outcome->redirectUrl);
        self::assertSame($request, $received, 'onSuccess receives the very request that completed the sign-in (§12.8 rule 2)');
        self::assertSame('/dashboard', $entryReturnTo);
        self::assertSame(1, $this->tokenRequests());
        self::assertStringStartsWith(self::HOST_COOKIE . '=;', (string) ($outcome->setCookie ?? null));
        self::assertStringContainsString('Max-Age=0', (string) ($outcome->setCookie ?? null));

        // A replay finds nothing, whatever cookie it carries.
        self::assertSame(401, $flow->complete($state, 'a-code', null, null, null, null, $cookie)->status);
    }

    public function testATwoParameterOnSuccessClosureKeepsWorking(): void
    {
        [$flow, , $cookie, $state] = $this->begun();
        $seen = [];

        $flow->complete($state, 'a-code', null, null, null, function (OidcTokenSet $tokens, OidcStateEntry $entry) use (&$seen): void {
            $seen[] = $entry->state;
        }, $cookie, new \stdClass());

        self::assertSame([$state], $seen);
    }

    public function testAnEntryStoredWithNoDigestIsRefusedEvenWithACookie(): void
    {
        $store = new MemoryOidcStateStore();
        $store->save(new OidcStateEntry('state-1', 'nonce-1', new Sensitive('verifier-1'), self::REDIRECT)); // a 1.67 entry
        $flow = new OidcLoginFlow($this->client([$this->discovery(), $this->tokenResponse()]), $store, self::REDIRECT);
        $called = false;

        $refused = $flow->complete('state-1', 'code', null, null, null, function () use (&$called): void {
            $called = true;
        }, 'some-cookie-value');

        self::assertSame(401, $refused->status);
        self::assertFalse($called);
        self::assertSame(0, $this->tokenRequests());
    }

    public function testEveryOtherCallbackOutcomeAlsoClearsTheCookie(): void
    {
        [$flow, , $cookie, $state] = $this->begun();
        $clears = static fn (OidcLoginOutcome $o): bool => ($o->setCookie ?? null) !== null
            && str_starts_with(($o->setCookie ?? null), self::HOST_COOKIE . '=;')
            && str_contains(($o->setCookie ?? null), 'Max-Age=0')
            && str_contains(($o->setCookie ?? null), 'Path=/')
            && str_contains(($o->setCookie ?? null), 'Secure');

        self::assertTrue($clears($flow->complete(null, null, 'access_denied', 'no', null, null, $cookie)), 'idp error');
        self::assertTrue($clears($flow->complete(null, 'code', null, null, null, null, $cookie)), 'missing state');
        self::assertTrue($clears($flow->complete('never-issued', 'code', null, null, null, null, $cookie)), 'unknown state');
        self::assertTrue($clears($flow->complete($state, 'code', null, null, null, null, null)), 'binding refusal');
    }

    public function testTheCookieValueAndItsDigestAreNeverLogged(): void
    {
        $logger = new class () extends AbstractLogger {
            /** @var list<string> */
            public array $lines = [];

            public function log(mixed $level, string|\Stringable $message, array $context = []): void
            {
                $this->lines[] = $message . ' ' . json_encode($context);
            }
        };
        $store = new MemoryOidcStateStore();
        $flow = new OidcLoginFlow($this->client([$this->discovery()]), $store, self::REDIRECT, null, $logger);
        $login = $flow->begin();
        $value = self::cookieValue($login);
        $flow->complete(self::stateOf($login), 'code', null, null, null, null, 'a-different-cookie-value');
        $flow->complete('never', 'code', null, null, null, null, $value);

        $logged = implode("\n", $logger->lines);
        self::assertStringNotContainsString($value, $logged);
        self::assertStringNotContainsString(hash('sha256', $value), $logged);
        self::assertStringNotContainsString('a-different-cookie-value', $logged);
    }

    // ==================================================================================
    // C6 — return_to
    // ==================================================================================

    /** @return iterable<string, array{string}> */
    public static function unsafeReturnTo(): iterable
    {
        yield 'absolute https URL' => ['https://evil.example/phish'];
        yield 'absolute http URL' => ['http://evil.example/'];
        yield 'scheme-relative' => ['//evil.example/phish'];
        yield 'slash-backslash' => ['/\\evil.example'];
        yield 'backslash inside' => ['/a\\b'];
        yield 'CR' => ["/a\r"];
        yield 'LF (header injection)' => ["/a\nSet-Cookie: x=1"];
        yield 'NUL' => ["/a\0b"];
        yield 'DEL' => ["/a\x7fb"];
        yield 'javascript scheme' => ['javascript:alert(1)'];
        yield 'relative, no leading slash' => ['dashboard'];
        yield 'empty' => [''];
    }

    /** @dataProvider unsafeReturnTo */
    public function testAnUnsafeReturnToIsDroppedAtLoginAndNeverFollowed(string $returnTo): void
    {
        $store = new MemoryOidcStateStore();
        $flow = new OidcLoginFlow($this->client([$this->discovery(), $this->tokenResponse()]), $store, self::REDIRECT);
        $login = $flow->begin($returnTo);
        $stateStored = null;
        $outcome = $flow->complete(self::stateOf($login), 'code', null, null, null, function (OidcTokenSet $t, OidcStateEntry $entry) use (&$stateStored): void {
            $stateStored = $entry;
        }, self::cookieIfAny($login));

        self::assertNotNull($stateStored);
        self::assertNull($stateStored->returnTo, 'dropped when stored');
        self::assertSame(OidcLoginOutcome::KIND_JSON, $outcome->kind, 'falls back to the JSON summary, never a redirect to it');
    }

    /** @dataProvider unsafeReturnTo */
    public function testAnUnsafeReturnToInAStoreIsNotFollowedEither(string $returnTo): void
    {
        // An entry a caller-supplied store hands back, or one written by older glue: the check at
        // the redirect is the one that matters.
        $store = new MemoryOidcStateStore();
        $store->save(new OidcStateEntry('state-1', 'n', new Sensitive('v'), self::REDIRECT, $returnTo, hash('sha256', 'cookie-1')));
        $flow = new OidcLoginFlow($this->client([$this->discovery(), $this->tokenResponse()]), $store, self::REDIRECT);

        $outcome = $flow->complete('state-1', 'code', null, null, null, null, 'cookie-1');

        self::assertSame(OidcLoginOutcome::KIND_JSON, $outcome->kind);
        self::assertNull($outcome->redirectUrl);
    }

    public function testASameOriginRelativePathIsStoredAndFollowed(): void
    {
        $flow = new OidcLoginFlow($this->client([$this->discovery(), $this->tokenResponse()]), new MemoryOidcStateStore(), self::REDIRECT);
        $login = $flow->begin('/dashboard?tab=1#frag');

        $outcome = $flow->complete(self::stateOf($login), 'code', null, null, null, null, self::cookieIfAny($login));

        self::assertSame(OidcLoginOutcome::KIND_REDIRECT, $outcome->kind);
        self::assertSame('/dashboard?tab=1#frag', $outcome->redirectUrl);
    }

    public function testTheConfiguredSuccessRedirectStillWinsOverAValidReturnTo(): void
    {
        $flow = new OidcLoginFlow($this->client([$this->discovery(), $this->tokenResponse()]), new MemoryOidcStateStore(), self::REDIRECT);
        $login = $flow->begin('/dashboard');

        $outcome = $flow->complete(self::stateOf($login), 'code', null, null, '/welcome', null, self::cookieIfAny($login));

        self::assertSame('/welcome', $outcome->redirectUrl);
    }

    public function testAnIntegratorPredicateWidensTheRuleOnlyForWhatItAcceptsAndOnlyForValuesTheDefaultRefuses(): void
    {
        $seen = [];
        $predicate = function (string $value) use (&$seen): bool {
            $seen[] = $value;

            return $value === 'https://app.example/x';
        };
        $flow = new OidcLoginFlow($this->client([$this->discovery(), $this->tokenResponse(), $this->tokenResponse()]), new MemoryOidcStateStore(), self::REDIRECT, null, new \Psr\Log\NullLogger(), $predicate);

        $accepted = $flow->begin('https://app.example/x');
        $outcome = $flow->complete(self::stateOf($accepted), 'code', null, null, null, null, self::cookieIfAny($accepted));
        self::assertSame('https://app.example/x', $outcome->redirectUrl, 'the allow-listed absolute URL is followed');

        $refused = $flow->begin('https://evil.example/x');
        $outcome = $flow->complete(self::stateOf($refused), 'code', null, null, null, null, self::cookieIfAny($refused));
        self::assertNull($outcome->redirectUrl, 'anything else the predicate does not accept is still not followed');

        self::assertNotContains('/dashboard', $seen);
        $flow->begin('/fine'); // a value the default rule accepts is not offered to the predicate
        self::assertNotContains('/fine', $seen);
    }

    public function testAPredicateThatThrowsAcceptsNothing(): void
    {
        $flow = new OidcLoginFlow($this->client([$this->discovery(), $this->tokenResponse()]), new MemoryOidcStateStore(), self::REDIRECT, null, new \Psr\Log\NullLogger(), static function (string $v): bool {
            throw new \RuntimeException('boom');
        });
        $login = $flow->begin('https://app.example/x');

        $outcome = $flow->complete(self::stateOf($login), 'code', null, null, null, null, self::cookieIfAny($login));

        self::assertNull($outcome->redirectUrl);
    }
}
