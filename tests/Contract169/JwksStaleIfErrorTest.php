<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract169;

use Axiam\Sdk\Auth\JwksVerifier;
use Axiam\Sdk\Tests\Fixtures\AccessTokenFixtureTrait;
use GuzzleHttp\Client;
use GuzzleHttp\Promise\FulfilledPromise;
use GuzzleHttp\Promise\RejectedPromise;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * Contract 1.69 (CONTRACT.md §12.4 rule 2 "Stale-if-error, bounded"; owner decision D-10): the
 * JWKS cache's age runs from the last SUCCESSFUL fetch; a failed refresh never discards the held
 * keys nor moves that anchor; the held keys verify until exactly TTL + 300 s after it and not
 * after; an unknown-`kid` refresh that fails refuses that token and never extends the window.
 * The clock is injected and never slept.
 */
final class JwksStaleIfErrorTest extends TestCase
{
    use AccessTokenFixtureTrait;

    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';
    private const TTL = 300;
    private const T0 = 1_800_000_000;

    /** @var 'ok'|'empty'|'status500'|'status204'|'transport'|'notjwks'|'notmodified' what /oauth2/jwks does now */
    private string $mode = 'ok';

    private int $now = self::T0;

    /** @var list<RequestInterface> */
    private array $jwksRequests = [];

    private string $cacheControl = '';

    /** @var list<array<string,mixed>> */
    private array $publishedKeys = [];

    protected function setUp(): void
    {
        $this->mode = 'ok';
        $this->now = self::T0;
        $this->jwksRequests = [];
        $this->cacheControl = '';
        $jwks = json_decode((string) file_get_contents(__DIR__ . '/../Fixtures/ed25519_jwks.json'), true);
        self::assertIsArray($jwks);
        $this->publishedKeys = $jwks['keys'];
    }

    private function verifier(int $ttl = self::TTL): JwksVerifier
    {
        $handler = function (RequestInterface $request) {
            $path = $request->getUri()->getPath();
            if ($path === '/.well-known/openid-configuration') {
                return new FulfilledPromise(new Response(200, [], (string) json_encode(['jwks_uri' => self::BASE_URL . '/oauth2/jwks'])));
            }
            if ($path !== '/oauth2/jwks') {
                return new FulfilledPromise(new Response(404));
            }
            $this->jwksRequests[] = $request;
            $headers = ['ETag' => '"v1"'] + ($this->cacheControl !== '' ? ['Cache-Control' => $this->cacheControl] : []);

            return match ($this->mode) {
                'ok' => new FulfilledPromise(new Response(200, $headers, (string) json_encode(['keys' => $this->publishedKeys]))),
                'empty' => new FulfilledPromise(new Response(200, $headers, '{"keys":[]}')),
                'status500' => new FulfilledPromise(new Response(500, [], '{"keys":[]}')),
                'status204' => new FulfilledPromise(new Response(204)),
                'notjwks' => new FulfilledPromise(new Response(200, $headers, '<html>captive portal</html>')),
                'notmodified' => new FulfilledPromise(new Response(304, $headers)),
                default => new RejectedPromise(new \RuntimeException('connection refused')),
            };
        };

        return new JwksVerifier(new Client(['handler' => $handler]), self::BASE_URL, $ttl, null, null, null, fn (): int => $this->now);
    }

    private function heldKidToken(): string
    {
        return $this->mintAccessToken();
    }

    private function unknownKidToken(): string
    {
        return $this->mintAccessToken([], ['kid' => 'forged-' . bin2hex(random_bytes(8))]);
    }

    private function accepts(JwksVerifier $v, ?string $token = null): bool
    {
        return is_array($v->verify($token ?? $this->heldKidToken(), self::TENANT));
    }

    /** The §12.4 conformance test for the stale window, step by step. */
    public function testTheBoundedStaleWindowConformanceSequence(): void
    {
        $v = $this->verifier();
        self::assertTrue($this->accepts($v), 'cold fill at T0');

        // TTL + 1 s: a refresh is due and fails; the held key still verifies.
        $this->now = self::T0 + self::TTL + 1;
        $this->mode = 'transport';
        self::assertTrue($this->accepts($v), 'held kid accepted at TTL+1 s while the endpoint is down');

        // An EMPTY key set is a failure, not a replacement.
        $this->mode = 'empty';
        $this->now = self::T0 + self::TTL + 2 + 60; // past the failed-attempt window, so it is fetched
        self::assertTrue($this->accepts($v), 'an empty-set response leaves the held kid accepted');

        // TTL + 250 s: an unknown kid is refused, the held kid is still accepted.
        $this->mode = 'transport';
        $this->now = self::T0 + self::TTL + 250;
        self::assertFalse($this->accepts($v, $this->unknownKidToken()), 'unknown kid refused at TTL+250 s');
        self::assertTrue($this->accepts($v), 'held kid still accepted at TTL+250 s');

        // TTL + 300 s is still inside; TTL + 301 s is past the bound, from the ANCHOR (T0), not from any failed attempt.
        $this->now = self::T0 + self::TTL + 300;
        self::assertTrue($this->accepts($v), 'held kid accepted at exactly TTL+300 s');
        $this->now = self::T0 + self::TTL + 301;
        self::assertFalse($this->accepts($v), 'held kid refused at TTL+301 s');

        // One successful fetch re-opens the path.
        $this->mode = 'ok';
        $this->now = self::T0 + self::TTL + 400;
        self::assertTrue($this->accepts($v), 'accepted again after one successful fetch');
    }

    /** @return iterable<string, array{string}> */
    public static function failures(): iterable
    {
        yield 'a transport error' => ['transport'];
        yield 'a 500' => ['status500'];
        yield 'a 204 with no body' => ['status204'];
        yield 'a body that is not a JWKS document' => ['notjwks'];
        yield 'an EMPTY key set' => ['empty'];
    }

    /** @dataProvider failures */
    public function testAFailedRefreshKeepsTheHeldKeysAndNeverMovesTheAnchor(string $mode): void
    {
        $v = $this->verifier();
        self::assertTrue($this->accepts($v));
        $this->mode = $mode;

        $this->now = self::T0 + self::TTL + 10;
        self::assertTrue($this->accepts($v), 'the held key verifies through the failed refresh');
        self::assertNotSame([], $this->jwksRequests);

        // Had the failed refresh moved the anchor, the held key would live to TTL+10+TTL+300.
        $this->now = self::T0 + self::TTL + 301;
        self::assertFalse($this->accepts($v), 'the bound still runs from the last SUCCESSFUL fetch');
    }

    public function testAnUnknownKidRefreshThatFailsNeverOpensOrExtendsTheStaleWindow(): void
    {
        $v = $this->verifier();
        self::assertTrue($this->accepts($v));
        $this->mode = 'transport';

        $this->now = self::T0 + 100; // inside the TTL: the unknown kid triggers a (failing) refresh
        self::assertFalse($this->accepts($v, $this->unknownKidToken()));
        self::assertTrue($this->accepts($v), 'held set kept');

        $this->now = self::T0 + self::TTL + 301;
        self::assertFalse($this->accepts($v), 'the failed unknown-kid refresh did not extend the window');
    }

    public function testAFailingEndpointCostsOneFetchPerWindowNotOnePerToken(): void
    {
        $v = $this->verifier();
        self::assertTrue($this->accepts($v));
        $this->mode = 'transport';
        $this->now = self::T0 + self::TTL + 5;
        $before = count($this->jwksRequests);

        for ($i = 0; $i < 50; $i++) {
            $this->accepts($v, $i % 2 === 0 ? $this->unknownKidToken() : null);
        }

        self::assertLessThanOrEqual(1, count($this->jwksRequests) - $before, 'at most one fetch inside one 60 s window');
    }

    public function testAConfiguredTtlAboveThreeHundredSecondsIsClamped(): void
    {
        $v = $this->verifier(3600);
        self::assertTrue($this->accepts($v));
        $fetches = count($this->jwksRequests);

        $this->now = self::T0 + 301;
        self::assertTrue($this->accepts($v));
        self::assertSame($fetches + 1, count($this->jwksRequests), '3600 was clamped to 300: a refresh is due at 301 s');
    }

    public function testAnAdvertisedMaxAgeAboveThreeHundredIsClampedAndASmallerOneHonoured(): void
    {
        $this->cacheControl = 'public, max-age=86400';
        $v = $this->verifier();
        self::assertTrue($this->accepts($v));
        $fetches = count($this->jwksRequests);
        $this->now = self::T0 + 301;
        self::assertTrue($this->accepts($v));
        self::assertSame($fetches + 1, count($this->jwksRequests), 'max-age=86400 clamped to 300');

        $this->cacheControl = 'max-age=100';
        $this->now = self::T0 + 700;
        self::assertTrue($this->accepts($v)); // refetch under max-age=100
        $fetches = count($this->jwksRequests);
        $this->now = self::T0 + 700 + 99;
        self::assertTrue($this->accepts($v));
        self::assertSame($fetches, count($this->jwksRequests), 'within the advertised 100 s: no fetch');
        $this->now = self::T0 + 700 + 101;
        self::assertTrue($this->accepts($v));
        self::assertSame($fetches + 1, count($this->jwksRequests), 'max-age=100 honoured: refresh due at 101 s');
    }

    public function testA304ToAConditionalRequestMovesTheAnchor(): void
    {
        $v = $this->verifier();
        self::assertTrue($this->accepts($v));

        $this->mode = 'notmodified';
        $this->now = self::T0 + self::TTL + 10;
        self::assertTrue($this->accepts($v));
        $last = end($this->jwksRequests);
        self::assertInstanceOf(RequestInterface::class, $last);
        self::assertSame('"v1"', $last->getHeaderLine('If-None-Match'), 'a conditional request with the held ETag');

        // Anchored at TTL+10 now: well past T0+TTL+300, still accepted.
        $this->now = self::T0 + self::TTL + 400;
        self::assertTrue($this->accepts($v), 'the 304 re-confirmed the held set and moved the anchor');
    }

    public function testAConfiguredTtlAboveThreeHundredEmitsOneConfigClampedEventAndAnInRangeOneNone(): void
    {
        $events = [];
        $telemetry = new \Axiam\Sdk\Core\TelemetryDispatcher(static function (\Axiam\Sdk\Core\TelemetryEvent $e) use (&$events): void {
            $events[] = $e;
        });
        $http = new Client(['handler' => static fn () => new FulfilledPromise(new Response(404))]);

        new JwksVerifier($http, self::BASE_URL, 3600, null, null, null, null, $telemetry);
        new JwksVerifier($http, self::BASE_URL, 120, null, null, null, null, $telemetry);

        self::assertCount(1, $events);
        self::assertInstanceOf(\Axiam\Sdk\Core\ConfigClampedEvent::class, $events[0]);
        self::assertSame('cacheTtlSeconds', $events[0]->setting);
        self::assertSame('3600', $events[0]->requested);
        self::assertSame('300', $events[0]->effective);
        self::assertSame('§12.4 rule 2', $events[0]->contractReference);
    }
}
