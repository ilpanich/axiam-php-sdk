<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\ConfigClampedEvent;
use Axiam\Sdk\Core\DecisionMemo;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\RequestStartEvent;
use Axiam\Sdk\Core\RetryEvent;
use Axiam\Sdk\Core\RetryPolicy;
use Axiam\Sdk\Core\TelemetryDispatcher;
use Axiam\Sdk\Core\TelemetryEvent;
use Axiam\Sdk\Rest\AccessDecision;
use Axiam\Sdk\Rest\AuthzRestClient;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * D5 conformance — CONTRACT.md §16, §17, §18, §19.
 *
 * These assert through the **public `checkAccessDecision` surface**, counting
 * requests that reach the transport, rather than against the helpers in
 * isolation. That distinction is normative as of contract 1.8.1: two SDKs
 * (TypeScript, C#) shipped a retry surface that was documented, tested and green
 * while no production path invoked it, so they retried nothing while appearing
 * to. Counting on the wire is the only assertion that catches it.
 */
final class D5ConformanceTest extends TestCase
{
    private const CHECK_PATH = '/api/v1/authz/check';
    private const RESOURCE = '11111111-2222-3333-4444-555555555555';
    private const ALLOW_BODY = '{"allowed":true,"reason_code":"allowed"}';

    /** @var list<\Psr\Http\Message\RequestInterface> */
    private array $sent = [];

    /**
     * Builds an authz client over a scripted mock transport, counting requests.
     *
     * @param list<Response> $responses The response script.
     */
    private function clientFor(
        array $responses,
        ?DecisionMemo $memo = null,
        ?TelemetryDispatcher $telemetry = null,
        bool $retry = true,
    ): AuthzRestClient {
        $this->sent = [];
        $mock = new MockHandler($responses);
        $stack = HandlerStack::create($mock);
        $stack->push(function (callable $handler): callable {
            return function ($request, array $options) use ($handler) {
                $this->sent[] = $request;

                return $handler($request, $options);
            };
        });

        return new AuthzRestClient(
            new Client(['handler' => $stack, 'base_uri' => 'https://axiam-d5.test']),
            $memo,
            $telemetry,
            $retry,
            // Pin the jitter to 0 and make the sleep a no-op: a test that really
            // waits 200ms is a test nobody runs (§16.7). The delay arithmetic is
            // asserted directly instead.
            static fn (): float => 0.0,
            static function (float $ms): void {
            },
        );
    }

    /** @param list<int> $statuses */
    private static function script(array $statuses, string $body = self::ALLOW_BODY): array
    {
        return array_map(
            static fn (int $s): Response => $s === 200
                ? new Response(200, ['Content-Type' => 'application/json'], $body)
                : new Response($s),
            $statuses,
        );
    }

    // -----------------------------------------------------------------------
    // §16 — the policy table
    // -----------------------------------------------------------------------

    public function testBackoffDoublesFromBaseAndStopsAtCap(): void
    {
        self::assertSame(RetryPolicy::BASE_DELAY_MS, RetryPolicy::backoffMs(1));
        self::assertSame(400.0, RetryPolicy::backoffMs(2));
        self::assertSame(RetryPolicy::MAX_DELAY_MS, RetryPolicy::backoffMs(20));
    }

    public function testJitterIsFullNotPartial(): void
    {
        // The range is [0, backoff], not backoff ± something. Pinning the fraction
        // to its endpoints is what distinguishes the two — a random draw would
        // pass under either policy.
        self::assertSame(0.0, RetryPolicy::delayMs(1, 0.0, 0.0));
        self::assertSame(RetryPolicy::BASE_DELAY_MS, RetryPolicy::delayMs(1, 0.0, 1.0));
        self::assertSame(200.0, RetryPolicy::delayMs(2, 0.0, 0.5));
    }

    public function testRetryAfterIsAFloorNeverACeiling(): void
    {
        // TypeScript's `retryAfterMs ?? backoff(n)` made the hint REPLACE the
        // backoff, so a zero retried immediately and defeated the policy.
        self::assertSame(2000.0, RetryPolicy::delayMs(1, 2000.0, 1.0));
        self::assertSame(RetryPolicy::BASE_DELAY_MS, RetryPolicy::delayMs(1, 0.0, 1.0));
        self::assertSame(50.0, RetryPolicy::delayMs(1, 50.0, 0.0));
    }

    public function testJitterFractionOutsideUnitIntervalIsClamped(): void
    {
        // A caller-supplied source is not trusted to stay in [0, 1]: above 1 would
        // exceed the §16.1 cap, below 0 would produce a negative wait.
        self::assertSame(RetryPolicy::BASE_DELAY_MS, RetryPolicy::delayMs(1, 0.0, 1.5));
        self::assertSame(0.0, RetryPolicy::delayMs(1, 0.0, -0.5));
    }

    public function testPersistentServerErrorMakesExactlyThreeAttempts(): void
    {
        $client = $this->clientFor(self::script([503, 503, 503]));

        $this->expectException(NetworkError::class);

        try {
            $client->checkAccessDecision('read', self::RESOURCE);
        } finally {
            self::assertCount(RetryPolicy::MAX_ATTEMPTS, $this->sent);
        }
    }

    public function testTransientFailureIsRetriedAndTheSuccessReturned(): void
    {
        $client = $this->clientFor(self::script([503, 200]));

        $decision = $client->checkAccessDecision('read', self::RESOURCE);

        self::assertTrue($decision->allowed);
        self::assertCount(2, $this->sent);
    }

    public function testDecisiveForbiddenIsNotRetried(): void
    {
        // A 403 is an answer, not a transport failure. Retrying reproduces the
        // identical rejection and spends the caller's latency budget.
        $client = $this->clientFor(self::script([403]));

        try {
            $client->checkAccessDecision('read', self::RESOURCE);
            self::fail('expected an authorization error');
        } catch (\Throwable) {
            self::assertCount(1, $this->sent);
        }
    }

    public function testRetryDisabledMakesExactlyOneAttempt(): void
    {
        $client = $this->clientFor(self::script([503]), retry: false);

        try {
            $client->checkAccessDecision('read', self::RESOURCE);
            self::fail('expected a network error');
        } catch (NetworkError) {
            self::assertCount(1, $this->sent);
        }
    }

    // -----------------------------------------------------------------------
    // §17 — decision memo
    // -----------------------------------------------------------------------

    public function testTheMemoIsOffByDefault(): void
    {
        // The most important assertion here. §11.2 rule 6's ban on decision caching
        // is still the default; a build that quietly enabled this would change
        // authorization staleness for every existing caller without them asking.
        $client = $this->clientFor(self::script([200, 200]));

        $client->checkAccessDecision('read', self::RESOURCE);
        $client->checkAccessDecision('read', self::RESOURCE);

        self::assertCount(2, $this->sent);
    }

    public function testARepeatInsideTheTtlIsServedWithoutASecondCall(): void
    {
        $client = $this->clientFor(self::script([200]), new DecisionMemo(5000.0));

        $first = $client->checkAccessDecision('read', self::RESOURCE);
        $second = $client->checkAccessDecision('read', self::RESOURCE);

        self::assertCount(1, $this->sent);
        // §17.1 rule 5: the reason code survives the memo.
        self::assertSame($first->reasonCode, $second->reasonCode);
        self::assertNotNull($second->reasonCode);
    }

    public function testDeniesAreMemoizedExactlyLikeAllows(): void
    {
        // §17.1 rule 4 — asymmetric caching leaks the outcome through latency.
        $client = $this->clientFor(
            self::script([200], '{"allowed":false,"reason_code":"denied_by_rule"}'),
            new DecisionMemo(5000.0),
        );

        $client->checkAccessDecision('read', self::RESOURCE);
        $second = $client->checkAccessDecision('read', self::RESOURCE);

        self::assertCount(1, $this->sent);
        self::assertFalse($second->allowed);
        self::assertSame('denied_by_rule', $second->reasonCode);
    }

    public function testAFailureIsNeverMemoized(): void
    {
        // §17.1 rule 7 — caching a transport error as a deny turns a blip into a
        // TTL-long outage.
        $client = $this->clientFor(self::script([503, 503]), new DecisionMemo(5000.0), retry: false);

        foreach ([1, 2] as $_) {
            try {
                $client->checkAccessDecision('read', self::RESOURCE);
                self::fail('expected a network error');
            } catch (NetworkError) {
                // expected
            }
        }

        self::assertCount(2, $this->sent);
    }

    public function testEveryKeyComponentIsDistinguished(): void
    {
        $keys = [
            DecisionMemo::key(null, 'r1', 'read', null),
            DecisionMemo::key(null, 'r1', 'write', null),
            DecisionMemo::key(null, 'r2', 'read', null),
            DecisionMemo::key(null, 'r1', 'read', 'col-a'),
            DecisionMemo::key('u1', 'r1', 'read', null),
        ];

        self::assertCount(5, array_unique($keys));
        // An absent scope must never collide with a present empty one.
        self::assertNotSame(
            DecisionMemo::key(null, 'r1', 'read', null),
            DecisionMemo::key(null, 'r1', 'read', ''),
        );
    }

    public function testATtlAboveTheCeilingIsClampedRatherThanRejected(): void
    {
        self::assertSame(DecisionMemo::MAX_TTL_MS, (new DecisionMemo(3_600_000.0))->effectiveTtlMs());
        self::assertSame(2000.0, (new DecisionMemo(2000.0))->effectiveTtlMs());
        self::assertFalse((new DecisionMemo())->enabled());
        self::assertFalse((new DecisionMemo(-1.0))->enabled());
    }

    public function testAnEntryExpiresAtExactlyTheTtl(): void
    {
        $now = 1000.0;
        $memo = new DecisionMemo(5000.0, static function () use (&$now): float {
            return $now;
        });
        $memo->put('k', new AccessDecision(true, null, 'allowed'));

        $now = 1000.0 + 4999.0;
        self::assertNotNull($memo->get('k'));
        $now = 1000.0 + 5000.0;
        self::assertNull($memo->get('k'));
    }

    public function testTheMemoEvictsRatherThanGrowingWithoutBound(): void
    {
        // §17.1 rule 8 — an unbounded per-client cache keyed by (subject, resource,
        // action, scope) is a memory leak in any service that checks many resources.
        $memo = new DecisionMemo(5000.0);
        for ($i = 0; $i < DecisionMemo::MAX_ENTRIES + 50; $i++) {
            $memo->put(DecisionMemo::key(null, "r{$i}", 'read', null), new AccessDecision(true, null, 'allowed'));
        }

        self::assertSame(DecisionMemo::MAX_ENTRIES, $memo->count());
    }

    // -----------------------------------------------------------------------
    // §19 — telemetry
    // -----------------------------------------------------------------------

    public function testOneRequestPairPerAttemptWithARetryBetween(): void
    {
        $events = [];
        $telemetry = new TelemetryDispatcher(static function (TelemetryEvent $e) use (&$events): void {
            $events[] = $e;
        });
        $client = $this->clientFor(self::script([503, 200]), null, $telemetry);

        $client->checkAccessDecision('read', self::RESOURCE);

        $kinds = array_map(
            static fn (TelemetryEvent $e): string => (new \ReflectionClass($e))->getShortName(),
            $events,
        );
        self::assertSame(
            ['RequestStartEvent', 'RequestEndEvent', 'RetryEvent', 'RequestStartEvent', 'RequestEndEvent'],
            $kinds,
        );

        $starts = array_values(array_filter($events, static fn ($e): bool => $e instanceof RequestStartEvent));
        // Emitting both pairs as attempt 1 would make a retried call
        // indistinguishable from a single slow one.
        self::assertSame([1, 2], array_map(static fn (RequestStartEvent $e): int => $e->attempt, $starts));
        // The path TEMPLATE, never a substituted URL — a metric label carrying a
        // UUID is a cardinality bomb.
        self::assertSame(self::CHECK_PATH, $starts[0]->pathTemplate);
    }

    public function testAThrowingHookCannotFailTheOperation(): void
    {
        // §19.2 rule 2 — telemetry is not permitted to fail an authorization check.
        $telemetry = new TelemetryDispatcher(static function (TelemetryEvent $e): void {
            throw new \RuntimeException('hook exploded');
        });
        $client = $this->clientFor(self::script([200]), null, $telemetry);

        self::assertTrue($client->checkAccessDecision('read', self::RESOURCE)->allowed);
    }

    public function testNoEventPayloadCarriesAToken(): void
    {
        // §19.2 rule 3 — this surface exists to be shipped to a metrics backend,
        // which is the last place a bearer token should land.
        $events = [];
        $telemetry = new TelemetryDispatcher(static function (TelemetryEvent $e) use (&$events): void {
            $events[] = $e;
        });
        $client = $this->clientFor(self::script([503, 503, 503]), null, $telemetry);

        try {
            $client->checkAccessDecision('read', self::RESOURCE);
        } catch (NetworkError) {
            // expected
        }

        $rendered = strtolower(print_r($events, true));
        self::assertStringNotContainsString('eyj', $rendered);
        self::assertStringNotContainsString('authorization:', $rendered);
    }

    public function testAnUninstalledDispatcherIsInert(): void
    {
        $dispatcher = new TelemetryDispatcher();
        self::assertFalse($dispatcher->installed());
        $dispatcher->emit(new RetryEvent('op', 1, 1.0, 'x'));
        ($dispatcher->startRequest('op', 'POST', self::CHECK_PATH, 1))(200, TelemetryEvent::OUTCOME_SUCCESS);
    }

    // -----------------------------------------------------------------------
    // §19.2 rule 6 — a clamp is reported, not swallowed
    // -----------------------------------------------------------------------

    public function testClampingTheMemoTtlEmitsAConfigClampedEvent(): void
    {
        // The clamp that matters most: an operator who set 60s believes their
        // staleness bound is 60s. It is 5s, and without this nothing says so.
        $events = [];
        $telemetry = new TelemetryDispatcher(static function (TelemetryEvent $e) use (&$events): void {
            $events[] = $e;
        });

        (new DecisionMemo(60_000.0))->reportClamp(60_000.0, $telemetry);

        self::assertCount(1, $events);
        $clamp = $events[0];
        self::assertInstanceOf(ConfigClampedEvent::class, $clamp);
        self::assertSame('decisionMemoTtlMs', $clamp->setting);
        self::assertSame('60000', $clamp->requested);
        self::assertSame('5000', $clamp->effective);
        self::assertSame('§17.1 rule 2', $clamp->contractReference);
    }

    public function testAValueAlreadyWithinItsLimitEmitsNothing(): void
    {
        // §19.2 rule 6: an event that fires when nothing happened trains its reader
        // to ignore it.
        $events = [];
        $telemetry = new TelemetryDispatcher(static function (TelemetryEvent $e) use (&$events): void {
            $events[] = $e;
        });

        (new DecisionMemo(2000.0))->reportClamp(2000.0, $telemetry);
        (new DecisionMemo())->reportClamp(0.0, $telemetry);

        self::assertSame([], $events);
    }
}
