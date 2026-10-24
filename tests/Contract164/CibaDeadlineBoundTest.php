<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract164;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\OAuthProtocolError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Oidc\CibaInitiateResponse;
use Axiam\Sdk\Oidc\OidcClient;
use Axiam\Sdk\Oidc\OidcConfiguration;
use Axiam\Sdk\Tests\Fixtures\CibaTestClock;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * C164-43: the §16 retry inside a CIBA poll, as `cibaAwait` calls it, never waits past the
 * request's deadline (CONTRACT.md §34.2 P10, §33.7 rule 5, §33.8 test 7): `Retry-After` is a
 * floor but not past `received_at + expires_in`, and no request follows the deadline. The waits
 * run on the injected clock.
 */
final class CibaDeadlineBoundTest extends TestCase
{
    private const BASE_URL = 'https://api.test';

    private static function configuration(): OidcConfiguration
    {
        return new OidcConfiguration(
            issuer: self::BASE_URL,
            authorization_endpoint: self::BASE_URL . '/oauth2/authorize',
            token_endpoint: self::BASE_URL . '/oauth2/token',
            userinfo_endpoint: self::BASE_URL . '/oauth2/userinfo',
            jwks_uri: self::BASE_URL . '/oauth2/jwks',
            revocation_endpoint: self::BASE_URL . '/oauth2/revoke',
            introspection_endpoint: self::BASE_URL . '/oauth2/introspect',
            response_types_supported: ['code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['EdDSA'],
            scopes_supported: ['openid'],
            token_endpoint_auth_methods_supported: ['client_secret_post'],
            claims_supported: ['sub'],
            grant_types_supported: [OidcClient::CIBA_GRANT_TYPE],
            backchannel_authentication_endpoint: self::BASE_URL . '/oauth2/bc-authorize',
        );
    }

    /**
     * Runs `cibaAwait` against polls answered `503` + `Retry-After`, and returns the clock times at
     * which each poll was sent, the clock, and the typed outcome.
     *
     * @param list<callable(CibaTestClock): Response> $answers
     * @return array{list<float>, CibaTestClock, ?OAuthProtocolError, ?\Axiam\Sdk\Oidc\OidcTokenSet}
     */
    private function await(array $answers, int $expiresIn, int $interval, bool $retryEnabled = true): array
    {
        $clock = new CibaTestClock();
        $sent = [];
        $queue = [];
        foreach ($answers as $answer) {
            $queue[] = static function () use ($clock, $answer, &$sent): Response {
                $sent[] = $clock->now;

                return $answer($clock);
            };
        }
        $client = new AxiamClient(
            self::BASE_URL,
            'acme',
            oidcClientId: 'my-ciba',
            oidcClientSecret: new Sensitive('s3cret-' . bin2hex(random_bytes(4))),
            oidcTenantId: '22222222-2222-2222-2222-222222222222',
            transportHandler: HandlerStack::create(new MockHandler($queue)),
            retryEnabled: $retryEnabled,
        );
        $initiated = new CibaInitiateResponse(new Sensitive(bin2hex(random_bytes(8))), $expiresIn, $interval, $clock->now);

        $set = null;
        try {
            $set = $client->cibaAwait($initiated, configuration: self::configuration(), clock: $clock);
            $error = null;
        } catch (OAuthProtocolError $e) {
            $error = $e;
        }

        return [$sent, $clock, $error, $set];
    }

    private static function unavailable(int $retryAfter): callable
    {
        return static fn (CibaTestClock $clock): Response => new Response(
            503,
            ['Retry-After' => (string) $retryAfter],
            (string) json_encode(['error' => 'temporarily_unavailable']),
        );
    }

    public function testEveryPollAnsweredWithARetryAfterPastTheDeadlineSendsNothingAtOrAfterIt(): void
    {
        // §33.8 test 7, the P10 case: expires_in 30, every poll 503 + Retry-After 120.
        [$sent, $clock, $error] = $this->await(array_fill(0, 4, self::unavailable(120)), 30, 5);

        self::assertNotNull($error);
        self::assertSame('expired_token', $error->error);
        self::assertSame([1005.0], $sent, 'one poll, at 5 s; no retry is started');
        self::assertSame([5], $clock->sleeps, 'no in-poll wait was served');
        self::assertLessThanOrEqual(1030.0, $clock->now);
    }

    public function testARetryAfterInsideTheDeadlineIsServedOnTheClockAndTheNextOneIsNot(): void
    {
        // Retry-After 20: the first 503 at 5 s is retried at 25 s (5 + 20 < 30), the second at 25 s
        // is not (25 + 20 >= 30). The wait runs on the injected clock, not a real usleep.
        [$sent, $clock, $error] = $this->await(array_fill(0, 4, self::unavailable(20)), 30, 5);

        self::assertNotNull($error);
        self::assertSame('expired_token', $error->error);
        self::assertSame([1005.0, 1025.0], $sent);
        self::assertSame([5, 20], $clock->sleeps);
    }

    public function testAPollThatFailsJustBeforeTheDeadlineIsNotRetried(): void
    {
        // The jitter is part of the bound: a bare 500 that returns 1 ms before the deadline would be
        // retried after up to 200 ms.
        [$sent, , $error] = $this->await([
            static function (CibaTestClock $clock): Response {
                $clock->now += 19.9;

                return new Response(400, [], (string) json_encode(['error' => 'authorization_pending']));
            },
            static function (CibaTestClock $clock): Response {
                $clock->now += 0.099;

                return new Response(500, [], (string) json_encode(['error' => 'server_error']));
            },
            static fn (CibaTestClock $clock): Response => new Response(500),
        ], 30, 5);

        self::assertNotNull($error);
        self::assertSame('expired_token', $error->error);
        self::assertCount(2, $sent, 'no retry after the deadline');
    }

    private static function tokens(): callable
    {
        return static fn (CibaTestClock $clock): Response => new Response(200, [], (string) json_encode([
            'access_token' => 'ciba-access-token', 'token_type' => 'Bearer', 'expires_in' => 900,
        ]));
    }

    private static function rateLimited(int $retryAfter): callable
    {
        return static fn (CibaTestClock $clock): Response => new Response(
            429,
            ['Retry-After' => (string) $retryAfter],
            (string) json_encode(['error' => 'rate_limit_exceeded']),
        );
    }

    public function testA429WithRetryAfterMakesTheNextWaitAtLeastThat(): void
    {
        // C164-52: AXIAM's own 429 body is an OAuthProtocolError; its Retry-After is a floor (§33.7
        // rule 5), and the interval is neither shortened nor raised.
        [$sent, $clock, $error, $set] = $this->await([self::rateLimited(12), self::tokens()], 600, 5);

        self::assertNull($error);
        self::assertNotNull($set);
        self::assertSame([5, 12], $clock->sleeps);
        self::assertSame([1005.0, 1017.0], $sent);
    }

    public function testA429WhoseRetryAfterPassesTheDeadlineEndsTheFlowWithNothingMoreSent(): void
    {
        [$sent, $clock, $error] = $this->await([self::rateLimited(12), self::tokens()], 15, 5);

        self::assertNotNull($error);
        self::assertSame('expired_token', $error->error);
        self::assertSame([1005.0], $sent);
        self::assertSame([5], $clock->sleeps);
    }

    public function testARetryAfterNeverShortensTheInterval(): void
    {
        // C164-54 (a): retry off, so the 503 reaches the loop; Retry-After 2 < interval 5.
        [, $clock, $error] = $this->await([self::unavailable(2), self::tokens()], 600, 5, retryEnabled: false);

        self::assertNull($error);
        self::assertSame([5, 5], $clock->sleeps);
    }

    public function testARetryAfterAboveTheIntervalIsTheNextWait(): void
    {
        // C164-54 (b)
        [, $clock, $error] = $this->await([self::unavailable(12), self::tokens()], 600, 5, retryEnabled: false);

        self::assertNull($error);
        self::assertSame([5, 12], $clock->sleeps);
    }

    public function testARetryWhoseWaitExactlyReachesTheDeadlineIsNotTaken(): void
    {
        // C164-54 (c): at 5 s with 25 s left, Retry-After 25 is not strictly less than the time left.
        [$sent, $clock, $error] = $this->await([self::unavailable(25), self::tokens()], 30, 5);

        self::assertNotNull($error);
        self::assertSame('expired_token', $error->error);
        self::assertSame([1005.0], $sent);
        self::assertSame([5], $clock->sleeps);
    }

    public function testAWholeSecondClockCannotServeAWaitPastTheDeadline(): void
    {
        // C164-54: the poll at 29.5 s fails with 0.5 s left; the 0.2 s backoff ceiling would fit, but
        // the clock serves it as a whole second, which would end at 30.5 s. Not admitted.
        [$sent, $clock, $error] = $this->await([
            static function (CibaTestClock $clock): Response {
                $clock->now += 19.5;

                return new Response(400, [], (string) json_encode(['error' => 'authorization_pending']));
            },
            static fn (CibaTestClock $clock): Response => new Response(500),
            self::tokens(),
        ], 30, 5);

        self::assertNotNull($error);
        self::assertSame('expired_token', $error->error);
        self::assertCount(2, $sent);
        self::assertLessThanOrEqual(1030.0, $clock->now);
    }

    public function testA429RetryAfterBelowTheIntervalStillWaitsTheInterval(): void
    {
        // C164-57 (a): the carry is a floor, never a shortcut.
        [, $clock, $error] = $this->await([self::rateLimited(2), self::tokens()], 600, 5);

        self::assertNull($error);
        self::assertSame([5, 5], $clock->sleeps);
    }

    public function testTheCarryOf429IsConsumedOnceAndTheIntervalIsNotRaised(): void
    {
        // C164-57 (b): after the 429 the next ordinary wait is back to the interval.
        [, $clock, $error] = $this->await([
            self::rateLimited(12),
            static fn (CibaTestClock $clock): Response => new Response(400, [], (string) json_encode(['error' => 'authorization_pending'])),
            self::tokens(),
        ], 600, 5);

        self::assertNull($error);
        self::assertSame([5, 12, 5], $clock->sleeps);
    }

    public function testTheStatusDecidesNotTheBodyOfA429(): void
    {
        // C164-57 (c): a 429 whose body says slow_down is the rule 5 wait and does not raise the
        // interval; only the 400 does.
        [, $clock, $error] = $this->await([
            static fn (CibaTestClock $clock): Response => new Response(429, ['Retry-After' => '3'], (string) json_encode(['error' => 'slow_down'])),
            self::tokens(),
        ], 600, 5);

        self::assertNull($error);
        self::assertSame([5, 5], $clock->sleeps);
    }

    public function testASlowDownOn400StillRaisesTheInterval(): void
    {
        [, $clock, $error] = $this->await([
            static fn (CibaTestClock $clock): Response => new Response(400, [], (string) json_encode(['error' => 'slow_down'])),
            self::tokens(),
        ], 600, 5);

        self::assertNull($error);
        self::assertSame([5, 10], $clock->sleeps);
    }
}
