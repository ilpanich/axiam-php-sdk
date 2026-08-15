<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Oidc\OidcConfiguration;
use Axiam\Sdk\Oidc\OidcTokenSet;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Promise;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * CONTRACT.md §9 burst test for `oidcRefresh` (F-06).
 *
 * §9's test requirement applies **per refresh operation** (contract 1.5), so the §1
 * cookie-session burst test in {@see SingleFlightRefreshTest} does not discharge it for
 * the §12 `POST /oauth2/token` `grant_type=refresh_token` path: the two run on different
 * token namespaces. This is that second test — N (= 5) concurrent `oidcRefresh` callers
 * MUST produce exactly **one** `/oauth2/token` wire call, and all five MUST receive
 * *that one call's* outcome (§9 rules 1 and 2).
 *
 * **Why Fibers.** Vanilla synchronous PHP cannot express a burst here at all:
 * `oidcRefresh()` returns an `OidcTokenSet`, not a promise, so caller 2 does not exist
 * until caller 1 has returned. The concurrency the guard defends against is therefore
 * reachable only on a cooperative runtime (Fibers, Swoole, RoadRunner), and modelling it
 * requires one: each caller runs in its own `Fiber`, and the transport handler suspends
 * the calling fiber mid-request — exactly what a fiber-aware/coroutine-hooked HTTP
 * handler does while a request is on the wire. The leader is therefore genuinely
 * in flight, holding the §9 guard, when callers 2..5 arrive.
 *
 * **Why this matters more than the two-caller {@see OidcTokenOpsTest} case.** AXIAM
 * refresh tokens are opaque, server-stored and **single-use with rotation**: the moment
 * the leader's POST is accepted, every other caller's copy of that refresh token is
 * already consumed. A second wire call does not merely waste a round trip — it replays a
 * dead token, is rejected `invalid_grant`, and can trip server-side replay defences.
 */
final class OidcRefreshBurstTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';
    private const CLIENT_ID = 'my-app';
    private const CLIENT_SECRET = 's3cr3t';
    private const TENANT_UUID = '22222222-2222-2222-2222-222222222222';

    /** How many concurrent `oidcRefresh` callers the burst fires (§9 requires N >= 5). */
    private const BURST = 5;

    /**
     * The single wire response the ONE permitted token call resolves with. Every caller
     * in the burst must come back holding this exact access token.
     */
    private const SHARED_ACCESS_TOKEN = 'rotated-access-token-from-the-one-wire-call';

    private function configuration(): OidcConfiguration
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
            grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
        );
    }

    /**
     * A transport handler that records every request and SUSPENDS the calling fiber for
     * the duration of the "round trip", resolving only once that fiber is resumed —
     * the minimal faithful model of a fiber-aware HTTP handler. Guzzle drives this
     * through the promise's wait function, so the suspension happens inside the leader's
     * `wait()`, leaving the §9 guard slot occupied while the other callers arrive.
     *
     * @param list<RequestInterface> $requests   Captured, by reference — the wire-call log.
     * @param \Closure(RequestInterface): Response|\Closure(RequestInterface): \Throwable $respondWith
     */
    private function suspendingHandler(array &$requests, \Closure $respondWith): \Closure
    {
        return function (RequestInterface $request, array $options) use (&$requests, $respondWith): PromiseInterface {
            $requests[] = $request;

            $promise = null;
            $promise = new Promise(function () use (&$promise, $request, $respondWith): void {
                // The request is now "on the wire": hand control back to the scheduler.
                \Fiber::suspend();

                $outcome = $respondWith($request);
                \assert($promise instanceof Promise);
                if ($outcome instanceof \Throwable) {
                    $promise->reject($outcome);

                    return;
                }
                $promise->resolve($outcome);
            });

            return $promise;
        };
    }

    /** @param list<RequestInterface> $requests */
    private function client(array &$requests, \Closure $respondWith): AxiamClient
    {
        return new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            oidcClientId: self::CLIENT_ID,
            oidcClientSecret: self::CLIENT_SECRET,
            oidcTenantId: self::TENANT_UUID,
            transportHandler: HandlerStack::create($this->suspendingHandler($requests, $respondWith)),
        );
    }

    /**
     * Runs `$callers` `oidcRefresh` calls, each in its own fiber, all of them entering
     * `oidcRefresh` before ANY of them is allowed to complete (that is what makes the
     * burst a burst), then drives the fibers to completion round-robin.
     *
     * @return array{results: array<int,OidcTokenSet>, errors: array<int,\Throwable>}
     */
    private function burst(AxiamClient $client, int $callers): array
    {
        $configuration = $this->configuration();
        $results = [];
        $errors = [];

        /** @var array<int,\Fiber> $fibers */
        $fibers = [];
        for ($i = 0; $i < $callers; $i++) {
            $fibers[$i] = new \Fiber(function () use ($client, $configuration, $i, &$results, &$errors): void {
                try {
                    // Every caller presents ITS OWN copy of the same rotating refresh
                    // token — which is precisely why only one of them may reach the wire.
                    $results[$i] = $client->oidcRefresh(
                        'the-single-use-refresh-token',
                        configuration: $configuration,
                    );
                } catch (\Throwable $e) {
                    $errors[$i] = $e;
                }
            });
        }

        // Start every caller. The first becomes the guard's leader and suspends inside
        // its wire call; the rest arrive while that call is genuinely in flight.
        foreach ($fibers as $fiber) {
            $fiber->start();
        }

        // Drive to completion. Each pass resumes whatever is suspended (the leader's
        // wire call, and any caller parked waiting for the leader's outcome). The bound
        // keeps a non-terminating implementation from hanging the suite.
        for ($pass = 0; $pass < 100; $pass++) {
            $suspended = false;
            foreach ($fibers as $fiber) {
                if ($fiber->isSuspended()) {
                    $suspended = true;
                    $fiber->resume();
                }
            }
            if (!$suspended) {
                break;
            }
        }

        foreach ($fibers as $i => $fiber) {
            self::assertTrue($fiber->isTerminated(), "caller {$i} never completed");
        }

        return ['results' => $results, 'errors' => $errors];
    }

    /** @param list<RequestInterface> $requests */
    private static function tokenCalls(array $requests): int
    {
        return \count(array_filter(
            $requests,
            static fn (RequestInterface $request): bool => $request->getUri()->getPath() === '/oauth2/token',
        ));
    }

    /**
     * §9 rules 1 + 2, success path: one wire call, one outcome, five callers.
     */
    public function testFiveConcurrentOidcRefreshCallsMakeOneWireCallAndShareItsAccessToken(): void
    {
        $requests = [];
        $client = $this->client($requests, static fn (): Response => new Response(200, [], (string) json_encode([
            'access_token' => self::SHARED_ACCESS_TOKEN,
            'refresh_token' => 'the-rotated-successor-refresh-token',
            'token_type' => 'Bearer',
            'expires_in' => 900,
        ])));

        ['results' => $results, 'errors' => $errors] = $this->burst($client, self::BURST);

        self::assertSame(
            [],
            array_map(static fn (\Throwable $e): string => $e::class . ': ' . $e->getMessage(), $errors),
            'no caller in the burst may fail — all five share the one refresh outcome (§9 rule 2)',
        );
        self::assertCount(self::BURST, $results, 'every caller must receive a token set');

        self::assertSame(
            1,
            self::tokenCalls($requests),
            'CONTRACT.md §9 rules 1/2: a burst of ' . self::BURST . ' concurrent oidcRefresh calls MUST produce '
            . 'exactly ONE /oauth2/token wire call — AXIAM refresh tokens are single-use with rotation, so every '
            . 'additional call replays an already-consumed token',
        );

        foreach ($results as $i => $tokens) {
            self::assertSame(
                self::SHARED_ACCESS_TOKEN,
                $tokens->accessToken->reveal(),
                "caller {$i} must observe the ONE wire call's access token, not its own",
            );
        }
    }

    /**
     * §9 rule 2, failure path: the one call's failure is shared too — every caller fails
     * with `AuthError`, and nobody "retries" the refresh behind the guard (§9 rule 3).
     */
    public function testAFailedRefreshIsSharedByTheWholeBurstWithoutASecondWireCall(): void
    {
        $requests = [];
        $client = $this->client($requests, static fn (): Response => new Response(
            400,
            ['Content-Type' => 'application/json'],
            (string) json_encode(['error' => 'invalid_grant', 'error_description' => 'refresh token is expired']),
        ));

        ['results' => $results, 'errors' => $errors] = $this->burst($client, self::BURST);

        self::assertSame([], $results, 'no caller may receive a token set from a failed refresh');
        self::assertCount(self::BURST, $errors, 'every caller must be told the refresh failed');
        foreach ($errors as $i => $error) {
            self::assertInstanceOf(AuthError::class, $error, "caller {$i} must fail with AuthError (§9 rule 2)");
        }

        self::assertSame(
            1,
            self::tokenCalls($requests),
            'a failed refresh must NOT be retried by the waiting callers (§9 rule 3) — still exactly one wire call',
        );
    }
}
