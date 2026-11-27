<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Oidc\OidcConfiguration;
use Axiam\Sdk\Session;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Promise;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * CONTRACT.md §9, per-token keying of the §12 `oidc_refresh` single-flight.
 *
 * The single-flight is keyed by a SHA-256 digest of the refresh token (plus the tenant), so
 * callers presenting the SAME token form one burst (rules 2, 6a-6d), while a caller presenting a
 * DIFFERENT token never joins it and never receives another grant's tokens. Each test drives the
 * public `oidcRefresh()` through fibers and a transport handler that suspends the calling fiber,
 * so the guard slot is genuinely occupied while the second caller arrives.
 */
final class OidcRefreshPerTokenTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TOKEN_A = 'refresh-token-AAAA-raw-secret';
    private const TOKEN_B = 'refresh-token-BBBB-raw-secret';
    private const TENANT_UUID = '22222222-2222-2222-2222-222222222222';
    private const OTHER_TENANT_UUID = '33333333-3333-3333-3333-333333333333';

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
            grant_types_supported: ['authorization_code', 'refresh_token'],
        );
    }

    /**
     * Wire handler that answers each token request with an access token derived from the
     * refresh token it carried, and suspends the calling fiber while the request is "on the wire".
     * With `$suspendAfterResolve` the promise is fulfilled BEFORE the suspension, so the guard
     * slot stays occupied while its settle callbacks are still queued: the publish-before-vacate
     * window of §9 rule 6a.
     *
     * @param list<string> $wireTokens refresh token of every wire call, in order (by reference)
     */
    private function client(array &$wireTokens, bool $suspendAfterResolve): AxiamClient
    {
        $handler = function (RequestInterface $request, array $options) use (&$wireTokens, $suspendAfterResolve): PromiseInterface {
            parse_str((string) $request->getBody(), $form);
            $presented = (string) ($form['refresh_token'] ?? '');
            $wireTokens[] = $presented;

            $response = new Response(200, [], (string) json_encode([
                'access_token' => 'access-for-' . substr(hash('sha256', $presented), 0, 8),
                'token_type' => 'Bearer',
                'expires_in' => 900,
            ]));

            $promise = null;
            $promise = new Promise(function () use (&$promise, $response, $suspendAfterResolve): void {
                \assert($promise instanceof Promise);
                if ($suspendAfterResolve) {
                    $promise->resolve($response);
                    \Fiber::suspend();

                    return;
                }
                \Fiber::suspend();
                $promise->resolve($response);
            });

            return $promise;
        };

        return new AxiamClient(
            self::BASE_URL,
            'acme-tenant',
            oidcClientId: 'my-app',
            oidcClientSecret: 's3cr3t',
            oidcTenantId: '22222222-2222-2222-2222-222222222222',
            transportHandler: HandlerStack::create($handler),
        );
    }

    private static function accessFor(string $refreshToken): string
    {
        return 'access-for-' . substr(hash('sha256', $refreshToken), 0, 8);
    }

    /** @param array<string,string> $out */
    private function fiber(AxiamClient $client, string $token, array &$out, ?string $tenantId = null): \Fiber
    {
        $configuration = $this->configuration();

        return new \Fiber(function () use ($client, $token, $configuration, $tenantId, &$out): void {
            try {
                $out[$token] = $client->oidcRefresh($token, tenantId: $tenantId, configuration: $configuration)->accessToken->reveal();
            } catch (\Throwable $e) {
                $out[$token] = 'ERROR ' . $e::class;
            }
        });
    }

    /** @param list<\Fiber> $fibers */
    private static function drive(array $fibers): void
    {
        for ($pass = 0; $pass < 200; $pass++) {
            $suspended = false;
            foreach ($fibers as $fiber) {
                if ($fiber->isSuspended()) {
                    $suspended = true;
                    $fiber->resume();
                }
            }
            if (!$suspended) {
                return;
            }
        }
    }

    /** Required test 1: a different token during a LIVE flight gets its own wire call. */
    public function testADifferentTokenDuringALiveFlightGetsItsOwnWireCallAndItsOwnTokens(): void
    {
        $wire = [];
        $client = $this->client($wire, suspendAfterResolve: false);
        $out = [];
        $a = $this->fiber($client, self::TOKEN_A, $out);
        $b = $this->fiber($client, self::TOKEN_B, $out);

        $a->start(); // leader of token A, parked on the wire
        $b->start(); // arrives while A is in flight
        self::drive([$a, $b]);

        self::assertCount(2, $wire, 'token B must not join token A\'s flight: two wire calls');
        self::assertEqualsCanonicalizing([self::TOKEN_A, self::TOKEN_B], $wire);
        self::assertSame(self::accessFor(self::TOKEN_A), $out[self::TOKEN_A]);
        self::assertSame(self::accessFor(self::TOKEN_B), $out[self::TOKEN_B], 'B receives B\'s own token set');
    }

    /** Required test 2: a different token inside A's publish-before-vacate window. */
    public function testADifferentTokenInsideThePublishBeforeVacateWindowGetsItsOwnResult(): void
    {
        $wire = [];
        $client = $this->client($wire, suspendAfterResolve: true);
        $out = [];
        $a = $this->fiber($client, self::TOKEN_A, $out);
        $b = $this->fiber($client, self::TOKEN_B, $out);

        $a->start(); // A's wire call is fulfilled, its slot still occupied (callbacks queued)
        $b->start();
        self::drive([$a, $b]);

        self::assertCount(2, $wire);
        self::assertSame(self::accessFor(self::TOKEN_A), $out[self::TOKEN_A]);
        self::assertSame(self::accessFor(self::TOKEN_B), $out[self::TOKEN_B]);
    }

    /** Required test 3: the same token in that window joins (rule 6a). */
    public function testTheSameTokenInsideThePublishBeforeVacateWindowJoins(): void
    {
        $wire = [];
        $client = $this->client($wire, suspendAfterResolve: true);
        $leaderOut = [];
        $followerOut = [];
        $a = $this->fiber($client, self::TOKEN_A, $leaderOut);
        $a2 = $this->fiber($client, self::TOKEN_A, $followerOut);

        $a->start();
        $a2->start();
        self::drive([$a, $a2]);

        self::assertCount(1, $wire, 'same token in the window joins: still one wire call');
        self::assertSame(self::accessFor(self::TOKEN_A), $leaderOut[self::TOKEN_A]);
        self::assertSame(self::accessFor(self::TOKEN_A), $followerOut[self::TOKEN_A]);
    }

    /** Required test 4: the same token after a full vacate gets a fresh wire call. */
    public function testTheSameTokenAfterFullVacateGetsAFreshWireCall(): void
    {
        $wire = [];
        $client = $this->client($wire, suspendAfterResolve: false);
        $out = [];

        $first = $this->fiber($client, self::TOKEN_A, $out);
        $first->start();
        self::drive([$first]);
        $second = $this->fiber($client, self::TOKEN_A, $out);
        $second->start();
        self::drive([$second]);

        self::assertSame([self::TOKEN_A, self::TOKEN_A], $wire, 'after the slot is vacated a new call is made');
    }

    /** Required test 5: no raw token in any registry, and a vacated slot is removed. */
    public function testNoRawTokenIsHeldInTheGuardAndAVacatedSlotIsRemoved(): void
    {
        $wire = [];
        $client = $this->client($wire, suspendAfterResolve: false);
        $out = [];
        $a = $this->fiber($client, self::TOKEN_A, $out);
        $b = $this->fiber($client, self::TOKEN_B, $out);
        $a->start();
        $b->start();

        $session = (new \ReflectionProperty(AxiamClient::class, 'session'))->getValue($client);
        self::assertInstanceOf(Session::class, $session);
        $dump = static function () use ($session): string {
            $parts = [];
            foreach ((new \ReflectionObject($session))->getProperties() as $property) {
                if (!$property->isInitialized($session)) {
                    continue;
                }
                $value = $property->getValue($session);
                $parts[] = $property->getName() . '=' . (\is_array($value) ? print_r(array_keys($value), true) : '');
            }

            return implode("\n", $parts);
        };

        $inFlight = $dump();
        self::assertStringNotContainsString(self::TOKEN_A, $inFlight);
        self::assertStringNotContainsString(self::TOKEN_B, $inFlight);
        foreach ([self::TOKEN_A, self::TOKEN_B] as $token) {
            self::assertStringContainsString(
                hash('sha256', self::TENANT_UUID . "\0" . $token),
                $inFlight,
                'each live OIDC flight is keyed by the SHA-256 digest of (tenant NUL token)',
            );
        }

        self::drive([$a, $b]);
        $vacated = $dump();
        self::assertStringNotContainsString('oidc', $vacated, 'every OIDC slot is removed once vacated');
    }

    /**
     * @param list<string|null> $tenants the tenant each caller passes (null = omitted)
     * @return array{wire: int, out: array<int,string>}
     */
    private function tenantBurst(array $tenants): array
    {
        $wire = [];
        $client = $this->client($wire, suspendAfterResolve: false);
        $fibers = [];
        $outs = [];
        foreach ($tenants as $i => $tenant) {
            $outs[$i] = [];
            $fibers[$i] = $this->fiber($client, self::TOKEN_A, $outs[$i], $tenant);
        }
        foreach ($fibers as $fiber) {
            $fiber->start(); // the first is held on the wire while the rest arrive
        }
        self::drive($fibers);

        return ['wire' => \count($wire), 'out' => array_map(static fn (array $o): string => (string) reset($o), $outs)];
    }

    /** Omitted vs explicit default vs upper-case spelling of the same tenant: ONE flight. */
    public function testSameTokenAndEffectiveTenantShareOneFlightHoweverTheTenantIsSpelled(): void
    {
        $result = $this->tenantBurst([null, self::TENANT_UUID, strtoupper(self::TENANT_UUID)]);

        self::assertSame(1, $result['wire'], 'omitted, explicit and upper-case default tenant are one flight');
        self::assertSame([self::accessFor(self::TOKEN_A)], array_values(array_unique($result['out'])));
    }

    /** The same token for a different resolved tenant is a separate flight. */
    public function testSameTokenForADifferentTenantIsASeparateFlight(): void
    {
        $result = $this->tenantBurst([null, self::OTHER_TENANT_UUID]);

        self::assertSame(2, $result['wire']);
    }

    /** An invalid tenant fails before any slot exists. */
    public function testAnInvalidTenantFailsBeforeAnyGuardSlotIsCreated(): void
    {
        $wire = [];
        $client = $this->client($wire, suspendAfterResolve: false);
        $out = [];
        $fiber = $this->fiber($client, self::TOKEN_A, $out, 'not-a-uuid');
        $fiber->start();

        self::assertTrue($fiber->isTerminated());
        self::assertSame([], $wire);
        $session = (new \ReflectionProperty(AxiamClient::class, 'session'))->getValue($client);
        self::assertSame([], (new \ReflectionProperty(Session::class, 'refreshSlots'))->getValue($session));
    }

    /** A failed burst's error never carries the raw refresh token. */
    public function testAFailedRefreshNeverCarriesTheRawTokenInItsMessage(): void
    {
        $client = new AxiamClient(
            self::BASE_URL,
            'acme-tenant',
            oidcClientId: 'my-app',
            oidcClientSecret: 's3cr3t',
            oidcTenantId: self::TENANT_UUID,
            transportHandler: HandlerStack::create(new \GuzzleHttp\Handler\MockHandler([
                new Response(400, ['Content-Type' => 'application/json'], (string) json_encode([
                    'error' => 'invalid_grant', 'error_description' => 'refresh token is expired',
                ])),
            ])),
        );

        try {
            $client->oidcRefresh(self::TOKEN_A, configuration: $this->configuration());
            self::fail('expected a failure');
        } catch (\Throwable $e) {
            self::assertStringNotContainsString(self::TOKEN_A, $e->getMessage());
            self::assertStringNotContainsString(self::TOKEN_A, (string) $e->getPrevious()?->getMessage());
        }
    }
}
