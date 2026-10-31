<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract165;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\OAuthProtocolError;
use Axiam\Sdk\Oidc\OidcConfiguration;
use Axiam\Sdk\Oidc\OidcTokenSet;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Promise\Promise;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * CONTRACT.md §9, the contract-1.65 paragraph "A replayed refresh token ends the session": the
 * port's CONFIRMATION that the existing rules deliver what the paragraph asks. No SDK behaviour
 * changed; this is the §9 rule-2 burst test run against a `400 invalid_grant` instead of a success.
 *
 * It sits beside {@see \Axiam\Sdk\Tests\OidcRefreshBurstTest::testAFailedRefreshIsSharedByTheWholeBurstWithoutASecondWireCall},
 * which already asserts the shared failure outcome with an `invalid_grant` body; this test adds
 * what the 1.65 paragraph names beyond it: every waiter receives that one `OAuthProtocolError`
 * (the same error, not N look-alikes), there are N >= 5 of them, and the spent token is never
 * presented again.
 *
 * **The "later call with no new token" clause, in this SDK's form.** This SDK stores no refresh
 * token (§12.3 rule 1): `oidcRefresh()` takes the token as an argument, so there is no call that
 * can be "made with no new token from the caller" and nothing from which the spent one could be
 * re-presented. The closest form the contract allows is asserted instead: after the burst the guard
 * slot is vacated, and a later call carries only the token its caller supplies, never the spent one.
 */
final class RefreshReuseConfirmationTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT_UUID = '22222222-2222-2222-2222-222222222222';
    private const SPENT = 'the-already-rotated-refresh-token';
    private const FRESH = 'a-token-from-a-new-authorization';
    private const BURST = 6;

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

    /** @param list<RequestInterface> $requests */
    private function client(array &$requests, \Closure $respondWith): AxiamClient
    {
        $handler = function (RequestInterface $request, array $options) use (&$requests, $respondWith): PromiseInterface {
            $requests[] = $request;
            $promise = null;
            $promise = new Promise(function () use (&$promise, $request, $respondWith): void {
                \Fiber::suspend(); // the request is on the wire; the other callers arrive now
                $promise->resolve($respondWith($request));
            });

            return $promise;
        };

        return new AxiamClient(
            self::BASE_URL,
            'acme-tenant',
            oidcClientId: 'my-app',
            oidcClientSecret: 's3cr3t',
            oidcTenantId: self::TENANT_UUID,
            transportHandler: HandlerStack::create($handler),
        );
    }

    public function testInvalidGrantOnOidcRefreshIsOneWireCallSharedByEveryWaiterAndTheSpentTokenIsNeverRepresented(): void
    {
        $requests = [];
        $client = $this->client($requests, static fn (RequestInterface $request): Response => str_contains((string) $request->getBody(), self::SPENT)
            ? new Response(400, ['Content-Type' => 'application/json'], (string) json_encode([
                'error' => 'invalid_grant',
                'error_description' => 'refresh token is invalid or has been used',
            ]))
            : new Response(200, ['Content-Type' => 'application/json'], (string) json_encode([
                'access_token' => 'fresh-access', 'token_type' => 'Bearer', 'expires_in' => 900,
            ])));
        $configuration = $this->configuration();

        /** @var array<int,OidcTokenSet> $results */
        $results = [];
        /** @var array<int,\Throwable> $errors */
        $errors = [];
        $fibers = [];
        for ($i = 0; $i < self::BURST; $i++) {
            $fibers[$i] = new \Fiber(function () use ($client, $configuration, $i, &$results, &$errors): void {
                try {
                    $results[$i] = $client->oidcRefresh(self::SPENT, configuration: $configuration);
                } catch (\Throwable $e) {
                    $errors[$i] = $e;
                }
            });
        }
        foreach ($fibers as $fiber) {
            $fiber->start();
        }
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

        // Exactly ONE wire call for the whole burst.
        self::assertCount(1, $requests, 'one rotation attempt, not N-1 replays that would each end the session');
        self::assertSame('/oauth2/token', $requests[0]->getUri()->getPath());

        // Every waiter of the burst of N >= 5 receives that one OAuthProtocolError.
        self::assertGreaterThanOrEqual(5, self::BURST);
        self::assertSame([], $results, 'nobody gets a token set out of a refused refresh');
        self::assertCount(self::BURST, $errors);
        foreach ($errors as $i => $error) {
            self::assertInstanceOf(OAuthProtocolError::class, $error, "caller {$i}");
            self::assertSame('invalid_grant', $error->error, "caller {$i}");
            self::assertSame(400, $error->httpStatus, "caller {$i}");
        }
        self::assertSame(1, count(array_unique(array_map('spl_object_id', $errors))), 'the SAME error reaches every caller');

        // The spent token went out once, and the SDK holds nothing from which it could go out again.
        // A later call carries only the token its caller supplies; the guard slot is free.
        $fresh = new \Fiber(function () use ($client, $configuration, &$results): void {
            $results['later'] = $client->oidcRefresh(self::FRESH, configuration: $configuration);
        });
        $fresh->start();
        for ($pass = 0; $pass < 10 && $fresh->isSuspended(); $pass++) {
            $fresh->resume();
        }
        self::assertTrue($fresh->isTerminated());
        self::assertCount(2, $requests, 'the later call is its own wire call: the failed outcome is not replayed to it');
        self::assertStringContainsString(self::FRESH, (string) $requests[1]->getBody());
        self::assertStringNotContainsString(self::SPENT, (string) $requests[1]->getBody(), 'the spent token is never presented again');
        $spentPresentations = count(array_filter(
            $requests,
            static fn (RequestInterface $request): bool => str_contains((string) $request->getBody(), self::SPENT),
        ));
        self::assertSame(1, $spentPresentations);
    }
}
