<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AccessEnforcer;
use Axiam\Sdk\Attributes\RequireAccess;
use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Oidc\UmaChallenge;
use Axiam\Sdk\UmaChallenger;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * The §20.3 emit half, wired into {@see AccessEnforcer} — the one enforcement
 * implementation both framework bridges delegate to, so configuring a
 * {@see UmaChallenger} once covers Laravel and Symfony alike.
 *
 * Everything asserted here is about the *deny* path, because that is the only path that
 * mints anything:
 *
 *   1. A denial with a challenger mints exactly one ticket and emits it.
 *   2. An allow mints nothing — an enforcer that minted on the happy path would put a
 *      Protection API call in front of every authorized request.
 *   3. A minting failure still denies, without a challenge. An outage must not turn a
 *      deny into a 503, and must never turn it into an allow.
 */
final class UmaChallengeEnforcerTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';
    private const RESOURCE_ID = '22222222-2222-2222-2222-222222222222';
    private const PAT = 'pat-token-value';
    private const TICKET = 'ticket-value';

    /** @var array{user_id: string, tenant_id: string, roles: list<string>} */
    private const IDENTITY = [
        'user_id' => '11111111-1111-1111-1111-111111111111',
        'tenant_id' => self::TENANT,
        'roles' => ['editor'],
    ];

    /**
     * @param list<Response|\Throwable> $queue
     * @param list<RequestInterface> $captured Every request that reached the transport,
     *        in order — how these tests count Protection API calls.
     */
    private function clientWith(array $queue, array &$captured = []): AxiamClient
    {
        $mock = new MockHandler($queue);
        $transportHandler = static function (RequestInterface $request, array $options) use ($mock, &$captured) {
            $captured[] = $request;

            return $mock($request, $options);
        };

        return new AxiamClient(self::BASE_URL, self::TENANT, transportHandler: $transportHandler);
    }

    private function challenger(AxiamClient $client): UmaChallenger
    {
        return new UmaChallenger('invoices', 'https://id.example', new Sensitive(self::PAT), $client);
    }

    /** @param list<RequestInterface> $captured */
    private function permRequests(array $captured): array
    {
        return array_values(array_filter(
            $captured,
            static fn (RequestInterface $request): bool => str_contains($request->getUri()->getPath(), '/uma2/perm'),
        ));
    }

    private function attribute(string $action = 'read'): RequireAccess
    {
        return new RequireAccess(action: $action, resourceParam: 'id');
    }

    /** @return array<string,mixed> */
    private function routeParams(): array
    {
        return ['id' => self::RESOURCE_ID];
    }

    public function testADenialMintsOneTicketAndEmitsTheChallenge(): void
    {
        $captured = [];
        $client = $this->clientWith([
            new Response(200, ['Content-Type' => 'application/json'], '{"allowed":false}'),
            new Response(201, ['Content-Type' => 'application/json'], '{"ticket":"' . self::TICKET . '"}'),
        ], $captured);
        $enforcer = new AccessEnforcer($client, null, $this->challenger($client));

        $response = $enforcer->enforceAccess(self::IDENTITY, $this->attribute(), $this->routeParams());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(403, $response->getStatusCode(), 'the challenge is additive, not a redirect');
        self::assertCount(1, $this->permRequests($captured), 'one ticket, not two');

        // The emitted header is the one this SDK's own parser consumes — the round trip
        // is the point of shipping both halves.
        $parsed = UmaChallenge::parse((string) $response->headers->get('WWW-Authenticate'));
        self::assertNotNull($parsed);
        self::assertSame('invoices', $parsed->realm);
        self::assertSame('https://id.example', $parsed->asUri);
        self::assertNotNull($parsed->ticket);
        self::assertSame(self::TICKET, $parsed->ticket->reveal());
    }

    public function testTheTicketAsksForTheActionThatWasRefused(): void
    {
        $captured = [];
        $client = $this->clientWith([
            new Response(200, ['Content-Type' => 'application/json'], '{"allowed":false}'),
            new Response(201, ['Content-Type' => 'application/json'], '{"ticket":"' . self::TICKET . '"}'),
        ], $captured);
        $enforcer = new AccessEnforcer($client, null, $this->challenger($client));

        $enforcer->enforceAccess(self::IDENTITY, $this->attribute('approve'), $this->routeParams());

        // §20.2: the UMA scope is the AXIAM *action*. Asking for anything else would
        // mint a ticket for authority other than the one just refused — and would step
        // outside the grants the engine evaluated, deny rules included.
        $perm = $this->permRequests($captured)[0];
        $body = json_decode((string) $perm->getBody(), true);
        self::assertSame([['resource_id' => self::RESOURCE_ID, 'resource_scopes' => ['approve']]], $body);
    }

    public function testAnAllowMintsNothing(): void
    {
        $captured = [];
        $client = $this->clientWith([
            new Response(200, ['Content-Type' => 'application/json'], '{"allowed":true}'),
        ], $captured);
        $enforcer = new AccessEnforcer($client, null, $this->challenger($client));

        $response = $enforcer->enforceAccess(self::IDENTITY, $this->attribute(), $this->routeParams());

        self::assertNull($response);
        // Minting on the happy path would put a Protection API call — and a live
        // credential — in front of every authorized request.
        self::assertCount(0, $this->permRequests($captured));
    }

    public function testAMintingFailureStillDeniesWithoutAChallenge(): void
    {
        $captured = [];
        $client = $this->clientWith([
            new Response(200, ['Content-Type' => 'application/json'], '{"allowed":false}'),
            new Response(500, [], 'server error'),
            // The SDK's §16 read retry may re-attempt the mint; the queue tolerates it.
            new Response(500, [], 'server error'),
            new Response(500, [], 'server error'),
            new Response(500, [], 'server error'),
        ], $captured);
        $enforcer = new AccessEnforcer($client, null, $this->challenger($client));

        $response = $enforcer->enforceAccess(self::IDENTITY, $this->attribute(), $this->routeParams());

        // Failure is not escalation: the caller was going to be refused, and a
        // Protection API outage must not turn that into a 503 — nor, far worse, into an
        // allow.
        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(403, $response->getStatusCode());
        self::assertFalse($response->headers->has('WWW-Authenticate'));
        self::assertGreaterThanOrEqual(1, count($this->permRequests($captured)));
    }

    public function testAnExpiredPatDeniesWithoutAChallenge(): void
    {
        // 401 from the Protection API — the PAT itself is no longer good. The classic
        // production failure, and the one most tempting to surface as a 500.
        $captured = [];
        $client = $this->clientWith([
            new Response(200, ['Content-Type' => 'application/json'], '{"allowed":false}'),
            new Response(401, [], '{"error":"invalid_token"}'),
        ], $captured);
        $enforcer = new AccessEnforcer($client, null, $this->challenger($client));

        $response = $enforcer->enforceAccess(self::IDENTITY, $this->attribute(), $this->routeParams());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(403, $response->getStatusCode());
        self::assertFalse($response->headers->has('WWW-Authenticate'));
    }

    public function testAServerIssued403OnTheCheckAlsoCarriesAChallenge(): void
    {
        // §11.2.5 maps a server-issued 403 on the check call itself to the same deny
        // outcome as an allowed=false body. It is the same refusal, so it is answerable
        // with the same ticket — the two deny paths must not disagree about that.
        $captured = [];
        $client = $this->clientWith([
            new Response(403, ['Content-Type' => 'application/json'], '{"error":"forbidden","message":"nope"}'),
            new Response(201, ['Content-Type' => 'application/json'], '{"ticket":"' . self::TICKET . '"}'),
        ], $captured);
        $enforcer = new AccessEnforcer($client, null, $this->challenger($client));

        $response = $enforcer->enforceAccess(self::IDENTITY, $this->attribute(), $this->routeParams());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(403, $response->getStatusCode());
        self::assertTrue($response->headers->has('WWW-Authenticate'));
    }

    public function testWithoutAChallengerADenialIsThePlain403(): void
    {
        $captured = [];
        $client = $this->clientWith([
            new Response(200, ['Content-Type' => 'application/json'], '{"allowed":false}'),
        ], $captured);
        $enforcer = new AccessEnforcer($client);

        $response = $enforcer->enforceAccess(self::IDENTITY, $this->attribute(), $this->routeParams());

        // Opt-in means opt-in: an application that never asked for UMA semantics gets no
        // Protection API traffic from its guards.
        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(403, $response->getStatusCode());
        self::assertFalse($response->headers->has('WWW-Authenticate'));
        self::assertCount(0, $this->permRequests($captured));
    }

    public function testTheChallengerNeverRendersItsPat(): void
    {
        // §7: a challenger is configuration an application may reasonably log, and the
        // PAT inside it is not.
        $rendered = (string) $this->challenger($this->clientWith([]));

        self::assertStringNotContainsString(self::PAT, $rendered);
        self::assertStringContainsString('invoices', $rendered);
    }
}
