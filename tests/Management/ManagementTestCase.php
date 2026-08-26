<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Management;

use Axiam\Sdk\AxiamClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * Shared rig for the §27 management tests.
 *
 * Everything runs against the SDK's real request path with a `MockHandler` at the
 * bottom, exactly like the rest of this suite — not against a stubbed transport. That
 * matters for §27.8: a test that mocked `ManagementTransport` would pass just as happily
 * if the generated layer had quietly opened its own HTTP client, which is the one thing
 * §27.8 forbids.
 */
abstract class ManagementTestCase extends TestCase
{
    protected const BASE_URL = 'https://axiam.test';
    protected const TENANT = 'acme';
    protected const ORG_ID = '11111111-1111-4111-8111-111111111111';
    protected const TENANT_ID = '11111111-1111-4111-8111-111111111111';

    protected MockHandler $handler;

    /** How many responses were queued up front, so sent-count can be derived. */
    private int $queued = 0;

    /**
     * Every request that reached the transport, in order.
     *
     * `MockHandler` is final and keeps only the LAST request, which is not enough to
     * assert things like "plan() issued no writes". Wrapping it in a recording callable
     * is what makes that assertion real rather than a spot check on the final call.
     *
     * @var list<RequestInterface>
     */
    protected array $requests = [];

    /**
     * A signed-in client whose next response is `$status`/`$body`.
     *
     * The session is established by a real login through the same handler, so
     * §27.4 rule 1's "no session, no wire call" check sees a genuine cookie-sourced
     * token rather than a field poked into place.
     *
     * @param array<mixed>|null $body Decoded body to return, or `null` for `204`.
     */
    protected function signedInClient(int $status = 200, ?array $body = null): AxiamClient
    {
        $this->handler = new MockHandler([
            new Response(200, ['Set-Cookie' => 'axiam_access=t0ken; Path=/'], (string) json_encode([
                'user' => ['id' => self::ORG_ID],
            ])),
            $body === null
                ? new Response($status === 200 ? 204 : $status)
                : new Response($status, ['Content-Type' => 'application/json'], (string) json_encode($body)),
        ]);

        $this->queued = \count($this->handler);
        $recorder = $this->recorder();

        $client = new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            orgId: self::ORG_ID,
            oidcTenantId: self::TENANT_ID,
            transportHandler: $recorder,
            retryEnabled: false,
        );
        $client->login('admin@axiam.test', 'pw');

        return $client;
    }

    /**
     * A signed-in client with no management response queued — for the error paths that
     * must throw before any wire call happens.
     */
    protected function signedInClientNoResponse(): AxiamClient
    {
        $this->handler = new MockHandler([
            new Response(200, ['Set-Cookie' => 'axiam_access=t0ken; Path=/'], (string) json_encode([
                'user' => ['id' => self::ORG_ID],
            ])),
        ]);

        $this->queued = \count($this->handler);
        $recorder = $this->recorder();

        $client = new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            orgId: self::ORG_ID,
            oidcTenantId: self::TENANT_ID,
            transportHandler: $recorder,
            retryEnabled: false,
        );
        $client->login('admin@axiam.test', 'pw');

        return $client;
    }

    /**
     * A signed-in client whose queued responses are exactly `$responses`, in order.
     *
     * For the multi-request cases — auto-paging, retry, apply-stops-at-first-failure —
     * where one canned response is not enough. A `Throwable` in the queue is how
     * `MockHandler` models a transport that never answered at all.
     */
    protected function signedInWith(Response|\Throwable ...$responses): AxiamClient
    {
        $this->handler = new MockHandler([
            new Response(200, ['Set-Cookie' => 'axiam_access=t0ken; Path=/'], (string) json_encode([
                'user' => ['id' => self::ORG_ID],
            ])),
            ...$responses,
        ]);

        $this->queued = \count($this->handler);
        $recorder = $this->recorder();

        $client = new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            orgId: self::ORG_ID,
            oidcTenantId: self::TENANT_ID,
            transportHandler: $recorder,
            retryEnabled: true,
        );
        $client->login('admin@axiam.test', 'pw');

        return $client;
    }

    /**
     * A JSON response with `$body` as its decoded content.
     *
     * @param array<mixed> $body
     */
    protected static function json(int $status, array $body): Response
    {
        return new Response($status, ['Content-Type' => 'application/json'], (string) json_encode($body));
    }

    /**
     * One page of a paginated list response.
     *
     * @param list<array<string,mixed>> $items
     */
    protected static function page(array $items, int $total): Response
    {
        return self::json(200, ['items' => $items, 'total' => $total, 'offset' => 0, 'limit' => 50]);
    }

    /**
     * How many requests have reached the transport so far, the login included.
     *
     * Derived from what the queue has left rather than counted by a spy, so a test that
     * asserts "no wire call happened" is asserting about the transport itself.
     */
    protected function requestCount(): int
    {
        return $this->queued - \count($this->handler);
    }

    /**
     * A transport handler that records each request, then delegates to the mock.
     *
     * @return callable(RequestInterface, array<string,mixed>): mixed
     */
    private function recorder(): callable
    {
        $this->requests = [];
        $mock = $this->handler;

        return function (RequestInterface $request, array $options) use ($mock): mixed {
            $this->requests[] = $request;

            return $mock($request, $options);
        };
    }

    /**
     * The HTTP methods of every management request sent, the login POST excluded.
     *
     * @return list<string>
     */
    protected function sentMethods(): array
    {
        return array_values(array_map(
            static fn (RequestInterface $r): string => $r->getMethod(),
            \array_slice($this->requests, 1),
        ));
    }

    /** The request the SDK last put on the wire. */
    protected function lastRequest(): RequestInterface
    {
        $request = $this->handler->getLastRequest();
        self::assertNotNull($request, 'no request reached the transport');

        return $request;
    }

    /** The decoded body of the request the SDK last sent, or `[]` when it sent none. */
    protected function lastBody(): mixed
    {
        $raw = (string) $this->lastRequest()->getBody();

        return $raw === '' ? [] : json_decode($raw, true);
    }

    /**
     * Asserts that every key the server sent survived the decode into `$model`.
     *
     * This is the strongest per-operation check in the suite and the reason it exists:
     * a generator that drops a field still produces code that compiles, still issues the
     * right request, and still returns a well-formed object — it just silently loses
     * data. A sibling SDK shipped exactly that bug, losing a one-time
     * `provisioning_token` that the server never sends twice. Re-rendering the decoded
     * model and comparing key sets is what catches it.
     *
     * @param array<string,mixed> $mounted The object the fake server returned.
     */
    protected function assertDecodedEveryField(array $mounted, object $model): void
    {
        self::assertTrue(
            method_exists($model, 'toArray'),
            $model::class . ' has no toArray() to re-render',
        );
        /** @var array<string,mixed> $rendered */
        $rendered = $model->toArray();

        $missing = array_diff(array_keys($mounted), array_keys($rendered));
        self::assertSame([], array_values($missing), sprintf(
            '%s dropped %s on the way in — the server sent it and the model does not carry it',
            $model::class,
            implode(', ', $missing),
        ));
    }
}
