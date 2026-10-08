<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract158;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Tests\Fixtures\RedactionAssertions;
use Axiam\Sdk\Tests\Fixtures\RoutedHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * Shared rig for the contract-1.58 management tests (§29, §30, §31, §32): a client signed in
 * through a real login against a {@see RoutedHandler}, with a session token generated at run
 * time, on the SDK's real request path.
 */
abstract class ManagementRouteTestCase extends TestCase
{
    use RedactionAssertions;

    protected const BASE_URL = 'https://iam.example.test';
    protected const TENANT_ID = '22222222-2222-4222-8222-222222222222';

    protected RoutedHandler $routes;

    protected function setUp(): void
    {
        $this->routes = new RoutedHandler();
    }

    /** A client signed in with a fresh session; `$retry` is §16.1's switch. */
    protected function client(bool $retry = false): AxiamClient
    {
        $this->routes->on('POST', '/api/v1/auth/login', new Response(200, [
            'Set-Cookie' => 'axiam_access=' . bin2hex(random_bytes(16)) . '; Path=/',
            'Content-Type' => 'application/json',
        ], (string) json_encode(['user' => ['id' => '33333333-3333-4333-8333-333333333333']])));
        $client = new AxiamClient(
            self::BASE_URL,
            'acme',
            orgId: '11111111-1111-4111-8111-111111111111',
            oidcTenantId: self::TENANT_ID,
            transportHandler: $this->routes,
            retryEnabled: $retry,
        );
        $client->login('admin@example.test', bin2hex(random_bytes(8)));

        return $client;
    }

    /** A random UUID (v4). */
    protected static function uuid(): string
    {
        $b = random_bytes(16);
        $b[6] = chr((ord($b[6]) & 0x0f) | 0x40);
        $b[8] = chr((ord($b[8]) & 0x3f) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }

    /**
     * The decoded JSON bodies sent to `METHOD path`, in order.
     *
     * @return list<mixed>
     */
    protected function bodies(string $method, string $path): array
    {
        return array_map(
            static function (RequestInterface $r): mixed {
                $raw = (string) $r->getBody();

                return $raw === '' ? null : json_decode($raw, true);
            },
            $this->routes->sent($method, $path),
        );
    }

    /**
     * The query strings sent to `METHOD path`, in order.
     *
     * @return list<string>
     */
    protected function queries(string $method, string $path): array
    {
        return array_map(static fn (RequestInterface $r): string => $r->getUri()->getQuery(), $this->routes->sent($method, $path));
    }

    /**
     * A page answer that serves `$item` at offsets below `$total` and nothing after — the
     * auto-pager's walk ends on the empty page.
     *
     * @param array<string,mixed> $item
     */
    protected static function pager(array $item, int $total): callable
    {
        return static function (RequestInterface $request) use ($item, $total): Response {
            parse_str($request->getUri()->getQuery(), $query);
            $offset = (int) ($query['offset'] ?? 0);

            return RoutedHandler::json(200, [
                'items' => $offset < $total ? [$item] : [],
                'total' => $total,
                'offset' => $offset,
                'limit' => 1,
            ]);
        };
    }
}
