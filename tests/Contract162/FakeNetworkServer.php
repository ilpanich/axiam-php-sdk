<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract162;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;

/**
 * An in-memory AXIAM `network` namespace for the §27.6.2 manifest tests: enough of
 * CONTRACT.md §36.3 to make `apply` then `plan` a real round trip rather than a script of
 * canned answers — versions that move on every write and are checked on every replace, a
 * profile checked against its segment's version, the tenant's cap clamping what a profile
 * reads as and refusing what a write states above it, and a failure the test can inject.
 *
 * It is a Guzzle base handler: everything the SDK sends reaches {@see self::__invoke()}.
 */
final class FakeNetworkServer
{
    public const TENANT_ID = '22222222-2222-4222-8222-222222222222';

    /** @var array<string,array<string,mixed>> segment id => row, as the server returns it */
    public array $segments = [];

    /** @var array<string,array<string,mixed>> segment id => the profile as STORED (unclamped) */
    public array $profiles = [];

    /** @var array<string,mixed> */
    public array $policy = [
        'tenant_id' => self::TENANT_ID, 'session_timeout_max_secs' => 3600, 'version' => 0,
    ];

    /** The `version` a freshly created row starts at; not 1, so a constant cannot pass a test. */
    public int $firstVersion = 7;

    /** @var list<RequestInterface> every request received, the login included */
    public array $requests = [];

    /** @var list<array{0:string,1:string,2:Response}> method, path regex, answer — each used once */
    private array $injected = [];

    /** Answer the next `$method` request whose path matches `$pathRegex` with `$response`, once. */
    public function failNext(string $method, string $pathRegex, Response $response): void
    {
        $this->injected[] = [strtoupper($method), $pathRegex, $response];
    }

    /**
     * A segment already on the server; returns its id.
     *
     * @param list<string> $filterIds
     */
    public function seedSegment(
        string $site,
        string $kind,
        string $name,
        int $vlan,
        ?int $rank = null,
        array $filterIds = [],
        bool $enabled = true,
    ): string {
        $id = self::uuid();
        $row = [
            'id' => $id, 'tenant_id' => self::TENANT_ID,
            'path' => '/network/' . ($kind === 'access' ? 'zones' : 'quarantine') . '/' . $site . '/' . $name,
            'name' => $name, 'site_key' => $site, 'kind' => $kind, 'vlan_id' => $vlan,
            'filter_ids' => $filterIds, 'enabled' => $enabled, 'version' => $this->firstVersion,
            'created_by' => self::uuid(), 'updated_by' => self::uuid(),
            'created_at' => '2026-10-16T08:00:00Z', 'updated_at' => '2026-10-16T08:00:00Z',
        ];
        if ($rank !== null) {
            $row['rank'] = $rank;
        }
        $this->segments[$id] = $row;

        return $id;
    }

    /**
     * A profile already on the server, as STORED (the read clamps it to the cap).
     *
     * @param array<string,mixed> $members
     */
    public function seedProfile(string $segmentId, int $storedTimeout, array $members = []): void
    {
        $this->profiles[$segmentId] = $members + [
            'segment_id' => $segmentId, 'tenant_id' => self::TENANT_ID,
            'dictionary' => 'axiam-radius-reply/1', 'session_timeout_secs' => $storedTimeout,
            'termination_action' => 'radius_request', 'version' => $this->firstVersion,
            'created_by' => self::uuid(), 'updated_by' => self::uuid(),
            'created_at' => '2026-10-16T08:00:00Z', 'updated_at' => '2026-10-16T08:00:00Z',
        ];
    }

    /** The profile as a read returns it: effective, with `session_timeout_clamped`. @return array<string,mixed> */
    public function readProfile(string $segmentId): array
    {
        $row = $this->profiles[$segmentId];
        $cap = (int) $this->policy['session_timeout_max_secs'];
        $stored = (int) $row['session_timeout_secs'];
        $row['session_timeout_secs'] = min($stored, $cap);
        $row['session_timeout_clamped'] = $stored > $cap;
        if (isset($row['idle_timeout_secs'])) {
            $row['idle_timeout_secs'] = min((int) $row['idle_timeout_secs'], (int) $row['session_timeout_secs']);
        }

        return $row;
    }

    /** The id of the segment at `site`, `kind`, `name`, or `null`. */
    public function segmentId(string $site, string $kind, string $name): ?string
    {
        foreach ($this->segments as $id => $row) {
            if ($row['site_key'] === $site && $row['kind'] === $kind && $row['name'] === $name) {
                return $id;
            }
        }

        return null;
    }

    /**
     * The management requests received, as `METHOD /path` — the login excluded.
     *
     * @return list<string>
     */
    public function calls(): array
    {
        $out = [];
        foreach ($this->requests as $request) {
            $line = $request->getMethod() . ' ' . $request->getUri()->getPath();
            if ($line !== 'POST /api/v1/auth/login') {
                $out[] = $line;
            }
        }

        return $out;
    }

    /**
     * The management requests received that are not `GET`s.
     *
     * @return list<string>
     */
    public function writes(): array
    {
        return array_values(array_filter($this->calls(), static fn (string $c): bool => !str_starts_with($c, 'GET ')));
    }

    /**
     * The decoded JSON bodies sent to `METHOD path`, in order.
     *
     * @return list<array<string,mixed>>
     */
    public function bodies(string $method, string $path): array
    {
        $out = [];
        foreach ($this->requests as $request) {
            if ($request->getMethod() === $method && $request->getUri()->getPath() === $path) {
                $decoded = json_decode((string) $request->getBody(), true);
                $out[] = \is_array($decoded) ? $decoded : [];
            }
        }

        return $out;
    }

    /** @param array<string,mixed> $options */
    public function __invoke(RequestInterface $request, array $options): PromiseInterface
    {
        $this->requests[] = $request;

        return Create::promiseFor($this->answer($request));
    }

    private function answer(RequestInterface $request): Response
    {
        $method = $request->getMethod();
        $path = $request->getUri()->getPath();
        parse_str($request->getUri()->getQuery(), $query);
        $body = json_decode((string) $request->getBody(), true);
        $body = \is_array($body) ? $body : [];

        if ($method === 'POST' && $path === '/api/v1/auth/login') {
            return self::json(200, ['user' => ['id' => self::uuid()]], [
                'Set-Cookie' => 'axiam_access=' . bin2hex(random_bytes(16)) . '; Path=/',
            ]);
        }
        foreach ($this->injected as $i => [$m, $regex, $response]) {
            if ($m === $method && preg_match($regex, $path) === 1) {
                array_splice($this->injected, $i, 1);

                return $response;
            }
        }

        if ($path === '/api/v1/network/policy') {
            return $this->policyRoute($method, $body);
        }
        if ($path === '/api/v1/network/segments') {
            return $method === 'GET'
                ? self::page(array_values($this->segments), $query)
                : $this->createSegment($body);
        }
        if (preg_match('#^/api/v1/network/segments/([^/]+)$#', $path, $m) === 1) {
            return $this->segmentRoute($method, $m[1], $body, $query);
        }
        if ($path === '/api/v1/network/profiles') {
            if ($method === 'GET') {
                return self::page(array_map($this->readProfile(...), array_keys($this->profiles)), $query);
            }

            return $this->createProfile($body);
        }
        if (preg_match('#^/api/v1/network/profiles/([^/]+)$#', $path, $m) === 1) {
            return $this->profileRoute($method, $m[1], $body, $query);
        }

        return self::json(404, ['error' => 'not_found', 'message' => 'no route ' . $path]);
    }

    /**
     * @param array<string,mixed> $body
     */
    private function policyRoute(string $method, array $body): Response
    {
        if ($method === 'GET') {
            return self::json(200, $this->policy);
        }
        if (($body['version'] ?? null) !== $this->policy['version']) {
            return self::conflict('stale_version');
        }
        $this->policy['session_timeout_max_secs'] = $body['session_timeout_max_secs'];
        $this->policy['version'] = (int) $this->policy['version'] + 1;

        return self::json(200, $this->policy);
    }

    /**
     * @param array<string,mixed> $body
     */
    private function createSegment(array $body): Response
    {
        if ($this->segmentId((string) $body['site_key'], (string) $body['kind'], (string) $body['name']) !== null) {
            return self::conflict('duplicate_name', 'already_exists');
        }
        foreach ($this->segments as $row) {
            if ($row['site_key'] === $body['site_key'] && $row['vlan_id'] === $body['vlan_id']) {
                return self::conflict('duplicate_vlan', 'already_exists');
            }
        }
        $id = $this->seedSegment(
            (string) $body['site_key'],
            (string) $body['kind'],
            (string) $body['name'],
            (int) $body['vlan_id'],
            isset($body['rank']) ? (int) $body['rank'] : null,
            \array_key_exists('filter_ids', $body) ? $body['filter_ids'] : [],
            (bool) ($body['enabled'] ?? true),
        );

        return self::json(201, $this->segments[$id]);
    }

    /**
     * @param array<string,mixed> $body
     * @param array<string,mixed> $query
     */
    private function segmentRoute(string $method, string $id, array $body, array $query): Response
    {
        if (!isset($this->segments[$id])) {
            return self::json(404, ['error' => 'not_found', 'message' => 'no such segment']);
        }
        $row = &$this->segments[$id];
        if ($method === 'GET') {
            return self::json(200, $row);
        }
        $version = $method === 'DELETE' ? (int) ($query['version'] ?? -1) : ($body['version'] ?? null);
        if ($version !== $row['version']) {
            return self::conflict('stale_version');
        }
        if ($method === 'DELETE') {
            unset($this->segments[$id], $this->profiles[$id]);

            return new Response(204);
        }
        foreach (['vlan_id', 'filter_ids', 'enabled'] as $member) {
            $row[$member] = $body[$member];
        }
        unset($row['rank']);
        if (isset($body['rank'])) {
            $row['rank'] = $body['rank'];
        }
        $row['version'] = (int) $row['version'] + 1;

        return self::json(200, $row);
    }

    /**
     * @param array<string,mixed> $body
     */
    private function createProfile(array $body): Response
    {
        $id = (string) $body['segment_id'];
        if (!isset($this->segments[$id])) {
            return self::json(404, ['error' => 'not_found', 'message' => 'no such segment']);
        }
        if (isset($this->profiles[$id])) {
            return self::conflict('profile_exists', 'already_exists');
        }
        if ($body['segment_version'] !== $this->segments[$id]['version']) {
            return self::conflict('stale_version');
        }
        $refused = $this->checkProfile($body['profile']);
        if ($refused !== null) {
            return $refused;
        }
        $this->seedProfile($id, (int) $body['profile']['session_timeout_secs'], $body['profile']);

        return self::json(201, $this->readProfile($id));
    }

    /**
     * @param array<string,mixed> $body
     * @param array<string,mixed> $query
     */
    private function profileRoute(string $method, string $id, array $body, array $query): Response
    {
        if (!isset($this->profiles[$id])) {
            return self::json(404, ['error' => 'not_found', 'message' => 'no such profile']);
        }
        if ($method === 'GET') {
            return self::json(200, $this->readProfile($id));
        }
        $version = $method === 'DELETE' ? (int) ($query['version'] ?? -1) : ($body['version'] ?? null);
        if ($version !== $this->profiles[$id]['version']) {
            return self::conflict('stale_version');
        }
        if ($method === 'DELETE') {
            unset($this->profiles[$id]);

            return new Response(204);
        }
        if ($body['segment_version'] !== $this->segments[$id]['version']) {
            return self::conflict('stale_version');
        }
        $refused = $this->checkProfile($body['profile']);
        if ($refused !== null) {
            return $refused;
        }
        $version = (int) $this->profiles[$id]['version'] + 1;
        $this->seedProfile($id, (int) $body['profile']['session_timeout_secs'], $body['profile']);
        $this->profiles[$id]['version'] = $version;

        return self::json(200, $this->readProfile($id));
    }

    /**
     * The write gate's H3: a timeout above the tenant's current cap is a `403`.
     *
     * @param array<string,mixed> $profile
     */
    private function checkProfile(array $profile): ?Response
    {
        $cap = (int) $this->policy['session_timeout_max_secs'];
        if ((int) $profile['session_timeout_secs'] > $cap) {
            return self::json(403, [
                'error' => 'authorization_denied',
                'message' => sprintf('session_timeout_secs is above the tenant\'s cap of %d', $cap),
            ]);
        }

        return null;
    }

    /**
     * @param list<array<string,mixed>> $items
     * @param array<string,mixed> $query
     */
    private static function page(array $items, array $query): Response
    {
        $offset = (int) ($query['offset'] ?? 0);
        $limit = (int) ($query['limit'] ?? 50);

        return self::json(200, [
            'items' => \array_slice($items, $offset, $limit),
            'total' => \count($items), 'offset' => $offset, 'limit' => $limit,
        ]);
    }

    private static function conflict(string $reason, string $error = 'conflict'): Response
    {
        return self::json(409, ['error' => $error, 'message' => 'a conflict (' . $reason . ')', 'reason_code' => $reason]);
    }

    /**
     * @param array<mixed> $body
     * @param array<string,string> $headers
     */
    private static function json(int $status, array $body, array $headers = []): Response
    {
        return new Response($status, $headers + ['Content-Type' => 'application/json'], (string) json_encode($body));
    }

    private static function uuid(): string
    {
        $b = random_bytes(16);
        $b[6] = \chr((\ord($b[6]) & 0x0f) | 0x40);
        $b[8] = \chr((\ord($b[8]) & 0x3f) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($b), 4));
    }
}
