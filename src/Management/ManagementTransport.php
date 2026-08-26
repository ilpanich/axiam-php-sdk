<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management;

use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\RequestEndEvent;
use Axiam\Sdk\Core\RequestStartEvent;
use Axiam\Sdk\Core\RetryPolicy;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Core\TelemetryDispatcher;
use Axiam\Sdk\Session;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Http\Message\ResponseInterface;

/**
 * The single wire path every one of the 146 §27 management operations goes through
 * (CONTRACT.md §27.8).
 *
 * §27.8 requires the generated layer to sit on the SDK's EXISTING request path rather
 * than open a second one. It is built on the same Guzzle client that carries
 * {@see \Axiam\Sdk\Rest\AuthMiddleware} and {@see \Axiam\Sdk\Rest\RefreshMiddleware}, so
 * §3 CSRF, the §4 cookie jar, the §5 `X-Tenant-ID` header, §6 TLS and §9 single-flight
 * refresh apply to all 146 by construction — not by 146 opportunities to forget one.
 *
 * What this class adds on top of that path is only what §27 asks for:
 *
 * - **Rule 1** — no session means no wire call. {@see self::requireSession()} throws
 *   before a request is built, so an unauthenticated management call cannot reach the
 *   server at all, let alone be counted against it.
 * - **Rule 8** — only `GET` is retried. A `POST`/`PATCH`/`PUT`/`DELETE` that failed may
 *   well have been applied, and §16's helper cannot tell.
 * - **Rule 10** — nothing is cached. Every call is a wire call; an administrative read
 *   that answers from a stale copy is worse than a slow one.
 * - **Rule 11** — telemetry carries the path TEMPLATE (`/api/v1/users/{user_id}`), never
 *   the substituted path, so identifiers never reach a metrics label and cardinality
 *   stays bounded.
 * - **§27.5** — a {@see Sensitive} in a request body is unwrapped on the way out. This is
 *   the one place in the SDK where that happens, and it happens explicitly rather than by
 *   serializer configuration (see {@see self::encodeBody()}).
 */
final class ManagementTransport
{
    /**
     * @param Client              $http     The full production stack (auth + refresh
     *                                      middleware) — §27.8's "existing request path".
     * @param Session             $session  Consulted for rule 1's session check.
     * @param TelemetryDispatcher $telemetry §19 dispatcher; one event pair per attempt.
     * @param bool                $retryEnabled §16.1 disable switch, honoured as-is.
     */
    public function __construct(
        private readonly Client $http,
        private readonly Session $session,
        private readonly TelemetryDispatcher $telemetry,
        private readonly bool $retryEnabled = true,
    ) {
    }

    /**
     * Issues one management operation and returns its decoded body.
     *
     * @param string              $operation    Canonical name (`users.get`), used for §19 labels.
     * @param string              $method       HTTP method, uppercase.
     * @param string              $pathTemplate The `{placeholder}` form — what telemetry sees.
     * @param array<string,string> $pathValues  Substituted into the template, URL-encoded.
     * @param array<string,mixed> $query        Query parameters; nulls are dropped.
     * @param array<string,mixed>|null $body    Request body, or `null` for none.
     * @return array<mixed>|null The decoded body, or `null` for a `204`/empty response.
     */
    public function send(
        string $operation,
        string $method,
        string $pathTemplate,
        array $pathValues = [],
        array $query = [],
        ?array $body = null,
    ): ?array {
        $this->requireSession($operation);

        $path = self::substitute($pathTemplate, $pathValues);
        $options = $this->options($operation, $query, $body);

        // Rule 8: a GET is the only method §16 may replay. Everything else may already
        // have been applied server-side, and no client can tell from a transport failure.
        //
        // A ValidationError is excluded on TOP of that, method regardless. It is a
        // NetworkError only because §27.4 rule 7 puts it there, but it is a decisive
        // answer from the server rather than a transport failure: re-sending a body the
        // server has already rejected just spends the caller's rate limit to be told the
        // same thing three times.
        $retryable = static fn (NetworkError $e): bool
            => $method === 'GET' && !$e instanceof ValidationError;

        $response = RetryPolicy::execute(
            $operation,
            $this->retryEnabled,
            $this->telemetry,
            fn (int $attempt): ResponseInterface => $this->attempt(
                $operation,
                $method,
                $pathTemplate,
                $path,
                $options,
                $attempt,
            ),
            null,
            null,
            $retryable,
        );

        return self::decode($response, $operation);
    }

    /**
     * Issues a paginated list operation and returns one {@see Page} (§27.4 rule 4).
     *
     * `total` is read from the server's own count field, never from
     * `count($items)` — the two differ on every page but the last, and deriving one from
     * the other is how a client silently processes only the first page.
     *
     * @param string               $operation    Canonical name, for §19 labels.
     * @param string               $pathTemplate The `{placeholder}` form.
     * @param array<string,string> $pathValues   Substituted into the template.
     * @param array<string,mixed>  $query        Extra query parameters beyond paging.
     * @param callable(array<string,mixed>): mixed $decode Maps one raw item to its model.
     * @return Page<mixed>
     */
    public function sendPage(
        string $operation,
        string $pathTemplate,
        array $pathValues,
        array $query,
        PageRequest $page,
        callable $decode,
    ): Page {
        $decoded = $this->send($operation, 'GET', $pathTemplate, $pathValues, $query + $page->toQuery());

        $rawItems = $decoded['items'] ?? $decoded['data'] ?? [];
        $items = [];
        if (\is_array($rawItems)) {
            foreach ($rawItems as $item) {
                if (\is_array($item)) {
                    $items[] = $decode($item);
                }
            }
        }

        $total = $decoded['total'] ?? $decoded['total_count'] ?? null;

        return new Page($items, \is_int($total) ? $total : \count($items), $page);
    }

    /**
     * Walks every page of a paginated operation, yielding items one at a time.
     *
     * Stops on the first EMPTY page, per §27.4 rule 4 — NOT on the first short page. A
     * server is free to return fewer items than asked for (a filter applied after
     * paging, a deleted row) without that meaning the collection has ended, and treating
     * a short page as the end silently truncates the walk.
     *
     * @param callable(PageRequest): Page<mixed> $fetch Fetches one page.
     * @return \Generator<int,mixed>
     */
    public static function walk(callable $fetch, ?PageRequest $start = null): \Generator
    {
        $request = $start ?? new PageRequest();
        while (true) {
            $page = $fetch($request);
            if ($page->isEmpty()) {
                return;
            }
            foreach ($page->items as $item) {
                yield $item;
            }
            $request = $page->nextRequest();
        }
    }

    /**
     * §27.4 rule 1: with no session there is no wire call at all.
     *
     * Checked before the request is built rather than left to the server's `401`, for
     * three reasons: it costs the caller nothing, it cannot be counted against a rate
     * limit, and the resulting message names the operation instead of arriving as a bare
     * transport failure.
     */
    private function requireSession(string $operation): void
    {
        if ($this->session->accessToken() === null) {
            throw new AuthError(sprintf(
                '%s: no active session — management operations require an authenticated '
                . 'caller (CONTRACT.md §27.4 rule 1)',
                $operation,
            ));
        }
    }

    /**
     * One attempt, wrapped in its §19 event pair.
     *
     * §19.2 rule 5 wants one pair per ATTEMPT, so a retried call can be told apart from a
     * single slow one; `$attempt` therefore comes from {@see RetryPolicy::execute()}
     * rather than being hard-coded to 1.
     *
     * @param array<string,mixed> $options
     */
    private function attempt(
        string $operation,
        string $method,
        string $pathTemplate,
        string $path,
        array $options,
        int $attempt,
    ): ResponseInterface {
        // Rule 11: the TEMPLATE, never $path — a metrics label carrying a user id is an
        // unbounded-cardinality series and, on this surface, a slow identifier leak.
        $this->telemetry->emit(new RequestStartEvent($operation, $method, $pathTemplate, $attempt));
        $started = microtime(true);

        try {
            $response = $this->http->request($method, $path, $options);
        } catch (GuzzleException $e) {
            $this->finish($operation, $method, $pathTemplate, $attempt, null, $started, 'transport_error');

            throw NetworkError::fromException($e, $operation);
        }

        $status = $response->getStatusCode();
        $this->finish(
            $operation,
            $method,
            $pathTemplate,
            $attempt,
            $status,
            $started,
            $status < 400 ? 'success' : 'error',
        );

        if ($status >= 400) {
            throw ManagementErrorMapper::fromResponse($response, $operation);
        }

        return $response;
    }

    /** Emits the closing §19 event for one attempt. */
    private function finish(
        string $operation,
        string $method,
        string $pathTemplate,
        int $attempt,
        ?int $status,
        float $started,
        string $outcome,
    ): void {
        $this->telemetry->emit(new RequestEndEvent(
            $operation,
            $method,
            $pathTemplate,
            $attempt,
            $status,
            (microtime(true) - $started) * 1000.0,
            $outcome,
        ));
    }

    /**
     * Builds the Guzzle options for one call.
     *
     * `http_errors` stays OFF: a non-2xx must reach {@see ManagementErrorMapper} so §27.4
     * rule 7 can classify it, and Guzzle's own exception would have collapsed `404`,
     * `409` and `422` into the same shape first.
     *
     * @param array<string,mixed>      $query
     * @param array<string,mixed>|null $body
     * @return array<string,mixed>
     */
    private function options(string $operation, array $query, ?array $body): array
    {
        $options = ['http_errors' => false];

        $clean = array_filter($query, static fn (mixed $v): bool => $v !== null);
        if ($clean !== []) {
            $options['query'] = $clean;
        }

        if ($body !== null) {
            $options['body'] = self::encodeBody($operation, $body);
            $options['headers'] = ['Content-Type' => 'application/json'];
        }

        return $options;
    }

    /**
     * Serializes a request body, revealing any {@see Sensitive} it carries (§27.5).
     *
     * This is where PHP's §27.5 story differs from its siblings, and the difference is in
     * PHP's favour. `Sensitive` implements `JsonSerializable` and returns `[SENSITIVE]`,
     * which is exactly right everywhere EXCEPT the one-time secret a §27 write must
     * actually send. Java reaches for a Jackson mixin and C# for converter precedence;
     * `json_encode` offers no such override, because `JsonSerializable` is consulted on
     * the instance and nothing outranks it.
     *
     * So the unwrapping is explicit: walk the body, replace each `Sensitive` with
     * {@see Sensitive::reveal()}, then encode. No precedence rule to remember, no way for
     * a serializer default to start shipping the literal `[SENSITIVE]` to the server as a
     * password, and the one place secrets are revealed is a named method you can grep for.
     *
     * @param array<string,mixed> $body
     */
    private static function encodeBody(string $operation, array $body): string
    {
        $json = json_encode(self::reveal($body), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw NetworkError::fromMessage(sprintf(
                '%s: request body could not be encoded as JSON (%s)',
                $operation,
                json_last_error_msg(),
            ));
        }

        return $json;
    }

    /**
     * Recursively replaces every {@see Sensitive} with its revealed value.
     *
     * Recursive rather than top-level-only because a secret is not always a top-level
     * field: `{"credential": {"private_key": Sensitive}}` is a real §27 shape, and a
     * shallow unwrap would post the string `[SENSITIVE]` as somebody's key.
     */
    private static function reveal(mixed $value): mixed
    {
        if ($value instanceof Sensitive) {
            return $value->reveal();
        }

        if (\is_array($value)) {
            return array_map(static fn (mixed $item): mixed => self::reveal($item), $value);
        }

        return $value;
    }

    /**
     * Substitutes `{name}` placeholders, URL-encoding each value.
     *
     * Encoding matters: an identifier is caller-supplied, and a raw `/` or `?` in one
     * would silently retarget the request at a different route.
     *
     * @param array<string,string> $values
     */
    private static function substitute(string $template, array $values): string
    {
        $path = $template;
        foreach ($values as $name => $value) {
            $path = str_replace('{' . $name . '}', rawurlencode($value), $path);
        }

        return $path;
    }

    /**
     * Decodes a success body, tolerating the 36 operations that return nothing.
     *
     * @return array<mixed>|null
     */
    private static function decode(ResponseInterface $response, string $operation): ?array
    {
        if ($response->getStatusCode() === 204) {
            return null;
        }

        $raw = (string) $response->getBody();
        if (trim($raw) === '') {
            return null;
        }

        $decoded = json_decode($raw, true);
        if (!\is_array($decoded)) {
            throw NetworkError::fromMessage(sprintf(
                '%s: expected a JSON object or array in the response body',
                $operation,
            ));
        }

        return $decoded;
    }
}
