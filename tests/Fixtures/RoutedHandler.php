<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Fixtures;

use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;

/**
 * A Guzzle base handler that answers by route rather than by queue position, and records
 * every request it receives.
 *
 * The contract-1.58 tests drive flows whose request ORDER is an implementation detail —
 * discovery, then a token request, then the ID token's JWKS fetch — and a positional
 * `MockHandler` queue would pin that order instead of the behaviour. Each route holds its own
 * queue; the last answer repeats once the queue is down to one, so "answer 503 to everything"
 * is one registration.
 */
final class RoutedHandler
{
    /** @var array<string, list<Response|\Throwable|callable(RequestInterface): Response>> */
    private array $routes = [];

    /** @var list<RequestInterface> */
    public array $requests = [];

    /**
     * Answer `METHOD path` (path only, no query) with `$answers`, in order; the last one
     * repeats.
     *
     * @param Response|\Throwable|callable(RequestInterface): Response ...$answers
     */
    public function on(string $method, string $path, Response|\Throwable|callable ...$answers): self
    {
        $this->routes[strtoupper($method) . ' ' . $path] = array_values($answers);

        return $this;
    }

    /** @param array<string,mixed> $options */
    public function __invoke(RequestInterface $request, array $options): PromiseInterface
    {
        $this->requests[] = $request;
        $key = strtoupper($request->getMethod()) . ' ' . $request->getUri()->getPath();
        if (!isset($this->routes[$key]) || $this->routes[$key] === []) {
            return Create::rejectionFor(new \RuntimeException('no route for ' . $key));
        }
        $answer = count($this->routes[$key]) > 1 ? array_shift($this->routes[$key]) : $this->routes[$key][0];
        if ($answer instanceof \Throwable) {
            return Create::rejectionFor($answer);
        }
        if (is_callable($answer)) {
            $answer = $answer($request);
        }

        return Create::promiseFor($answer);
    }

    /**
     * The requests whose method and path match.
     *
     * @return list<RequestInterface>
     */
    public function sent(string $method, string $path): array
    {
        return array_values(array_filter(
            $this->requests,
            static fn (RequestInterface $r): bool => strtoupper($r->getMethod()) === strtoupper($method)
                && $r->getUri()->getPath() === $path,
        ));
    }

    /**
     * A JSON response.
     *
     * @param array<mixed> $body
     * @param array<string,string> $headers
     */
    public static function json(int $status, array $body, array $headers = []): Response
    {
        return new Response($status, $headers + ['Content-Type' => 'application/json'], (string) json_encode($body, JSON_UNESCAPED_SLASHES));
    }
}
