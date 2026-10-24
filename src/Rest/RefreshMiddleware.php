<?php

declare(strict_types=1);

namespace Axiam\Sdk\Rest;

use Axiam\Sdk\Session;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * `HandlerStack` middleware: on a `401` response, triggers the session's single-flight
 * refresh (CONTRACT.md §9, D-06, SC#2) and retries the ORIGINAL request exactly once
 * via the inner `$handler` — never a loop. All concurrent 401-triggering requests on
 * one {@see Session} share the SAME refresh `PromiseInterface`
 * ({@see Session::refreshIfNeeded()}), so N concurrent expired-token requests still
 * result in exactly one `/api/v1/auth/refresh` call.
 *
 * Pushed BEFORE {@see AuthMiddleware} (`AxiamClient::$authzStack`). `HandlerStack` runs the
 * first pushed middleware first on a request, so a request runs Guzzle's `http_errors`,
 * redirect, cookie and body middleware, then this middleware, then `AuthMiddleware`, then the
 * base handler. The retry — invoked via the `$handler` captured here, which is everything
 * INSIDE this middleware, i.e. `AuthMiddleware` + the base handler — passes through
 * `AuthMiddleware` again, so it carries the refreshed bearer token and `X-CSRF-Token`; the
 * `Cookie` header was set by the cookie middleware outside this one and is rebuilt here from the
 * request's own `cookies` jar. It never re-enters this middleware's own 401 check a second time (retry-exactly-once by
 * construction, not by an explicit retry counter).
 */
final class RefreshMiddleware
{
    /** @param Session $session Session whose access token is refreshed on a 401. */
    public function __construct(private readonly Session $session)
    {
    }

    /**
     * Wraps the next Guzzle handler so a 401 triggers a single-flight token refresh and one
     * replay of the original request.
     *
     * The replay is issued through the NEXT handler rather than the top of the stack, so it
     * cannot re-enter this middleware's 401 check — retry-exactly-once by construction, with no
     * explicit retry counter and no infinite refresh loop.
     *
     * @param callable $handler Next handler in the Guzzle stack.
     *
     * @return callable Decorated handler.
     */
    public function __invoke(callable $handler): callable
    {
        return function (RequestInterface $request, array $options) use ($handler) {
            return $handler($request, $options)->then(
                function (ResponseInterface $response) use ($request, $options, $handler) {
                    if ($response->getStatusCode() !== 401) {
                        return $response;
                    }

                    // CONTRACT.md §6.1 rule 11 / C-12 N4.5: a device credential, or an
                    // adopted client-credentials/device-grant token, has no refresh
                    // token behind it and must NEVER enter the §9 guard — not even to
                    // fail through it. Returning the untouched 401 here (rather than
                    // calling refreshIfNeeded()) means the caller's ordinary
                    // ErrorMapper-based mapping runs exactly as it would with this
                    // middleware absent, instead of the guard's own synthesized
                    // "token refresh failed" AuthError.
                    if (!$this->session->canRefresh()) {
                        return $response;
                    }

                    // Single-flight: every concurrent 401-triggering request calls
                    // refreshIfNeeded() and is handed back the SAME Promise (D-06) —
                    // the retry below fires exactly once per request, no loop.
                    return $this->session->refreshIfNeeded()->then(
                        // The jar now holds the rotated cookies; the stale `Cookie` header was
                        // set by the cookie middleware, which sits outside this one and does not
                        // run again for the replay.
                        function () use ($handler, $request, $options): \GuzzleHttp\Promise\PromiseInterface {
                            // The jar the request was sent with (the `cookies` option), not
                            // necessarily the session's: a request that opted out (`false`) or
                            // brought its own jar is replayed the same way (C164-23).
                            $replay = $request->withoutHeader('Cookie');
                            $jar = $options['cookies'] ?? null;
                            if ($jar instanceof \GuzzleHttp\Cookie\CookieJarInterface) {
                                $replay = $jar->withCookieHeader($replay);
                            }

                            return $handler($replay, $options);
                        },
                    );
                },
            );
        };
    }
}
