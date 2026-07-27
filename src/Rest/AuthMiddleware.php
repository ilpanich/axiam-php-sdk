<?php

declare(strict_types=1);

namespace Axiam\Sdk\Rest;

use Axiam\Sdk\Session;
use Psr\Http\Message\RequestInterface;

/**
 * `HandlerStack` middleware: injects `Authorization` (current access token) and
 * `X-Tenant-ID` on EVERY outgoing request, and `X-CSRF-Token` (captured from a prior
 * response, {@see Session::csrfToken()}) on state-changing requests
 * (CONTRACT.md §3 non-browser CSRF, §5 tenant context contract).
 *
 * Registered on the `HandlerStack` closer to the base handler than
 * {@see RefreshMiddleware}, so a retried request (after a single-flight refresh) is
 * re-decorated with the FRESH access token / CSRF value picked up from the shared
 * {@see Session} — never the stale headers from the original 401'd attempt.
 *
 * CONTRACT.md §12.1 note 3 / §12.3 rule 2: a request to `/oauth2/*` never gets the
 * `Authorization` header, regardless of whether {@see Session::accessToken()} is
 * currently returning a cookie-sourced session token or a
 * `login_client_credentials`-adopted one (§12.1's opt-in credential-adoption MAY) —
 * those endpoints authenticate the CLIENT through the form body
 * (`client_secret_post`, never `Authorization: Basic` or `Bearer`).
 */
final class AuthMiddleware
{
    /** @var list<string> HTTP methods §3 requires the CSRF header on. */
    private const STATE_CHANGING_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

    /** @param Session $session Session supplying the tenant, bearer token and CSRF token. */
    public function __construct(private readonly Session $session)
    {
    }

    /**
     * Wraps the next Guzzle handler, decorating same-origin requests with the tenant header,
     * bearer token and — on state-changing methods (§3) — the `X-CSRF-Token` header.
     *
     * Cross-host requests (and cross-host redirects) are deliberately left undecorated so the
     * credentials never leak to a third-party URL.
     *
     * @param callable $handler Next handler in the Guzzle stack.
     *
     * @return callable Decorated handler.
     */
    public function __invoke(callable $handler): callable
    {
        $baseHost = parse_url($this->session->baseUrl(), PHP_URL_HOST);

        return function (RequestInterface $request, array $options) use ($handler, $baseHost) {
            // Host-isolation (3A, defense in depth): only same-origin requests
            // are decorated, so the tenant id, bearer token, and CSRF token
            // never leak to an absolute third-party URL or a followed cross-host
            // redirect. A request whose host differs from our base origin is
            // forwarded untouched. Mirrors the Python SDK's _prepare_request guard.
            $requestHost = $request->getUri()->getHost();
            if (\is_string($baseHost) && $requestHost !== '' && strcasecmp($requestHost, $baseHost) !== 0) {
                return $handler($request, $options);
            }

            $request = $request->withHeader('X-Tenant-ID', $this->session->tenant());

            // CONTRACT.md §12.1 note 3 / §12.3 rule 2: never attach a bearer credential
            // (cookie-sourced OR client-credentials-adopted) to an /oauth2/* request.
            $isOAuth2Path = str_starts_with($request->getUri()->getPath(), '/oauth2/');

            $accessToken = $isOAuth2Path ? null : $this->session->accessToken();
            if ($accessToken !== null) {
                $request = $request->withHeader('Authorization', 'Bearer ' . $accessToken);
            }

            if (\in_array(strtoupper($request->getMethod()), self::STATE_CHANGING_METHODS, true)) {
                $csrfToken = $this->session->csrfToken();
                if ($csrfToken !== null) {
                    $request = $request->withHeader('X-CSRF-Token', $csrfToken);
                }
            }

            return $handler($request, $options);
        };
    }
}
