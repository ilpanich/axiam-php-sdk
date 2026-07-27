<?php

declare(strict_types=1);

namespace Axiam\Sdk;

use Axiam\Sdk\Auth\RefreshGuard;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\Sensitive;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Per-`AxiamClient` session state (CONTRACT.md §3/§4/§5/§9): owns the shared Guzzle
 * `CookieJar` (§4), captures/exposes the non-browser CSRF token (§3), and is the
 * single-flight home for the shared refresh `Promise` (§9, D-06).
 *
 * `tenant` is a required constructor parameter with no nullable default (D-13) — there
 * is no default-tenant fallback anywhere in this class or in any of its callers.
 *
 * `refreshIfNeeded()` returns the SAME `PromiseInterface` to every concurrent caller
 * until it settles. The check-and-store below (the `null` check immediately followed
 * by the assignment) executes synchronously — nothing in between calls `->wait()` or
 * yields — so it is safe without a mutex even under N concurrent async callers sharing
 * one `Session` instance (D-06's "fiber-safe by construction" claim; PHP Fibers are
 * cooperative/non-preemptive, and Guzzle's own promise resolution never interleaves
 * mid-statement).
 *
 * The `$http` client passed in is used directly for the refresh POST. In production
 * wiring (a later plan assembles `AxiamClient`), that client is expected to be
 * constructed WITHOUT `RefreshMiddleware` attached, so a 401 response to the refresh
 * call itself can never recursively re-enter the single-flight guard; this plan does
 * not need to solve that wiring, only provide the guard itself.
 */
final class Session
{
    private ?PromiseInterface $refreshPromise = null;

    private ?string $csrfToken = null;

    private readonly CookieJar $cookieJar;

    /**
     * CONTRACT.md §12.1 "`login_client_credentials` as a credential source" (a MAY):
     * the access token adopted via {@see self::adoptBearerCredential()}, held behind
     * {@see Sensitive} and consulted by {@see self::accessToken()} ONLY when the shared
     * cookie jar carries none — a real `login()`/`verifyMfa()` session (cookie-sourced)
     * always takes precedence. Never written to a public property, the cookie jar, or
     * sent to `/oauth2/*` ({@see \Axiam\Sdk\Rest\AuthMiddleware} skips the
     * `Authorization` header entirely on that path, §12.3 rule 2).
     */
    private ?Sensitive $adoptedAccessToken = null;

    /**
     * @param string         $baseUrl   AXIAM server base URL (HTTPS; `http://` is rejected
     *                                  except on loopback).
     * @param string         $tenant    Tenant slug every request is scoped to.
     * @param Client         $http      Guzzle client carrying this session's middleware stack.
     * @param CookieJar|null $cookieJar Persistent cookie store (CONTRACT.md §4). Defaults to a
     *                                  fresh in-memory jar — REQUIRED, because AXIAM delivers the
     *                                  access and refresh tokens as `httpOnly` cookies, so a client
     *                                  that does not persist them fails every request after login.
     */
    public function __construct(
        private readonly string $baseUrl,
        private readonly string $tenant,
        private readonly Client $http,
        ?CookieJar $cookieJar = null,
    ) {
        $this->cookieJar = $cookieJar ?? new CookieJar();
    }

    /** AXIAM server base URL this session is bound to. */
    public function baseUrl(): string
    {
        return $this->baseUrl;
    }

    /** Tenant slug every request in this session is scoped to. */
    public function tenant(): string
    {
        return $this->tenant;
    }

    /** §4: the single cookie jar every REST-facing Guzzle client MUST share. */
    public function cookieJar(): CookieJar
    {
        return $this->cookieJar;
    }

    /** §3 non-browser CSRF: the most recently captured `X-CSRF-Token` response header. */
    public function csrfToken(): ?string
    {
        return $this->csrfToken;
    }

    /**
     * Public seam for {@see \Axiam\Sdk\Oidc\OidcClient::ssoComplete()} (CONTRACT.md
     * §12.1 note 6): `ssoComplete` establishes the session as `Set-Cookie` rather than
     * a response body, but the server ALSO freshly sets `X-CSRF-Token` on that same
     * response (exactly as `login()`'s response does), so this wraps the same private
     * capture logic {@see self::refreshIfNeeded()} already uses.
     */
    public function captureCsrfTokenFromResponse(ResponseInterface $response): void
    {
        $this->captureCsrfToken($response);
    }

    /**
     * CONTRACT.md §12.1 "`login_client_credentials` as a credential source" (a MAY):
     * adopt `$accessToken` as this session's bearer credential for subsequent
     * same-origin REST calls (never `/oauth2/*` — {@see \Axiam\Sdk\Rest\AuthMiddleware}
     * excludes that path unconditionally). A cookie-sourced access token from a real
     * `login()`/`verifyMfa()` session always takes precedence over an adopted one — see
     * {@see self::accessToken()}.
     */
    public function adoptBearerCredential(Sensitive $accessToken): void
    {
        $this->adoptedAccessToken = $accessToken;
    }

    /**
     * Clears the captured CSRF token — called by {@see \Axiam\Sdk\AxiamClient::logout()} so a
     * logged-out session never echoes a stale `X-CSRF-Token` on a subsequent (re-authenticated)
     * request. Purely additive: does not change {@see self::csrfToken()}'s or
     * {@see self::refreshIfNeeded()}'s existing behavior in any other way.
     */
    public function resetCsrf(): void
    {
        $this->csrfToken = null;
    }

    /**
     * The current access token, read live from the shared cookie jar's `axiam_access`
     * entry rather than cached separately — avoids a second, potentially-stale, copy
     * of the token (mirrors the Java SDK's `SessionState::cachedAccessToken()` and
     * the Go SDK's `cookieValue()` helper).
     */
    public function accessToken(): ?string
    {
        $cookieToken = $this->cookieValue('axiam_access');
        if ($cookieToken !== null) {
            return $cookieToken;
        }

        // §12.1 "login_client_credentials as a credential source" fallback — only
        // consulted when there is no real cookie-sourced session (see class doc on
        // self::$adoptedAccessToken).
        return $this->adoptedAccessToken?->reveal();
    }

    private function cookieValue(string $name): ?string
    {
        foreach ($this->cookieJar as $cookie) {
            if ($cookie->getName() === $name) {
                return $cookie->getValue();
            }
        }

        return null;
    }

    /**
     * Returns the SAME `PromiseInterface` to every caller until it resolves (SC#2,
     * D-06). On success: captures the `X-CSRF-Token` response header, then clears the
     * stored promise. On failure: clears the stored promise and rejects with
     * `AuthError` — no retry loop (§9.3). Clear-on-both-paths bookkeeping and the
     * failure-to-`AuthError` translation are factored into {@see RefreshGuard::settle()}
     * so REST and (later) gRPC never re-implement — or drift on — that one mechanism;
     * {@see RefreshGuard::settle()}'s `$onClear` closure below is invoked on EITHER
     * outcome, never on both, never on neither.
     */
    public function refreshIfNeeded(): PromiseInterface
    {
        return $this->refreshGuard(
            fn (): PromiseInterface => $this->buildRefreshCall(),
            onSuccess: function (mixed $response): mixed {
                \assert($response instanceof ResponseInterface);
                $this->captureCsrfToken($response);
                return $response;
            },
        )['promise'];
    }

    /**
     * The generic single-flight primitive behind {@see self::refreshIfNeeded()}
     * (CONTRACT.md §9) — and, additively, behind `oidc_refresh`'s own single-flight
     * requirement (§12.1: "`oidc_refresh` MUST run under the §9 single-flight refresh
     * guard"). Both share the SAME `$refreshPromise` slot, so a cookie-session refresh
     * and an `oidcRefresh()` call can never race each other independently — whichever
     * gets here first "owns" the slot until it settles.
     *
     * If no refresh is currently in flight, invokes `$startRefresh` (which must return
     * the wire-call `PromiseInterface`) as THIS refresh, publishing it into the shared
     * slot. If a refresh (of EITHER kind) is already in flight, `$startRefresh` is NOT
     * invoked at all and the existing promise is returned instead — the caller tells
     * the two cases apart via the returned `ran` flag, since the existing promise's
     * resolved value may not match what `$startRefresh` would have produced (e.g. a
     * cookie-session refresh's PSR-7 `ResponseInterface` when the caller wanted an
     * OAuth2 token array).
     *
     * @param \Closure(): PromiseInterface $startRefresh Produces the wire-call promise
     *        for THIS refresh attempt. Invoked only when the guard is free.
     * @param (\Closure(mixed): mixed)|null $onSuccess Runs after the shared promise
     *        resolves successfully, before the settled value is handed back (e.g. CSRF
     *        capture) — same contract as {@see RefreshGuard::settle()}'s own parameter.
     *
     * @return array{ran: bool, promise: PromiseInterface} `ran` is `true` only when
     *         `$startRefresh` was actually invoked by THIS call.
     */
    public function refreshGuard(\Closure $startRefresh, ?\Closure $onSuccess = null): array
    {
        if ($this->refreshPromise !== null) {
            return ['ran' => false, 'promise' => $this->refreshPromise];
        }

        // Check-and-store completes synchronously here — nothing above this point
        // awaits or yields, so no concurrent caller can observe a null
        // $refreshPromise again until this whole method returns. This holds whether
        // $startRefresh() below returns a real in-flight HTTP promise or an
        // immediately-rejected one — either way exactly ONE PromiseInterface is stored
        // and shared.
        $refreshCall = $startRefresh();

        $this->refreshPromise = RefreshGuard::settle(
            $refreshCall,
            onClear: function (): void {
                $this->refreshPromise = null;
            },
            onSuccess: $onSuccess,
        );

        return ['ran' => true, 'promise' => $this->refreshPromise];
    }

    /**
     * Builds the `/api/v1/auth/refresh` request per `openapi.json`'s
     * `RefreshRequest` schema (`{tenant_id, org_id}`, both UUIDs — there is no
     * `tenant` slug field on this endpoint). Both identifiers are resolved from the
     * CURRENT access token's unverified claims (mirrors the C# sibling's
     * `AxiamClient::DoHttpRefreshAsync`/`DecodeUnverifiedClaims`): this is a base64url
     * decode of the JWT payload segment only — the signature is never checked here,
     * since the token was already trusted at login/verify time and this call only
     * reads the SDK's own claims to build the wire body.
     *
     * When no access token is available, or `tenant_id`/`org_id` cannot be resolved
     * from it, an immediately-rejected promise carrying an {@see AuthError} is
     * returned instead of throwing synchronously — so this failure still flows
     * through the SAME single-flight `RefreshGuard::settle()` clear-on-both-paths
     * bookkeeping as a real HTTP failure, and every concurrent caller sharing this
     * `Session` observes the identical rejection (SC#2's single-flight guarantee is
     * not weakened by this validation step).
     */
    private function buildRefreshCall(): PromiseInterface
    {
        $accessToken = $this->accessToken();
        if ($accessToken === null) {
            return Create::rejectionFor(
                new AuthError('no access token to refresh — login must succeed before refresh'),
            );
        }

        $claims = $this->decodeUnverifiedClaims($accessToken);

        $tenantId = is_array($claims) ? ($claims['tenant_id'] ?? null) : null;
        if (!is_string($tenantId) || $tenantId === '') {
            return Create::rejectionFor(
                new AuthError(
                    'tenant_id could not be resolved from the current access token; login must succeed before refresh',
                ),
            );
        }

        $orgId = is_array($claims) ? ($claims['org_id'] ?? null) : null;
        if (!is_string($orgId) || $orgId === '') {
            return Create::rejectionFor(
                new AuthError(
                    'org_id could not be resolved from the current access token; login must succeed before refresh',
                ),
            );
        }

        return $this->http->postAsync('/api/v1/auth/refresh', [
            'json' => ['tenant_id' => $tenantId, 'org_id' => $orgId],
        ]);
    }

    /**
     * Unverified decode of a JWT's payload segment (base64url + JSON, NO signature
     * check) — used ONLY to resolve `tenant_id`/`org_id` for the refresh request body
     * above. Never used for an authorization decision (that is exclusively
     * {@see \Axiam\Sdk\Auth\JwksVerifier::verify()}'s job); mirrors
     * `AxiamClient::currentClaimsOrNull()`'s identical decode logic, kept local here
     * so `Session` does not depend on `AxiamClient`.
     *
     * @return array<string,mixed>|null
     */
    private function decodeUnverifiedClaims(string $jwt): ?array
    {
        $parts = explode('.', $jwt);
        if (\count($parts) !== 3) {
            return null;
        }

        $decoded = base64_decode(strtr($parts[1], '-_', '+/'), true);
        if ($decoded === false) {
            return null;
        }

        try {
            $claims = json_decode($decoded, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return is_array($claims) ? $claims : null;
    }

    private function captureCsrfToken(ResponseInterface $response): void
    {
        // §3 non-browser CSRF: capture the X-CSRF-Token response header, echoed later
        // on mutating requests by AuthMiddleware.
        $token = $response->getHeaderLine('X-CSRF-Token');
        if ($token !== '') {
            $this->csrfToken = $token;
        }
    }
}
