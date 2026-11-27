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
    /**
     * Guard-slot kind for the §1 cookie-session refresh path
     * ({@see self::refreshIfNeeded()}) — the default `refreshGuard()` kind.
     */
    public const REFRESH_KIND_SESSION = 'session';

    /**
     * Guard-slot kind for the §12 `oidc_refresh` OAuth2 token-endpoint path
     * (CONTRACT.md §9 rule 5 / F-06). Used by {@see \Axiam\Sdk\Oidc\OidcClient::oidcRefresh()}
     * together with a per-refresh-token key, so a second concurrent caller presenting the
     * SAME token shares the one wire call's outcome instead of replaying an already-consumed
     * (single-use, rotating) token, while a caller with a different token has its own flight.
     */
    public const REFRESH_KIND_OIDC = 'oidc';

    /**
     * The §9 single-flight slots, one per flight identity: the §1 cookie-session refresh owns
     * the slot named by its kind, and each `oidc_refresh` flight owns a slot named by its kind
     * plus the SHA-256 digest of (tenant, refresh token) it was started for (CONTRACT.md §9,
     * per-token keying) — the raw token is never a key. A slot is created when its flight is
     * published and removed when it is vacated (see {@see self::refreshGuard()}'s `onClear`),
     * so the map never grows beyond the flights actually in the air.
     *
     * @var array<string, array{promise: PromiseInterface, kind: string}>
     */
    private array $refreshSlots = [];

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
     * CONTRACT.md §5.2 rule 1 (contract 1.51): the tenant this client currently ACTS ON,
     * sent as `X-Axiam-Tenant` by {@see \Axiam\Sdk\Rest\AuthMiddleware} on every
     * `/api/v1` request while set, and on NO request while `null` (the default — byte-
     * for-byte what every request sent before 1.51). Distinct from `$tenant` above,
     * which is the constructor's OWN tenant slug and is always sent as `X-Tenant-ID`
     * (§5 rule 2) regardless of this value. Deliberately shared, mutable session state
     * rather than per-handle: PHP's request lifecycle has no concurrent tasks sharing
     * one client the way a long-lived Rust/Go process does, so
     * {@see \Axiam\Sdk\AxiamClient::actingTenant()}/`clearActingTenant()` mutate this in
     * place and return `$this`, a deliberate simplification from the reference
     * implementation's per-handle isolation, recorded in the README/CHANGELOG.
     */
    private ?string $actingTenant = null;

    /**
     * CONTRACT.md §5.2/§5.2.3 — what the last completed login reported about the
     * principal's reach, or `null` when this client holds no such result (a service
     * account, an injected token, or a session completed without a `LoginUserInfo` —
     * OPAQUE, SSO and WebAuthn AUTHENTICATION reset it; password login, verify-MFA,
     * OPAQUE's finish and the MFA/WebAuthn SETUP completions set it, since the server
     * sends a user object on all five). `null` on purpose rather than a defaulted
     * `false`: "the server did not say" must not gate
     * {@see \Axiam\Sdk\AxiamClient::actingTenant()} as though the server had said
     * "not organization-level" — that would refuse a caller the server would admit.
     *
     * @var array{organizationLevel: bool, reachableTenantIds: ?list<string>}|null
     */
    private ?array $principalScope = null;

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
     * Clears the adopted bearer credential (CONTRACT.md §6.1 rule 11 / C-12 N4.4:
     * "logout clears it"). Called only by {@see \Axiam\Sdk\AxiamClient::logout()},
     * after a successful server-side logout — mirroring how the cookie jar, CSRF token
     * and principal scope are also cleared only then, never on a refused call.
     *
     * Without this, a device token or adopted client-credentials token from EARLIER in
     * this client's life — merely SHADOWED, never cleared, by a subsequent
     * `login()`'s cookie session, since {@see self::accessToken()} always prefers a
     * cookie-sourced token when one is present — resurfaces once `logout()` clears that
     * cookie again: a client that believes it logged itself out would still be
     * authenticated as the stale device/service credential.
     */
    public function clearBearerCredential(): void
    {
        $this->adoptedAccessToken = null;
    }

    /**
     * The tenant this client currently acts on (CONTRACT.md §5.2 rule 1), or `null`
     * when it acts on its own tenant — the state {@see \Axiam\Sdk\Rest\AuthMiddleware}
     * reads to decide whether to send `X-Axiam-Tenant` at all.
     */
    public function actingTenant(): ?string
    {
        return $this->actingTenant;
    }

    /**
     * Sets, or clears (`null`), the acting tenant (CONTRACT.md §5.2 rule 1). The caller
     * ({@see \Axiam\Sdk\AxiamClient::actingTenant()}/`clearActingTenant()`) is
     * responsible for validating `$tenantId` as a UUID first — this setter trusts it.
     */
    public function setActingTenant(?string $tenantId): void
    {
        $this->actingTenant = $tenantId;
    }

    /**
     * What the last completed login reported about the principal's reach (CONTRACT.md
     * §5.2/§5.2.3), or `null` when this client holds no such result. See
     * {@see self::$principalScope}'s own doc for which sessions set/reset it.
     *
     * @return array{organizationLevel: bool, reachableTenantIds: ?list<string>}|null
     */
    public function principalScope(): ?array
    {
        return $this->principalScope;
    }

    /**
     * Records what a just-completed login/verify-MFA/OPAQUE-finish/setup-completion
     * reported about the principal's reach (§5.2/§5.2.3).
     *
     * @param list<string>|null $reachableTenantIds
     */
    public function recordPrincipalScope(bool $organizationLevel, ?array $reachableTenantIds): void
    {
        $this->principalScope = ['organizationLevel' => $organizationLevel, 'reachableTenantIds' => $reachableTenantIds];
    }

    /**
     * Resets the principal scope to "unknown" (§5.2 rule 1): a session that just
     * completed WITHOUT reporting a `LoginUserInfo` — WebAuthn authentication, SSO, a
     * device login, or an ordinary logout — must not let
     * {@see \Axiam\Sdk\AxiamClient::actingTenant()} keep gating on a PREVIOUS
     * principal's reach.
     */
    public function resetPrincipalScope(): void
    {
        $this->principalScope = null;
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
     * Whether the credential {@see self::accessToken()} would currently return can be
     * refreshed through the §9 `/api/v1/auth/refresh` guard (CONTRACT.md §6.1 rule 11,
     * C-12 N4.5): true exactly when a cookie-sourced session exists — a real
     * `login()`/`verifyMfa()`/OPAQUE/MFA-setup/WebAuthn-setup/SSO session has a
     * server-stored refresh token behind its `axiam_access` cookie. An ADOPTED bearer
     * credential — {@see \Axiam\Sdk\AxiamClient::authenticateDevice()}'s device token
     * (§6.1 rule 6: no refresh token is ever issued for it), or a `client_credentials`/
     * device-grant token adopted via {@see self::adoptBearerCredential()} (RFC 6749
     * §4.4.3: `client_credentials` issues no `refresh_token` either) — has none, and
     * MUST NEVER be refreshed, on either transport. Mirrors {@see self::accessToken()}'s
     * own cookie-first precedence exactly, so this is true whenever THAT method would
     * hand back a cookie-sourced token and false whenever it would fall back to the
     * adopted one (or return `null`).
     *
     * Consulted by {@see \Axiam\Sdk\Rest\RefreshMiddleware} (REST, before ever calling
     * {@see self::refreshIfNeeded()}) and {@see \Axiam\Sdk\AuthzDispatcher} (gRPC,
     * before ever calling its own `$refreshAccessor`) — never by this class itself,
     * which stays agnostic of which credential is "current" beyond what
     * {@see self::accessToken()} already resolves.
     */
    public function canRefresh(): bool
    {
        return $this->cookieValue('axiam_access') !== null;
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
            kind: self::REFRESH_KIND_SESSION,
        )['promise'];
    }

    /**
     * The generic single-flight primitive behind {@see self::refreshIfNeeded()}
     * (CONTRACT.md §9) — and, additively, behind `oidc_refresh`'s own single-flight
     * requirement (§12.1: "`oidc_refresh` MUST be governed by a §9-conformant
     * single-flight guard").
     *
     * Flights are identified by `$kind` plus the optional `$key`. The §1 cookie-session
     * refresh passes no key (its token is the session's own, so one slot per session);
     * `oidc_refresh` passes a key derived from the refresh token it was called with, so
     * only callers presenting the SAME token share a flight (§9, per-token keying).
     *
     * If no refresh is currently in flight for that identity, invokes `$startRefresh`
     * (which must return the wire-call `PromiseInterface`) as THIS refresh and publishes
     * it into its own slot. If one is already in flight, `$startRefresh` is NOT invoked
     * and the existing promise is returned instead.
     *
     * **Result sharing (CONTRACT.md §9 rule 2, F-06).** `ran === true` means this call
     * started the refresh — its own outcome IS the shared outcome, and only it may
     * `wait()` on the promise. `ran === false` means the guard is busy with a flight of
     * the SAME identity: the returned `promise` resolves to that one leader's exact
     * outcome, and the caller MUST await it with {@see RefreshGuard::join()}, **never**
     * with `PromiseInterface::wait()` (which would consume the leader's wait function and
     * destroy its in-flight refresh, F-06), and reuse it rather than issuing its own wire
     * call: refresh tokens are single-use with rotation, so a second call would replay an
     * already-consumed token. A caller with a different `$key` never lands here — it gets
     * its own slot and its own wire call (rule 6d: never another grant's outcome).
     *
     * @param \Closure(): PromiseInterface $startRefresh Produces the wire-call promise
     *        for THIS refresh attempt. Invoked only when the identity's slot is free.
     * @param (\Closure(mixed): mixed)|null $onSuccess Runs after the shared promise
     *        resolves successfully, before the settled value is handed back (e.g. CSRF
     *        capture) — same contract as {@see RefreshGuard::settle()}'s own parameter.
     * @param string $kind One of {@see self::REFRESH_KIND_SESSION} /
     *        {@see self::REFRESH_KIND_OIDC} (or a future operation-specific kind).
     * @param string|null $key Flight discriminator within the kind — a digest, never a raw
     *        secret (see {@see \Axiam\Sdk\Oidc\OidcClient::refreshFlightKey()}); `null`
     *        for a kind with a single flight per session.
     *
     * @return array{ran: bool, promise: PromiseInterface, kind: string} `ran` is
     *         `true` only when `$startRefresh` was actually invoked by THIS call;
     *         `kind` is the kind that owns the returned `promise`.
     */
    public function refreshGuard(
        \Closure $startRefresh,
        ?\Closure $onSuccess = null,
        string $kind = self::REFRESH_KIND_SESSION,
        ?string $key = null,
    ): array {
        $slotId = $key === null ? $kind : $kind . ':' . $key;

        if (isset($this->refreshSlots[$slotId])) {
            $slot = $this->refreshSlots[$slotId];

            return ['ran' => false, 'promise' => $slot['promise'], 'kind' => $slot['kind']];
        }

        // Check-and-store completes synchronously here — nothing above this point
        // awaits or yields, so no concurrent caller can observe a free $slotId again
        // until this whole method returns. This holds whether $startRefresh() below
        // returns a real in-flight HTTP promise or an immediately-rejected one —
        // either way exactly ONE PromiseInterface is stored and shared per slot.
        $refreshCall = $startRefresh();

        $promise = RefreshGuard::settle(
            $refreshCall,
            onClear: function () use ($slotId, &$promise): void {
                // Identity-checked vacate (§9 rule 6): only the flight that owns the slot
                // removes it, never a different, still-live attempt that took it since.
                if (isset($this->refreshSlots[$slotId]) && $this->refreshSlots[$slotId]['promise'] === $promise) {
                    unset($this->refreshSlots[$slotId]);
                }
            },
            onSuccess: $onSuccess,
        );
        $this->refreshSlots[$slotId] = ['promise' => $promise, 'kind' => $kind];

        return ['ran' => true, 'promise' => $promise, 'kind' => $kind];
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
