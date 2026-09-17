<?php

declare(strict_types=1);

namespace Axiam\Sdk\Laravel;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Mcp\McpGuardOptions;
use Closure;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Laravel authentication middleware (D-02, CONTRACT.md §10): extracts the bearer/cookie
 * token, verifies it via {@see AxiamClient::verifyLocally()} — the no-fallback seam
 * mandated by §10.1 rule 8 — and populates the `axiam_user` request attribute with
 * `user_id`/`tenant_id`/`roles` on success. Returns a standardized 401 JSON error body on
 * any failure (missing token, invalid signature, expired token). Never duplicates
 * JWKS-verify logic itself (D-02 prohibition) — every security-critical decision is made
 * by {@see AxiamClient}.
 *
 * The decision is always about the CALLER's credential. This middleware deliberately does
 * not use {@see AxiamClient::verifyLocallyOrFallback()}: its reactive-refresh fallback
 * verifies *this application's own* session, so a request whose token fails verification
 * would be admitted under the app's own principal (SEC-085).
 *
 * Type-hinted against `Symfony\Component\HttpFoundation\Request` rather than
 * `Illuminate\Http\Request`: a real `Illuminate\Http\Request` instance IS a
 * `Symfony\Component\HttpFoundation\Request` (it directly extends it, adding only
 * Laravel-specific convenience methods this class does not need), so Laravel's own HTTP
 * kernel/pipeline can call `handle($request, $next)` with its real request object
 * unchanged. This keeps the class's own dependency footprint to a package every Laravel
 * installation already ships transitively (via `illuminate/http`), without requiring a
 * new `illuminate/http` dev/runtime dependency just to type-hint the parameter (D-01:
 * illuminate/* stays dev-only, and only the packages actually needed are declared).
 *
 * CSRF (cookie double-submit, CONTRACT.md §3): when the credential was sourced from the
 * `axiam_access` COOKIE (not the `Authorization` header) and the request method is
 * state-changing (anything other than GET/HEAD/OPTIONS), this middleware additionally
 * requires the `X-CSRF-Token` request header to be present and equal (constant-time) to
 * the `axiam_csrf` cookie value, rejecting with 403 on mismatch/absence. Bearer-header
 * requests are CSRF-immune by construction — a cross-site attacker cannot set arbitrary
 * request headers — but a cookie automatically attached by the browser is not, and in
 * any same-site deployment where `axiam_access` reaches this app, the non-httpOnly
 * `axiam_csrf` cookie does too. This mirrors, locally, the same double-submit check the
 * AXIAM server performs on its own endpoints (§3).
 *
 * MCP resource-server helpers (CONTRACT.md §28, opt-in): supplying `$resourceMetadataUrl`
 * turns on the RFC 6750 `WWW-Authenticate` challenge on every 401 this middleware emits,
 * and exempts the metadata document's own path from authentication — see
 * {@see \Axiam\Sdk\Mcp\McpGuardOptions} for the precomputation and
 * `Route::serveProtectedResourceMetadata()` (registered by {@see AxiamServiceProvider})
 * for serving the document itself. With `$resourceMetadataUrl` unset (the default), this
 * middleware behaves byte-for-byte as it did before §28 existed — no header on any
 * response, no status changed, no body changed, no path exempted.
 */
final class AxiamMiddleware
{
    private const CSRF_COOKIE_NAME = 'axiam_csrf';
    private const CSRF_HEADER_NAME = 'X-CSRF-Token';

    /** @var list<string> */
    private const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];

    private readonly ?McpGuardOptions $mcp;

    /**
     * @param AxiamClient $client Client used to verify the presented token against the cached JWKS.
     * @param string      $tenant Tenant slug the verified token's claim must match (cross-tenant
     *                            control: a JWKS is organization-wide, so a valid signature alone
     *                            never implies tenant authorization).
     * @param string|null $resourceMetadataUrl CONTRACT.md §28.5's opt-in option: the URL
     *                            of this resource server's RFC 9728 metadata document
     *                            (the `metadataUrl` a prior
     *                            `Mcp::protectedResourceMetadata(...)` call returned).
     *                            `null` (the default) leaves this middleware's behaviour
     *                            byte-for-byte unchanged from before §28 existed. Setting
     *                            it REQUIRES `$client` to have been constructed with
     *                            `expectedAudience` — refused at construction, naming
     *                            both options, when it was not (§28.5 rule 2).
     */
    public function __construct(
        private readonly AxiamClient $client,
        private readonly string $tenant,
        ?string $resourceMetadataUrl = null,
    ) {
        $this->mcp = $resourceMetadataUrl !== null
            ? McpGuardOptions::build(self::class, $resourceMetadataUrl, $client->expectedAudience())
            : null;
    }

    /**
     * This middleware's own CONTRACT.md §28.5 configuration, or `null` when
     * `$resourceMetadataUrl` was not supplied at construction.
     *
     * Public so `Route::serveProtectedResourceMetadata()` (registered by
     * {@see AxiamServiceProvider}) can cross-check that the document it is about to
     * publish agrees with THIS middleware's own configuration (§28.5 rule 3) when both
     * are given to it — never required, since the two may legitimately be configured in
     * separate processes, in which case nothing can be cross-checked and nothing is.
     */
    public function mcpGuardOptions(): ?McpGuardOptions
    {
        return $this->mcp;
    }

    /**
     * The `AxiamClient` this middleware verifies against — the same accessor
     * {@see \Axiam\Sdk\Mcp\Mcp::checkGuardAgreement()} reads `expectedAudience()` from
     * for the §28.5 rule 3 cross-check.
     */
    public function client(): AxiamClient
    {
        return $this->client;
    }

    /**
     * Authenticates the inbound request and, for cookie-authenticated writes, enforces CSRF.
     *
     * Sequence: extract the credential (`Authorization: Bearer` first, then the `axiam_access`
     * cookie) → verify the JWT locally → enforce the cross-tenant claim check → inject the
     * identity → call the next middleware.
     *
     * CSRF (CONTRACT.md §3a): when the credential came from the COOKIE and the method is
     * state-changing (not GET/HEAD/OPTIONS), the `X-CSRF-Token` header must be present and equal
     * (constant-time) to the `axiam_csrf` cookie, else the request is rejected with 403.
     * Bearer-authenticated requests are exempt — a cross-site attacker cannot set custom headers.
     *
     * @param Request $request Inbound request.
     * @param Closure $next    Next middleware in the pipeline.
     *
     * @return mixed The next middleware's response, or a 401/403 JSON error response.
     */
    public function handle(Request $request, Closure $next): mixed
    {
        // CONTRACT.md §28.3 rule 2: the metadata document MUST be reachable with no
        // credential of any kind. Where this middleware is applied globally (the normal
        // arrangement), it must exempt that one path itself — a document that 401s
        // cannot start the handshake it exists to start.
        if ($this->mcp !== null && $this->mcp->isMetadataDocumentRequest($request->getMethod(), $request->getPathInfo())) {
            return $next($request);
        }

        $credential = $this->extractToken($request);
        if ($credential === null) {
            return $this->unauthorized('missing authentication credentials', credentialPresented: false);
        }

        if (
            $credential['fromCookie']
            && !in_array(strtoupper($request->getMethod()), self::SAFE_METHODS, true)
            && !$this->isCsrfValid($request)
        ) {
            return $this->csrfValidationFailed();
        }

        $token = $credential['token'];

        // §10.1 rule 4: the token's tenant_id MUST equal the CONFIGURED tenant. The
        // X-Tenant-ID header is attacker-controlled, so it can only ever NARROW which
        // tenant this request asserts — it can never substitute for, or widen beyond,
        // the tenant this app was configured with. Letting the header pick the expected
        // value would make the whole check vacuous: an attacker would simply present a
        // token for tenant B alongside `X-Tenant-ID: B` and be compared against himself.
        //
        // §10.1 rule 8: the decision is about the CALLER's credential and no other. This
        // calls verifyLocally(), which has no fallback — never verifyLocallyOrFallback(),
        // whose fallback re-verifies THIS APPLICATION's own session and would admit a
        // failed request as the app's own (usually service-account) principal (SEC-085).
        $claims = $this->client->verifyLocally($token, $this->tenant);
        if ($claims === null) {
            return $this->unauthorized('invalid or expired token', credentialPresented: true);
        }

        $requestedTenant = $request->headers->get('X-Tenant-ID');
        if (is_string($requestedTenant) && $requestedTenant !== '' && $requestedTenant !== ($claims['tenant_id'] ?? null)) {
            return $this->unauthorized('invalid or expired token', credentialPresented: true);
        }

        $userId = $claims['sub'] ?? null;
        $claimedTenantId = $claims['tenant_id'] ?? null;
        if (!is_string($userId) || $userId === '' || !is_string($claimedTenantId) || $claimedTenantId === '') {
            // A signature-valid token with a malformed claim shape must still degrade to
            // the standardized 401, never an unhandled error further downstream.
            return $this->unauthorized('invalid or expired token', credentialPresented: true);
        }

        $request->attributes->set('axiam_user', [
            'user_id' => $userId,
            'tenant_id' => $claimedTenantId,
            'roles' => $this->rolesFromClaims($claims),
        ]);

        return $next($request);
    }

    /**
     * Bearer header first, cookie fallback second — the SAME ordering as every sibling
     * SDK's own auth middleware (e.g. the Python SDK's `django/middleware.py`
     * `_extract_token`, the Go SDK's `middleware/nethttp.go` `extractToken`), a Shared
     * Pattern documented across every framework bridge in this repository.
     *
     * Returns which source the credential came from so {@see self::handle()} can gate
     * state-changing cookie-sourced requests behind the CSRF double-submit check — a
     * Bearer-header credential never needs that check (§3).
     *
     * @return array{token: string, fromCookie: bool}|null
     */
    private function extractToken(Request $request): ?array
    {
        $header = (string) $request->headers->get('Authorization', '');
        if ($header !== '') {
            [$scheme, $credentials] = array_pad(explode(' ', $header, 2), 2, '');
            if (strtolower($scheme) === 'bearer' && trim($credentials) !== '') {
                return ['token' => trim($credentials), 'fromCookie' => false];
            }

            return null;
        }

        $cookie = $request->cookies->get('axiam_access');

        return is_string($cookie) && $cookie !== '' ? ['token' => $cookie, 'fromCookie' => true] : null;
    }

    /**
     * Cookie double-submit check (CONTRACT.md §3): the `X-CSRF-Token` header must be
     * present and equal, constant-time (mirrors {@see \Axiam\Sdk\Amqp\Hmac::verify()}'s
     * use of `hash_equals()`), to the `axiam_csrf` cookie value.
     */
    private function isCsrfValid(Request $request): bool
    {
        $header = (string) $request->headers->get(self::CSRF_HEADER_NAME, '');
        if ($header === '') {
            return false;
        }

        $cookie = $request->cookies->get(self::CSRF_COOKIE_NAME);
        if (!is_string($cookie) || $cookie === '') {
            return false;
        }

        return hash_equals($cookie, $header);
    }

    /**
     * @param array<string,mixed> $claims
     * @return list<string>
     */
    private function rolesFromClaims(array $claims): array
    {
        $rolesClaim = $claims['roles'] ?? $claims['scope'] ?? [];
        if (is_array($rolesClaim)) {
            return array_values(array_filter($rolesClaim, 'is_string'));
        }
        if (is_string($rolesClaim) && $rolesClaim !== '') {
            return array_values(array_filter(explode(' ', $rolesClaim)));
        }

        return [];
    }

    private function unauthorized(string $message, bool $credentialPresented): JsonResponse
    {
        // CONTRACT.md §10: AuthError -> HTTP 401 with a standardized JSON error body; no
        // raw token value is ever included in the response (mirrors every sibling SDK).
        // The JSON body is UNCHANGED by CONTRACT.md §28 (§28.5 rule 4) — only a header
        // is added, and only when this middleware was configured for it.
        $response = new JsonResponse(['error' => 'AuthError', 'message' => $message], 401);
        if ($this->mcp !== null) {
            $response->headers->set('WWW-Authenticate', $this->mcp->challengeFor401($credentialPresented));
        }

        return $response;
    }

    private function csrfValidationFailed(): JsonResponse
    {
        // CONTRACT.md §3/§10: a cookie-sourced credential on a state-changing request
        // without a valid double-submit token is an authorization failure -> HTTP 403,
        // same "AuthzError" shape {@see \Axiam\Sdk\Laravel\AxiamGate::authorize()} uses.
        return new JsonResponse(['error' => 'AuthzError', 'message' => 'csrf validation failed'], 403);
    }
}
