<?php

declare(strict_types=1);

namespace Axiam\Sdk;

use Axiam\Sdk\Auth\JwksVerifier;
use Axiam\Sdk\Auth\LoginResult;
use Axiam\Sdk\Auth\UserInfo;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\ErrorMapper;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Oidc\AuthorizationRequest;
use Axiam\Sdk\Oidc\IntrospectionResult;
use Axiam\Sdk\Oidc\OidcClient as OidcEngine;
use Axiam\Sdk\Oidc\OidcConfiguration;
use Axiam\Sdk\Oidc\OidcTokenSet;
use Axiam\Sdk\Oidc\SsoCompleteResult;
use Axiam\Sdk\Oidc\SsoStartResult;
use Axiam\Sdk\Rest\AuthMiddleware;
use Axiam\Sdk\Rest\AuthzRestClient;
use Axiam\Sdk\Rest\RefreshMiddleware;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\HandlerStack;
use Psr\Http\Message\ResponseInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * The AXIAM PHP SDK's public REST entry point (CONTRACT.md §1–§9, SC#1).
 *
 * `tenant` is a REQUIRED, non-nullable-defaulted constructor parameter (D-13, §5) — there
 * is no overload or default that lets a caller omit it; AXIAM is multi-tenant and there is
 * no default tenant. `login($email, $password)` returns a typed {@see LoginResult}, never a
 * raw array/stdClass (D-09); a two-phase MFA flow is completed via {@see self::verifyMfa()}.
 * `checkAccess`/`can`/`batchCheck` delegate to {@see AuthzDispatcher} — this class never
 * hand-rolls REST/gRPC transport selection (D-03). {@see self::verifyLocallyOrFallback()} is
 * the seam the Laravel/Symfony framework bridges (a later plan) call: local {@see JwksVerifier}
 * verification first, falling back to the reactive single-flight refresh path (D-02, D-06).
 *
 * Composition, not reimplementation: this class wires together the already-built wave-2/3
 * pieces — {@see Session} (CookieJar + CSRF + single-flight refresh promise, D-06),
 * {@see AuthMiddleware}/{@see RefreshMiddleware} (the `HandlerStack` auth/refresh mechanism),
 * {@see JwksVerifier} (local EdDSA/JWKS verification), and {@see AuthzDispatcher}
 * (REST-default, gRPC-when-available authz, D-03) — it does not reimplement any of their
 * internal mechanisms.
 *
 * Two Guzzle clients share ONE {@see CookieJar} (§4):
 *  - `$plainHttp` carries ONLY {@see AuthMiddleware} (tenant/auth/CSRF header injection, no
 *    401-triggered refresh-and-retry). This is the client handed to {@see Session}'s own
 *    constructor for its internal `/api/v1/auth/refresh` POST (per {@see Session}'s own doc
 *    comment: the refresh call itself must never be able to recursively re-enter the
 *    single-flight guard), and is also used for `login()`/`verifyMfa()`/`logout()` — a failed
 *    login/logout attempt (401/403) must surface as its own clear error, not trigger an
 *    unrelated token-refresh attempt first.
 *  - `$authzHttp` carries BOTH {@see AuthMiddleware} and {@see RefreshMiddleware} — the full
 *    production stack — and is the client {@see AuthzRestClient} (and therefore
 *    {@see AuthzDispatcher}'s REST path) sends every authz request through, so a 401 on an
 *    authz call transparently triggers the shared single-flight refresh-and-retry-once (D-06).
 *
 * §6/D-12: the Guzzle `verify` option is ALWAYS `true` (strict TLS, system trust roots) unless
 * `$customCa` (a CA bundle FILE PATH) is supplied, in which case `verify` is set to that path —
 * the ONLY escape hatch. There is no code path in this class that sets `verify` to `false` or
 * any other TLS-bypass value.
 *
 * §6.1 (mTLS): supplying `$clientCert` + `$clientKey` (both PEM strings) makes this client
 * present an X.509 client identity for mutual TLS on BOTH transports — the REST Guzzle clients
 * (via `cert`/`ssl_key`) and any gRPC channel (via
 * `\Grpc\ChannelCredentials::createSsl(rootCerts, privateKey, certChain)`). This is strictly
 * ADDITIVE to §6: presenting a client certificate NEVER relaxes server verification — `verify`
 * is untouched by this code path (contract rule §6.1.2). The private key is secret (§7): it is
 * held behind {@see Sensitive}, written only to a `0600` temp file consumed by cURL, and never
 * appears in any debug/log/exception output. Both PEM strings must be supplied together;
 * supplying exactly one is a construction-time {@see \InvalidArgumentException}.
 */
final class AxiamClient
{
    private const LOGIN_PATH = '/api/v1/auth/login';
    private const MFA_VERIFY_PATH = '/api/v1/auth/mfa/verify';
    private const LOGOUT_PATH = '/api/v1/auth/logout';

    private readonly string $tenant;

    private readonly ?string $orgSlug;

    private readonly ?string $orgId;

    private readonly LoggerInterface $logger;

    private readonly Session $session;

    /** AuthMiddleware only — login/verifyMfa/logout, and Session's own internal refresh POST. */
    private readonly Client $plainHttp;

    /** AuthMiddleware + RefreshMiddleware — the full production stack; authz traffic. */
    private readonly Client $authzHttp;

    private readonly JwksVerifier $jwksVerifier;

    private readonly AuthzDispatcher $authzDispatcher;

    /** CONTRACT.md §12 OIDC/SSO relying-party engine — see {@see OidcEngine}'s own docblock. */
    private readonly OidcEngine $oidc;

    /**
     * §6.1: absolute path to the `0600` temp file holding the client-certificate chain PEM
     * that BOTH Guzzle clients present as `cert`, or `null` when mTLS is not configured.
     */
    private readonly ?string $clientCertFile;

    /**
     * §6.1/§7: absolute path to the `0600` temp file holding the client PRIVATE KEY PEM that
     * BOTH Guzzle clients present as `ssl_key`, or `null` when mTLS is not configured. The key
     * lives on disk only in this short-lived, owner-only-readable file (deleted in
     * {@see self::__destruct()}); it is never retained as a plaintext property.
     */
    private readonly ?string $clientKeyFile;

    /**
     * @param string $baseUrl The AXIAM server's base URL (e.g. `https://api.axiam.example`).
     * @param string $tenant The tenant slug — REQUIRED, no nullable default anywhere on this
     *        signature (D-13, §5). There is no default tenant; constructing this client
     *        without one is a compile-time (missing required argument) error, and an empty
     *        string is rejected at runtime as a backstop.
     * @param string|null $orgSlug Organization slug — mutually exclusive with `$orgId`. The
     *        real login/refresh handlers require an org identifier beyond CONTRACT.md §5's
     *        tenant-only minimum (mirrors the Python/C# sibling SDKs' `org_slug`/`org_id`
     *        constructor options).
     * @param string|null $orgId Organization UUID — mutually exclusive with `$orgSlug`.
     * @param string|null $customCa A CA bundle FILE PATH (PEM-encoded) — the ONLY TLS escape
     *        hatch (§6/D-12). Never pass a value here to disable TLS verification; there is no
     *        such option on this class.
     * @param string|null $clientCert §6.1 (mTLS): the client's X.509 identity certificate
     *        CHAIN as a PEM STRING (not a path). When supplied together with `$clientKey`, this
     *        client presents that certificate for mutual TLS on both the REST and gRPC
     *        transports. Purely additive — server verification is never relaxed (§6.1.2). Must
     *        be a PEM value; a non-PEM string is rejected at construction. `null` (default)
     *        leaves the default bearer-cookie behavior unchanged (§6.1.5).
     * @param string|null $clientKey §6.1/§7 (mTLS): the PEM STRING of the private key matching
     *        `$clientCert` (PKCS#8 or PKCS#1). Secret material — it is held behind
     *        {@see Sensitive} and never logged, displayed, or exposed via a getter. `$clientCert`
     *        and `$clientKey` are all-or-nothing: supplying exactly one throws
     *        {@see \InvalidArgumentException}.
     * @param LoggerInterface|null $logger Injectable logger (D-15: diagnostic-only — status
     *        codes and operation names, NEVER a token/credential value). Defaults to a silent
     *        {@see NullLogger}.
     * @param bool|null $restOnly Force REST-only authz transport. `null` (default) resolves to
     *        `true` when `$grpcTarget` is not supplied (there would be nothing to connect the
     *        gRPC transport to) and `false` otherwise — an explicit `true`/`false` always wins.
     *        REST authz ALWAYS works regardless of this setting (D-03).
     * @param int $cacheTtlSeconds {@see JwksVerifier}'s local JWKS TTL cache lifetime.
     * @param string|null $grpcTarget gRPC target host:port (e.g. `api.axiam.example:9443`),
     *        required only to actually use the gRPC authz transport.
     * @param callable|null $transportHandler Test-only seam (NOT part of the public API
     *        contract, trailing/optional so it never affects SC#1's "tenant is required"
     *        reflection check): a raw Guzzle handler (e.g. `GuzzleHttp\Handler\MockHandler`)
     *        used as the base handler for both internal `HandlerStack`s instead of Guzzle's
     *        default cURL/stream handler. Mirrors the C# sibling SDK's `CreateForTesting`
     *        internal seam, adapted to Guzzle's own documented
     *        `HandlerStack::create($mockHandler)` testing idiom
     *        (docs.guzzlephp.org/en/stable/testing.html) — never used by production code.
     * @param string|null $oidcClientId CONTRACT.md §12: the relying party's OAuth2
     *        `client_id`, used by every `oidc*`/`introspect`/`revoke` operation and
     *        matched against an ID token's `aud`/`azp` (§12.4 rule 4). Required only by
     *        callers that use the §12 OIDC/SSO helpers — omitting it leaves the §1–§11
     *        surface completely unaffected, and a §12 call without one raises
     *        {@see AuthError} before any wire call.
     * @param Sensitive|string|null $oidcClientSecret CONTRACT.md §12: the confidential
     *        client's `client_secret`, held behind {@see Sensitive} (§12.5). Omit for a
     *        public client — `introspect`/`revoke`/`loginClientCredentials` REQUIRE it
     *        (§12.1 note 4) and raise {@see AuthError} when it is absent; `oidcExchange`/
     *        `oidcRefresh` omit it from the form body entirely when absent, per §12.1's
     *        "MUST omit rather than send empty/null" rule.
     * @param string|null $oidcTenantId CONTRACT.md §12.3 rule 4: the tenant UUID used as
     *        the default `?tenant_id=` query parameter on `/oauth2/*` calls when a call
     *        does not supply one explicitly. `$tenant` above is a SLUG (§5's
     *        `X-Tenant-ID` header value) and is never accepted where the wire contract
     *        requires a UUID — a §12 call with neither this nor a per-call `tenantId`
     *        raises {@see AuthError} client-side, with no wire call.
     */
    public function __construct(
        string $baseUrl,
        string $tenant,
        ?string $orgSlug = null,
        ?string $orgId = null,
        ?string $customCa = null,
        ?string $clientCert = null,
        ?string $clientKey = null,
        ?LoggerInterface $logger = null,
        ?bool $restOnly = null,
        int $cacheTtlSeconds = 300,
        ?string $grpcTarget = null,
        ?callable $transportHandler = null,
        ?string $oidcClientId = null,
        Sensitive|string|null $oidcClientSecret = null,
        ?string $oidcTenantId = null,
    ) {
        if ($tenant === '') {
            // D-13/§5 runtime backstop: PHP's type system alone cannot forbid an empty
            // string, only a missing argument. AXIAM is multi-tenant — there is no default
            // tenant, so a blank one is rejected exactly like an omitted one would be.
            throw new \InvalidArgumentException(
                'tenant is required — AXIAM is multi-tenant and there is no default tenant (CONTRACT.md §5)'
            );
        }
        if ($orgSlug !== null && $orgId !== null) {
            throw new \InvalidArgumentException('orgSlug and orgId are mutually exclusive — supply at most one');
        }
        // §6.1.1: PEM cert + PEM key are all-or-nothing. Presenting a half-configured client
        // identity is never valid, so reject exactly one at construction (clear, early error).
        if (($clientCert === null) !== ($clientKey === null)) {
            throw new \InvalidArgumentException(
                'clientCert and clientKey must be supplied together — mTLS needs both the certificate chain and its private key (CONTRACT.md §6.1)'
            );
        }

        $this->tenant = $tenant;
        $this->orgSlug = $orgSlug;
        $this->orgId = $orgId;
        $this->logger = $logger ?? new NullLogger();

        // §6.1/§7: hold the private key behind Sensitive so it can never leak via debug/log
        // output; the certificate chain is public material and needs no wrapping.
        $clientKeySensitive = $clientKey !== null ? new Sensitive($clientKey) : null;

        // §6.1.1: reject a non-PEM cert/key BEFORE any temp file is written, so a bad key can
        // never leave an orphaned cert temp file behind (a throwing constructor never runs
        // __destruct). §6.1: Guzzle/cURL consumes the client identity as FILES, so the
        // validated PEM strings are then materialized into short-lived `0600` temp files held
        // for this client's lifetime.
        if ($clientCert !== null && $clientKeySensitive !== null) {
            self::assertPem($clientCert, 'cert');
            self::assertPem($clientKeySensitive->reveal(), 'key');
            $this->clientCertFile = self::writeClientPemFile($clientCert);
            $this->clientKeyFile = self::writeClientPemFile($clientKeySensitive->reveal());
        } else {
            $this->clientCertFile = null;
            $this->clientKeyFile = null;
        }

        $cookieJar = new CookieJar();
        // §6/D-12: verify is ALWAYS true unless a customCa bundle PATH is supplied — never a
        // TLS-disable value. There is no other branch that can set `verify` to `false`.
        $verify = $customCa ?? true;

        $commonConfig = [
            'base_uri' => $baseUrl,
            'cookies' => $cookieJar, // §4: the ONE cookie jar every REST-facing client shares
            'verify' => $verify,
        ];
        // §6.1.4: apply the client identity to BOTH Guzzle clients alongside (never in place
        // of) `verify` — mutual TLS is additive to strict server verification (§6.1.2).
        if ($this->clientCertFile !== null && $this->clientKeyFile !== null) {
            $commonConfig['cert'] = $this->clientCertFile;
            $commonConfig['ssl_key'] = $this->clientKeyFile;
        }

        // $plainHttp: AuthMiddleware only, no RefreshMiddleware — handed to Session below for
        // its own refresh POST (so a 401 on the refresh call itself can never recursively
        // re-enter the single-flight guard) and used directly for login/verifyMfa/logout,
        // which must never trigger an unrelated token-refresh attempt on their own failures.
        $plainStack = HandlerStack::create($transportHandler);
        $this->plainHttp = new Client($commonConfig + ['handler' => $plainStack]);

        $this->session = new Session($baseUrl, $tenant, $this->plainHttp, $cookieJar);

        // AuthMiddleware needs the Session instance it decorates requests for; pushed after
        // Session exists but before any request is actually sent (HandlerStack::resolve() is
        // lazy and cached on first send, so this ordering is safe).
        $plainStack->push(new AuthMiddleware($this->session), 'axiam_auth');

        // $authzHttp: the full production stack (AuthMiddleware + RefreshMiddleware) — every
        // authz call transparently benefits from the shared single-flight refresh-on-401
        // (D-06), matching the plan's own prescribed push order.
        $authzStack = HandlerStack::create($transportHandler);
        $authzStack->push(new AuthMiddleware($this->session), 'axiam_auth');
        $authzStack->push(new RefreshMiddleware($this->session), 'axiam_refresh');
        $this->authzHttp = new Client($commonConfig + ['handler' => $authzStack]);

        $this->jwksVerifier = new JwksVerifier($this->plainHttp, $baseUrl, $cacheTtlSeconds);

        $resolvedRestOnly = $restOnly ?? ($grpcTarget === null);

        $this->authzDispatcher = new AuthzDispatcher(
            restClient: new AuthzRestClient($this->authzHttp),
            restOnly: $resolvedRestOnly,
            grpcTarget: $grpcTarget,
            tenantId: $tenant,
            tokenAccessor: fn (): ?string => $this->session->accessToken(),
            subjectIdAccessor: fn (): string => $this->currentSubjectId(),
            customCaPem: $customCa,
            clientCertPem: $clientCert,
            clientKey: $clientKeySensitive,
            // §1.1.4: getUserInfo's gRPC UNAUTHENTICATED retry drives the SAME single-flight
            // refresh guard (§9, D-06) the REST 401 path uses — never a second mechanism.
            refreshAccessor: fn (): mixed => $this->session->refreshIfNeeded()->wait(),
        );

        // CONTRACT.md §12: built on $plainHttp (AuthMiddleware only, NEVER
        // RefreshMiddleware) so a 401 from /oauth2/introspect or /oauth2/revoke can
        // never reach the §9 single-flight refresh guard — there is structurally no
        // guard on this transport for it to enter (§12.3 rule 3/rule 4). Shares
        // $this->jwksVerifier (the SAME verifier the §10 middleware uses for AXIAM's
        // own access tokens) for ID-token signature verification, since AXIAM's OIDC
        // provider and its own auth server are the same origin with one JWKS to trust.
        $this->oidc = new OidcEngine(
            http: $this->plainHttp,
            baseUrl: $baseUrl,
            session: $this->session,
            jwksVerifier: $this->jwksVerifier,
            clientId: $oidcClientId,
            clientSecret: $oidcClientSecret !== null && !($oidcClientSecret instanceof Sensitive)
                ? new Sensitive($oidcClientSecret)
                : $oidcClientSecret,
            tenantId: $oidcTenantId,
            orgId: $orgId,
            orgSlug: $orgSlug,
            tenantSlugForSso: $tenant,
        );
    }

    /**
     * §6.1: cleans up the `0600` temp files backing the client-certificate identity when this
     * client is destroyed, so no PEM material (least of all the private key) outlives the
     * object on disk. A no-op when mTLS was not configured.
     */
    public function __destruct()
    {
        foreach ([$this->clientCertFile, $this->clientKeyFile] as $file) {
            if ($file !== null && is_file($file)) {
                @unlink($file);
            }
        }
    }

    /**
     * §6.1.1: asserts that `$pem` looks like a PEM value (has a `-----BEGIN ...` block),
     * throwing an {@see \InvalidArgumentException} at construction time otherwise — consistent
     * with §6's PEM-only rule. `$kind` (`cert`|`key`) only shapes the error wording; the raw
     * private-key PEM is never placed in any message (§7).
     */
    private static function assertPem(string $pem, string $kind): void
    {
        if (!str_contains($pem, '-----BEGIN ')) {
            throw new \InvalidArgumentException(sprintf(
                'client %s must be a PEM string (expected a "-----BEGIN ..." block) — a non-PEM value is rejected (CONTRACT.md §6.1.1)',
                $kind === 'key' ? 'private key' : 'certificate',
            ));
        }
    }

    /**
     * §6.1/§7: writes an already-validated PEM string to a fresh owner-only (`0600`) temp file,
     * returning the absolute path cURL reads the client identity from. The file is chmod-ed to
     * `0600` BEFORE the (possibly secret) bytes are written, and is removed in
     * {@see self::__destruct()}.
     */
    private static function writeClientPemFile(string $pem): string
    {
        $path = tempnam(sys_get_temp_dir(), 'axiam-mtls-');
        if ($path === false) {
            throw new \RuntimeException('unable to create a temp file for the mTLS client identity');
        }
        // Restrict to owner read/write BEFORE writing the (possibly secret) bytes.
        @chmod($path, 0600);
        if (file_put_contents($path, $pem) === false) {
            @unlink($path);
            throw new \RuntimeException('unable to write the mTLS client identity to its temp file');
        }

        return $path;
    }

    // ------------------------------------------------------------------
    // Test-only seam (not part of the public API contract) — lets
    // ClientConstructionTest assert the TLS `verify` option actually configured
    // on this client's Guzzle transport without reaching into private state via
    // Reflection.
    // ------------------------------------------------------------------

    /** @return string|bool The Guzzle `verify` option: `true`, or a CA bundle path (never `false`). */
    public function debugVerifyOption(): string|bool
    {
        return $this->authzHttp->getConfig('verify');
    }

    /**
     * Test-only seam (not part of the public API contract, mirroring {@see self::debugVerifyOption()}):
     * exposes the §6.1 client-identity options (`cert` = certificate-chain file, `ssl_key` =
     * private-key file) actually configured on this client's authz Guzzle transport, so tests
     * can assert the mTLS wiring without performing a live TLS handshake. Both entries are
     * `null` when mTLS was not configured. The values are FILE PATHS, never the PEM bytes —
     * this seam never surfaces the private key itself.
     *
     * @return array{cert: string|null, ssl_key: string|null}
     */
    public function debugClientCertOptions(): array
    {
        $cert = $this->authzHttp->getConfig('cert');
        $sslKey = $this->authzHttp->getConfig('ssl_key');

        return [
            'cert' => is_string($cert) ? $cert : null,
            'ssl_key' => is_string($sslKey) ? $sslKey : null,
        ];
    }

    // ------------------------------------------------------------------
    // Auth flow (CONTRACT.md §1): login / verifyMfa / refresh / logout
    // ------------------------------------------------------------------

    /**
     * `POST /api/v1/auth/login` (CONTRACT.md §1). Returns a typed {@see LoginResult} — an MFA
     * challenge (HTTP 202) is an expected outcome, not an exception: callers MUST check
     * {@see LoginResult::$mfaRequired} before assuming a session was established (SC#1).
     */
    public function login(string $email, string $password): LoginResult
    {
        $response = $this->post($this->plainHttp, self::LOGIN_PATH, $this->loginBody($email, $password));

        return $this->handleLoginResponse($response);
    }

    /**
     * `POST /api/v1/auth/mfa/verify` (CONTRACT.md §1) — completes the two-phase flow started by
     * {@see self::login()} when {@see LoginResult::$mfaRequired} was `true`. `$challengeToken`
     * is the `Sensitive`-wrapped value from that `LoginResult` (D-11: never a raw string on the
     * public surface).
     */
    public function verifyMfa(Sensitive $challengeToken, string $totpCode): LoginResult
    {
        $response = $this->post($this->plainHttp, self::MFA_VERIFY_PATH, [
            'challenge_token' => $challengeToken->reveal(),
            'totp_code' => $totpCode,
        ]);

        return $this->handleLoginResponse($response);
    }

    /**
     * `POST /api/v1/auth/refresh` (CONTRACT.md §1), routed through {@see Session}'s
     * single-flight guard (§9, D-06) — the SAME mechanism {@see RefreshMiddleware} triggers
     * reactively on a `401`. A failure surfaces as {@see AuthError} with no retry (§9.3).
     */
    public function refresh(): void
    {
        $this->logger->debug('axiam_sdk: token refresh triggered');
        $this->session->refreshIfNeeded()->wait();
    }

    /**
     * `POST /api/v1/auth/logout` (CONTRACT.md §1) and clears local session state: the shared
     * cookie jar (§4) and the captured CSRF token (§3). The session id comes from the current
     * access token's `jti` claim (unverified decode — an operational hint only, never an
     * authorization decision, mirroring the Python/C# sibling SDKs).
     */
    public function logout(): void
    {
        $claims = $this->currentClaimsOrNull();
        $jti = is_array($claims) ? ($claims['jti'] ?? null) : null;
        if (!is_string($jti) || $jti === '') {
            throw new AuthError('no active session to log out');
        }

        $response = $this->post($this->plainHttp, self::LOGOUT_PATH, ['session_id' => $jti]);
        if ($response->getStatusCode() >= 300) {
            throw ErrorMapper::fromResponse($response, 'logout failed');
        }

        // Clears cookies/CSRF/local state (this plan's own behavior contract).
        $this->session->cookieJar()->clear();
        $this->session->resetCsrf();
    }

    // ------------------------------------------------------------------
    // Authz (CONTRACT.md §1, FND-04, D-03) — transparent REST/gRPC delegation
    // ------------------------------------------------------------------

    /**
     * `checkAccess` — delegates to {@see AuthzDispatcher} (REST default, gRPC when available).
     *
     * @param string|null $subjectId Additive, optional (CONTRACT.md §11.2.2 —
     *        declarative authorization helpers): when given, the check is evaluated
     *        for THIS subject (a UUID) rather than whichever identity this client's
     *        own session represents. This matters for a framework bridge sharing ONE
     *        `AxiamClient` instance (typically authenticated as a service account, or
     *        not authenticated at all) to authorize each inbound HTTP request's OWN
     *        end user: passing `subjectId: $endUserId` here checks the end user's
     *        permissions, never the shared client's. `null` (the default) preserves
     *        this method's pre-§11 behavior exactly.
     */
    public function checkAccess(string $action, string $resourceId, ?string $scope = null, ?string $subjectId = null): bool
    {
        return $this->authzDispatcher->checkAccess($action, $resourceId, $scope, $subjectId);
    }

    /**
     * `can` — the browser/UI-scenario alias for {@see self::checkAccess()} (CONTRACT.md §1
     * note). Argument order is `(action, resource)` — matching {@see self::checkAccess()}
     * and every other AXIAM SDK's `can`/`Can` (D-09/SDK-Q09; this was previously reversed
     * relative to the rest of the SDK family).
     */
    public function can(string $action, string $resource): bool
    {
        return $this->authzDispatcher->can($resource, $action);
    }

    /**
     * `batchCheck` — results preserve input order (CONTRACT.md §1).
     *
     * @param list<array{action: string, resourceId: string, scope?: string|null}> $checks
     * @return list<bool>
     */
    public function batchCheck(array $checks): array
    {
        return $this->authzDispatcher->batchCheck($checks);
    }

    /**
     * `getUserInfo` — the gRPC-ONLY OIDC-style userinfo operation (CONTRACT.md §1.1,
     * contract 1.3): returns the authenticated caller's identity claims from
     * `axiam.v1.UserInfoService/GetUserInfo`, the low-latency counterpart of the server's
     * REST `GET /oauth2/userinfo`. Delegates to {@see AuthzDispatcher} — this class never
     * hand-rolls the gRPC transport (D-03).
     *
     * Identity is derived server-side from the current bearer token; the request is empty.
     * `sub`/`tenantId`/`orgId` are always populated on the returned {@see UserInfo};
     * `email` is present only with the "email" token scope and `preferredUsername` only with
     * "profile" (the server gates them exactly as the REST endpoint does). Requires a prior
     * successful {@see self::login()} — calling it with no token raises {@see AuthError}
     * before any wire call (§1.1.3) — and, being gRPC-only (§1.1.6), requires the `grpc` PECL
     * extension plus a configured `grpcTarget`; there is NO REST fallback, so on a REST-only
     * runtime it raises {@see NetworkError} rather than degrading. A gRPC `UNAUTHENTICATED`
     * response drives the shared single-flight refresh (§9) and retries once (§1.1.4).
     */
    public function getUserInfo(): UserInfo
    {
        return $this->authzDispatcher->getUserInfo();
    }

    // ------------------------------------------------------------------
    // OIDC / SSO relying-party helpers (CONTRACT.md §12, contract 1.4)
    //
    // The nine canonical §12 operations, exactly the §12.2 PHP names, delegating to
    // {@see OidcEngine} — this class's OWN internal composed collaborator, exactly as
    // `checkAccess`/`can`/`batchCheck`/`getUserInfo` above delegate to
    // {@see AuthzDispatcher}. Building an RP flow requires `oidcClientId` (and, for
    // `introspect`/`revoke`/`loginClientCredentials`, `oidcClientSecret`) at
    // construction — see this class's constructor docblock.
    // ------------------------------------------------------------------

    /**
     * `GET /.well-known/openid-configuration` (CONTRACT.md §12.1) — fetch the OIDC
     * discovery document, cached per origin with a ≥5-minute TTL and single-flight
     * de-duplication of concurrent callers (§12.3 rule 6). The document's own `issuer`
     * is authoritative for ID-token validation (§12.4 rule 3) and may legitimately
     * differ from `$baseUrl` behind a proxy — never treated as an error (§12.3 rule 6).
     */
    public function oidcDiscover(): OidcConfiguration
    {
        return $this->oidc->oidcDiscover();
    }

    /**
     * Build an authorization request (CONTRACT.md §12.1) — **pure local computation, no
     * network I/O**. Generates a `state`/`nonce` (CSPRNG, ≥128 bits) and a fresh PKCE
     * verifier/challenge pair (**S256 only**), and builds `$configuration`'s
     * `authorization_endpoint` into a redirect URL with exactly the eight SDK-owned
     * query parameters plus any `$extraParams` supplied.
     *
     * **Nothing is stored** (§12.3 rule 1): persist the returned `state`, `nonce` and
     * `codeVerifier` yourself (e.g. in your own HTTP session, or via
     * {@see \Axiam\Sdk\Oidc\MemoryOidcStateStore}) and pass `nonce`/`codeVerifier` back
     * into {@see self::oidcExchange()} when the authorization code arrives.
     *
     * @param string|list<string>|null $scope `openid` is added automatically when
     *        absent (§12.1 rule 4). Defaults to `openid`.
     * @param array<string,string> $extraParams Extra authorization-request parameters
     *        (e.g. `prompt`, `login_hint`). Throws {@see \InvalidArgumentException} if
     *        one tries to override an SDK-owned parameter (§12.1 rule 5).
     */
    public function oidcBegin(
        OidcConfiguration $configuration,
        string $redirectUri,
        string|array|null $scope = null,
        array $extraParams = [],
    ): AuthorizationRequest {
        return $this->oidc->oidcBegin($configuration, $redirectUri, $scope, $extraParams);
    }

    /**
     * `POST /oauth2/token` with `grant_type=authorization_code` (CONTRACT.md §12.1) —
     * exchange an authorization code for a token set, validating the returned ID token
     * in full (§12.4) before returning. `$nonce` is MANDATORY: this grant always
     * requests `openid`, so §12.4 rule 6 always applies. On ANY §12.4 failure the whole
     * token set is discarded and {@see AuthError} is raised with the matching reason
     * code (§12.4 rule 7) — `getReason()` returns one of `invalid_alg`, `unknown_kid`,
     * `invalid_signature`, `invalid_issuer`, `invalid_audience`, `token_expired`,
     * `nonce_mismatch`.
     *
     * @param Sensitive|string $codeVerifier The verifier from the matching
     *        {@see AuthorizationRequest} — accepts the wrapped or bare form.
     * @param string|null $tenantId Tenant UUID for the required `?tenant_id=` query
     *        parameter (§12.3 rule 4). Falls back to the client's `oidcTenantId`.
     * @param OidcConfiguration|null $configuration A pre-fetched discovery document, to
     *        avoid re-reading the (cached) one. Fetched via {@see self::oidcDiscover()}
     *        when omitted.
     */
    public function oidcExchange(
        string $code,
        Sensitive|string $codeVerifier,
        string $redirectUri,
        string $nonce,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
    ): OidcTokenSet {
        return $this->oidc->oidcExchange($code, $codeVerifier, $redirectUri, $nonce, $tenantId, $configuration);
    }

    /**
     * `POST /oauth2/token` with `grant_type=refresh_token` (CONTRACT.md §12.1) —
     * refresh an {@see OidcTokenSet} under the SAME §9 single-flight guard
     * {@see self::refresh()} uses. A **distinct operation** from {@see self::refresh()}
     * (the cookie/opaque-token session path) — the two are never merged, aliased, or
     * fall back to one another, but they share ONE guard slot: a concurrent
     * `oidcRefresh()` call finding the guard busy with a cookie-session refresh retries
     * (bounded) rather than returning a stale token set.
     *
     * Any `id_token` in the response is validated against §12.4 rules 1–5 and 7; rule 6
     * (nonce) is skipped (OIDC Core §12.2 does not require a nonce on a refresh-issued
     * ID token).
     *
     * @param Sensitive|string $refreshToken The refresh token to redeem — accepts the
     *        wrapped or bare form.
     */
    public function oidcRefresh(
        Sensitive|string $refreshToken,
        ?string $scope = null,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
    ): OidcTokenSet {
        return $this->oidc->oidcRefresh($refreshToken, $scope, $tenantId, $configuration);
    }

    /**
     * `POST /oauth2/token` with `grant_type=client_credentials` (CONTRACT.md §12.1) —
     * service-account machine-to-machine login. Requests no `openid` scope, so the
     * response carries no `id_token`. Pass `$adoptAsCredential: true` to additionally
     * adopt the returned access token as this client's bearer credential for
     * subsequent same-origin REST calls (§12.1, an opt-in MAY) — the token is held
     * behind {@see Sensitive} inside {@see Session} and is NEVER sent to `/oauth2/*`.
     *
     * @throws AuthError when no `oidcClientSecret` was configured — this grant cannot
     *                    be performed by a public client (§12.1 note 4).
     */
    public function loginClientCredentials(
        ?string $scope = null,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
        bool $adoptAsCredential = false,
    ): OidcTokenSet {
        return $this->oidc->loginClientCredentials($scope, $tenantId, $configuration, $adoptAsCredential);
    }

    /**
     * `POST /oauth2/introspect` (RFC 7662, CONTRACT.md §12.1) — ask the server whether
     * a token is active and, if so, for its metadata. Requires confidential-client
     * credentials (§12.1 note 4). A `401` here is a client-credential failure surfaced
     * as {@see \Axiam\Sdk\Core\OAuthProtocolError} and NEVER enters the §9 refresh guard
     * (§12.3 rule 3).
     *
     * @param Sensitive|string $token The token to introspect — accepts the wrapped or
     *        bare form.
     *
     * @throws AuthError when no `oidcClientSecret` was configured.
     */
    public function introspect(
        Sensitive|string $token,
        ?string $tokenTypeHint = null,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
    ): IntrospectionResult {
        return $this->oidc->introspect($token, $tokenTypeHint, $tenantId, $configuration);
    }

    /**
     * `POST /oauth2/revoke` (RFC 7009, CONTRACT.md §12.1) — revoke an access or refresh
     * token. Returns nothing. Per RFC 7009 the server answers `200` for an unknown,
     * expired, or already-revoked token too, so this call is **idempotent**: only a
     * `401` (client authentication failed) is an error, surfaced as
     * {@see \Axiam\Sdk\Core\OAuthProtocolError} (§12.1 note 5). A `5xx` still raises
     * {@see NetworkError}.
     *
     * @param Sensitive|string $token The token to revoke — accepts the wrapped or bare
     *        form.
     *
     * @throws AuthError when no `oidcClientSecret` was configured.
     */
    public function revoke(
        Sensitive|string $token,
        ?string $tokenTypeHint = null,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
    ): void {
        $this->oidc->revoke($token, $tokenTypeHint, $tenantId, $configuration);
    }

    /**
     * `POST /api/v1/auth/federation/oidc/start` (CONTRACT.md §12.1) — step 1 of
     * first-time SSO against an **upstream** IdP. No JWT required. One tenant form
     * (`$tenantId`/`$tenantSlug`) and one org form (`$orgId`/`$orgSlug`) must be
     * resolvable, from the arguments or from this client's construction options
     * (§5.1) — an unresolvable one raises {@see AuthError} client-side, with no wire
     * call. Redirect the browser to the returned `authorizeUrl` and round-trip `state`
     * back into {@see self::ssoComplete()} unmodified; the server keeps the nonce to
     * itself (§12.1 note 7).
     */
    public function ssoStart(
        string $federationConfigId,
        string $redirectUri,
        ?string $tenantId = null,
        ?string $tenantSlug = null,
        ?string $orgId = null,
        ?string $orgSlug = null,
    ): SsoStartResult {
        return $this->oidc->ssoStart($federationConfigId, $redirectUri, $tenantId, $tenantSlug, $orgId, $orgSlug);
    }

    /**
     * `POST /api/v1/auth/federation/oidc/callback` (CONTRACT.md §12.1) — step 2 of
     * upstream SSO: consumes the single-use `$state`, provisions or links the user, and
     * establishes the session. The session arrives as `Set-Cookie` — not in the
     * response body (§12.1 note 6) — so it is captured automatically via this client's
     * shared §4 cookie jar; the freshly-issued §3 CSRF token is captured too, exactly
     * as {@see self::login()} does. §12.4 does not apply here: no ID token ever reaches
     * the SDK on the federation path.
     */
    public function ssoComplete(string $state, string $code): SsoCompleteResult
    {
        return $this->oidc->ssoComplete($state, $code);
    }

    // ------------------------------------------------------------------
    // Framework-bridge seam (D-02): local verify, reactive-refresh fallback
    // ------------------------------------------------------------------

    /**
     * Local-first JWT verification with a reactive-refresh fallback (D-02) — the seam the
     * Laravel/Symfony framework bridges (a later plan) call for every incoming request.
     * Tries {@see JwksVerifier::verify()} first (no network call on the happy path); if that
     * fails (expired/unknown-kid/invalid token), attempts the shared single-flight refresh
     * (§9, D-06) and re-verifies the FRESH access token. Returns `null` — never unverified
     * claims — on any failure; this method is fail-closed exactly like {@see JwksVerifier}
     * itself, since callers use the result for an authorization decision.
     *
     * @return array<string,mixed>|null Verified claims, or null.
     */
    public function verifyLocallyOrFallback(string $token, string $tenant): ?array
    {
        $claims = $this->jwksVerifier->verify($token, $tenant);
        if ($claims !== null) {
            return $claims;
        }

        try {
            $this->session->refreshIfNeeded()->wait();
        } catch (\Throwable) {
            return null;
        }

        $refreshedToken = $this->session->accessToken();
        if ($refreshedToken === null) {
            return null;
        }

        return $this->jwksVerifier->verify($refreshedToken, $tenant);
    }

    // ------------------------------------------------------------------
    // Wire-body construction + response handling
    // ------------------------------------------------------------------

    /** @return array<string,string> */
    private function loginBody(string $email, string $password): array
    {
        $body = [
            'tenant_slug' => $this->tenant,
            'username_or_email' => $email,
            'password' => $password,
        ];
        if ($this->orgId !== null) {
            $body['org_id'] = $this->orgId;
        } elseif ($this->orgSlug !== null) {
            $body['org_slug'] = $this->orgSlug;
        }

        return $body;
    }

    /**
     * Maps a `LoginSuccessResponse` (HTTP 200) or `MfaRequiredResponse` (HTTP 202) — the two
     * non-error outcomes of both `POST /api/v1/auth/login` and `POST /api/v1/auth/mfa/verify`
     * (openapi.json) — to a typed {@see LoginResult}. Any other status is a mapped error.
     */
    private function handleLoginResponse(ResponseInterface $response): LoginResult
    {
        $status = $response->getStatusCode();
        $wire = json_decode((string) $response->getBody(), true);

        if ($status === 200) {
            $userId = is_array($wire) ? ($wire['user']['id'] ?? null) : null;
            if (!is_string($userId) || $userId === '') {
                throw NetworkError::fromResponse($response, 'login: malformed response body');
            }

            return new LoginResult(mfaRequired: false, userId: $userId, tenantId: $this->tenant);
        }

        if ($status === 202) {
            $challengeToken = is_array($wire) ? ($wire['challenge_token'] ?? null) : null;
            if (!is_string($challengeToken) || $challengeToken === '') {
                throw NetworkError::fromResponse($response, 'login: MFA challenge response missing challenge_token');
            }

            return new LoginResult(mfaRequired: true, challengeToken: new Sensitive($challengeToken));
        }

        $this->logger->warning('axiam_sdk: login/verify_mfa failed: status={status}', ['status' => $status]);

        throw ErrorMapper::fromResponse($response, 'login/verifyMfa failed');
    }

    /**
     * POSTs `$body` as JSON to `$path` via `$http`, mapping any non-2xx response (thrown by
     * Guzzle as a {@see RequestException} by default) through {@see ErrorMapper} (CONTRACT.md
     * §2, D-10) — the single translation point every transport in this SDK uses.
     *
     * @param array<string,mixed> $body
     */
    private function post(Client $http, string $path, array $body): ResponseInterface
    {
        try {
            return $http->post($path, ['json' => $body]);
        } catch (RequestException $e) {
            // Guzzle 8 moved getResponse() to BadResponseException; a bare
            // RequestException/ConnectException carries no response (works on ^7.13 and ^8.0).
            $response = $e instanceof BadResponseException ? $e->getResponse() : null;
            if ($response !== null) {
                throw ErrorMapper::fromResponse($response, $path . ' failed');
            }

            throw NetworkError::fromException($e, $path . ' failed');
        } catch (GuzzleException $e) {
            throw NetworkError::fromException($e, $path . ' failed');
        }
    }

    /**
     * Unverified decode of the CURRENT access token's payload segment (base64url + JSON, NO
     * signature check) — used ONLY to resolve operational identifiers (`jti` for logout,
     * `sub` for the gRPC authz subject id), mirroring the Python/C# sibling SDKs'
     * `_decode_unverified_claims`/`DecodeUnverifiedClaims` helpers. NEVER used for an
     * authorization decision — that is exclusively {@see JwksVerifier::verify()}'s job
     * (SEC-003); this method deliberately does not check `tenant_id` or any signature.
     *
     * @return array<string,mixed>|null
     */
    private function currentClaimsOrNull(): ?array
    {
        $token = $this->session->accessToken();
        if ($token === null) {
            return null;
        }

        $parts = explode('.', $token);
        if (count($parts) !== 3) {
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

    /** The `sub` claim of the current (unverified) access token, or `''` if unavailable. */
    private function currentSubjectId(): string
    {
        $claims = $this->currentClaimsOrNull();
        $sub = is_array($claims) ? ($claims['sub'] ?? null) : null;

        return is_string($sub) ? $sub : '';
    }
}
