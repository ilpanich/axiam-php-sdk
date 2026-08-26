<?php

declare(strict_types=1);

namespace Axiam\Sdk;

use Axiam\Sdk\Auth\JwksVerifier;
use Axiam\Sdk\Auth\LoginResult;
use Axiam\Sdk\Auth\UserInfo;
use Axiam\Sdk\Account\MfaEnrollment;
use Axiam\Sdk\Account\PasswordResetConfirmation;
use Axiam\Sdk\Account\PasswordResetContext;
use Axiam\Sdk\Account\PasswordResetRequest;
use Axiam\Sdk\Webauthn\WebauthnChallenge;
use Axiam\Sdk\Webauthn\WebauthnCredential;
use Axiam\Sdk\Webauthn\WebauthnLoginResult;
use Axiam\Sdk\Webauthn\WebauthnWorkspace;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\ErrorMapper;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Oidc\AuthorizationRequest;
use Axiam\Sdk\Oidc\IntrospectionResult;
use Axiam\Sdk\Oidc\DeviceAuthorization;
use Axiam\Sdk\Oidc\ExchangedToken;
use Axiam\Sdk\Oidc\OidcClient as OidcEngine;
use Axiam\Sdk\Oidc\VerifiedLogoutToken;
use Axiam\Sdk\Oidc\OidcConfiguration;
use Axiam\Sdk\Oidc\OidcTokenSet;
use Axiam\Sdk\Oidc\PushedAuthorizationRequest;
use Axiam\Sdk\Oidc\RequestedPermission;
use Axiam\Sdk\Oidc\RequestingPartyToken;
use Axiam\Sdk\Oidc\ResourceSet;
use Axiam\Sdk\Oidc\SsoCompleteResult;
use Axiam\Sdk\Oidc\SsoStartResult;
use Axiam\Sdk\Oidc\UmaChallenge;
use Axiam\Sdk\Rest\AuthMiddleware;
use Axiam\Sdk\Rest\AuthzRestClient;
use Axiam\Sdk\Rest\RefreshMiddleware;
use Axiam\Sdk\Opaque\KsfParams;
use Axiam\Sdk\Opaque\Opaque;
use Axiam\Sdk\Opaque\OpaqueEnrollment;
use Axiam\Sdk\Opaque\OpaqueMode;
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
    private const OPAQUE_REGISTER_START_PATH = '/api/v1/auth/opaque/register/start';
    private const OPAQUE_LOGIN_START_PATH = '/api/v1/auth/opaque/login/start';
    private const OPAQUE_LOGIN_FINISH_PATH = '/api/v1/auth/opaque/login/finish';

    private const LOGOUT_PATH = '/api/v1/auth/logout';

    private const WEBAUTHN_REGISTER_START_PATH = '/api/v1/auth/webauthn/register/start';
    private const WEBAUTHN_REGISTER_FINISH_PATH = '/api/v1/auth/webauthn/register/finish';
    private const WEBAUTHN_AUTH_START_PATH = '/api/v1/auth/webauthn/authenticate/start';
    private const WEBAUTHN_AUTH_FINISH_PATH = '/api/v1/auth/webauthn/authenticate/finish';
    private const WEBAUTHN_DISCOVERABLE_START_PATH = '/api/v1/auth/webauthn/authenticate/discoverable/start';
    private const WEBAUTHN_DISCOVERABLE_FINISH_PATH = '/api/v1/auth/webauthn/authenticate/discoverable/finish';

    private const MFA_ENROLL_PATH = '/api/v1/auth/mfa/enroll';
    private const MFA_CONFIRM_PATH = '/api/v1/auth/mfa/confirm';
    private const MFA_SETUP_ENROLL_PATH = '/api/v1/auth/mfa/setup/enroll';
    private const MFA_SETUP_CONFIRM_PATH = '/api/v1/auth/mfa/setup/confirm';
    private const VERIFY_EMAIL_PATH = '/api/v1/auth/verify-email';
    private const RESEND_VERIFICATION_PATH = '/api/v1/auth/resend-verification';
    private const RESET_PATH = '/api/v1/auth/reset';
    private const RESET_CONTEXT_PATH = '/api/v1/auth/reset/context';
    private const RESET_CONFIRM_PATH = '/api/v1/auth/reset/confirm';

    /** §17 decision memo. Disabled unless a TTL was configured. */
    private readonly \Axiam\Sdk\Core\DecisionMemo $decisionMemo;

    /** §19 telemetry dispatcher. Inert unless a hook was installed. */
    private readonly \Axiam\Sdk\Core\TelemetryDispatcher $telemetry;

    /** §18 shutdown flag, read on every operation. */
    private bool $closed = false;

    private readonly string $tenant;

    private readonly ?string $orgSlug;

    private readonly ?string $orgId;

    /**
     * The tenant UUID (`$oidcTenantId`), kept because `$tenant` above is a SLUG.
     * CONTRACT.md §27 routes substitute `{tenant_id}`, which is the UUID form — a slug
     * in that position is a 404 the caller cannot diagnose.
     */
    private readonly ?string $tenantUuid;

    /** §16.1 retry switch, forwarded to the §27 management transport. */
    private readonly bool $retryEnabled;

    /** §27 management surface. Built on first use; see {@see self::management()}. */
    private ?\Axiam\Sdk\Management\ManagementApi $management = null;

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
     * @param string|null $expectedIssuer CONTRACT.md §10.1 rule 5: the `iss` value local
     *        token verification requires. CONDITIONAL and unset by default — `null` means
     *        no issuer check is performed at all; once supplied, a token whose `iss`
     *        differs (or which carries no `iss`) is rejected. There is no default value
     *        and no hardcoded AXIAM issuer anywhere in this SDK.
     * @param string|null $expectedAudience CONTRACT.md §10.1 rule 6: the `aud` value local
     *        token verification requires. CONDITIONAL and unset by default — `null` means
     *        no audience check at all; once supplied, a token whose `aud` does not contain
     *        it (including one with no `aud`) is rejected. An app guarding a user-facing
     *        resource server should generally expect `axiam:user`; it is not defaulted,
     *        because a service-to-service guard legitimately expects a different audience.
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
        ?string $expectedIssuer = null,
        ?string $expectedAudience = null,
        bool $retryEnabled = true,
        float $decisionMemoTtlMs = 0.0,
        ?callable $telemetryHook = null,
    ) {
        // §17.1 rule 1: off unless the caller asked for it. §19: inert unless a hook
        // was installed.
        $this->telemetry = new \Axiam\Sdk\Core\TelemetryDispatcher($telemetryHook);
        $this->decisionMemo = new \Axiam\Sdk\Core\DecisionMemo($decisionMemoTtlMs);
        // §19.2 rule 6: a clamped setting is reported, not swallowed. Emitted once,
        // here, because construction is the only moment an operator can act on it.
        $this->decisionMemo->reportClamp($decisionMemoTtlMs, $this->telemetry);

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
        $this->tenantUuid = $oidcTenantId;
        $this->retryEnabled = $retryEnabled;
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

        $this->jwksVerifier = new JwksVerifier(
            $this->plainHttp,
            $baseUrl,
            $cacheTtlSeconds,
            // §10.1 rules 5/6 are CONDITIONAL — normalize '' to null so an empty config
            // value can never be mistaken for "expect the empty string".
            ($expectedIssuer ?? '') !== '' ? $expectedIssuer : null,
            ($expectedAudience ?? '') !== '' ? $expectedAudience : null,
        );

        $resolvedRestOnly = $restOnly ?? ($grpcTarget === null);

        $this->authzDispatcher = new AuthzDispatcher(
            restClient: new AuthzRestClient(
                $this->authzHttp,
                $this->decisionMemo,
                $this->telemetry,
                $retryEnabled,
            ),
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
        //
        // ---------------------------------------------------------------------------
        // INVARIANT (name it, because nothing enforces it): §12.3 rule 3 holds here by
        // the ABSENCE of a 401→refresh interceptor on this transport, not by any check
        // anywhere that inspects the URL and opts /oauth2/* out. Nothing in OidcEngine,
        // AuthMiddleware or RefreshMiddleware would object if that absence ended.
        //
        // Two edits silently violate the rule, and neither fails to compile:
        //   1. pushing RefreshMiddleware (or any other retry-on-401 middleware) onto
        //      $plainStack — it is the SAME stack $this->plainHttp and Session's own
        //      refresh POST run on; or
        //   2. handing OidcEngine $this->authzHttp, or any future client built on
        //      $authzStack, instead of $plainHttp.
        // Either one turns an ordinary `invalid_client` from /oauth2/introspect into a
        // cookie-session refresh attempt — spending a single-use rotating refresh token
        // to "fix" a 401 that was never about the cookie session at all.
        //
        // Conformance-review F-14: five SDKs rely on this same structural invariant.
        // What guards it here is not the type system but two regression tests —
        // OidcTokenOpsTest::test401From{Introspect,Revoke}SurfacesAsOAuthProtocolError
        // AndNeverEntersRefreshGuard — which assert zero /api/v1/auth/refresh calls on
        // that path. If you deliberately change this wiring, expect them to fail, and
        // treat that failure as the contract speaking rather than as a stale test.
        // ---------------------------------------------------------------------------
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
     * Releases this client's local resources (CONTRACT.md §18).
     *
     * Idempotent — calling it twice is not an error. Cleanup runs from error paths,
     * and an error path that itself throws hides the original failure.
     *
     * **This does not log out.** §18.1 rule 5: shutting down a client releases
     * *local* resources and never reaches the network. The server-side session
     * deliberately outlives the client object, which is what lets a process restart
     * and resume; a `close()` that logged out would silently end every user's
     * session on each deploy. Call {@see AxiamClient::logout()} first if ending the
     * session is what you want.
     *
     * After this returns, every operation on this client throws a
     * {@see \Axiam\Sdk\Core\NetworkError} rather than silently reconnecting.
     */
    public function close(): void
    {
        $this->closed = true;
        $this->decisionMemo->clear();
    }

    /**
     * The CONTRACT.md §27 management surface: 146 operations across 24 namespaces.
     *
     * `$client->management()->users()->listItems()`. Built on the same Guzzle client that
     * carries {@see \Axiam\Sdk\Rest\AuthMiddleware} and
     * {@see \Axiam\Sdk\Rest\RefreshMiddleware}, so §27.8's "the generated layer sits on
     * the SDK's existing request path" holds by construction rather than by convention.
     *
     * Memoised: the returned object holds only the transport and the client's default
     * scope, and handing back a new one per call would make `management() !==
     * management()` for no benefit. This is not a §27.4 rule 10 violation — that rule
     * forbids caching RESPONSES, and nothing here caches one.
     */
    public function management(): \Axiam\Sdk\Management\ManagementApi
    {
        $this->ensureOpen();

        return $this->management ??= new \Axiam\Sdk\Management\ManagementApi(
            new \Axiam\Sdk\Management\ManagementTransport(
                $this->authzHttp,
                $this->session,
                $this->telemetry,
                $this->retryEnabled,
            ),
            $this->orgId,
            $this->tenantUuid,
        );
    }

    /**
     * The organization UUID §27 routes substitute for `{org_id}`, or `null` when the
     * client was constructed without one (§27.4 rule 3).
     *
     * Public because §27 has routes where `{org_id}` names the entity being ADMINISTERED
     * rather than the calling context — the signing CAs under `caCertificates` — and
     * those take it as an ordinary argument. Without this accessor a caller had no way to
     * pass the same identifier the implicit routes use.
     */
    public function resolvedOrgId(): ?string
    {
        return $this->orgId;
    }

    /**
     * The tenant UUID §27 routes substitute for `{tenant_id}`, or `null` when the client
     * was constructed without one (§27.4 rule 3).
     *
     * This is the UUID, never the `$tenant` SLUG the client is constructed with: §5's
     * `X-Tenant-ID` header takes the slug, but a `{tenant_id}` path segment takes the
     * UUID, and the two are not interchangeable.
     */
    public function resolvedTenantId(): ?string
    {
        return $this->tenantUuid;
    }

    /**
     * Throws if {@see AxiamClient::close()} has been called (§18.1 rule 4).
     *
     * Use-after-close is an error, not a silent reconnect: a client that quietly
     * rebuilt its transport would make `close()` meaningless and hide the lifecycle
     * bug that caused the call.
     */
    private function ensureOpen(): void
    {
        if ($this->closed) {
            throw \Axiam\Sdk\Core\NetworkError::fromMessage(
                'client is closed: this AxiamClient was shut down with close()',
            );
        }
    }

    /**
     * Drops memoized decisions (§17.1 rule 9).
     *
     * Entries are keyed by subject rather than session, so a re-authentication as a
     * *different* principal would otherwise inherit the previous one's decisions.
     */
    private function onCredentialChange(): void
    {
        $this->decisionMemo->clear();
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
        $this->ensureOpen();
        $this->onCredentialChange();
        // postAllowingErrorStatus, not post(): §25.2 rule 1 gives 403 a specific,
        // non-error meaning here, and Guzzle's default http_errors would turn it into the
        // same exception shape as every other failure before the body could be read.
        $response = $this->postAllowingErrorStatus(self::LOGIN_PATH, $this->loginBody($email, $password));

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
        $this->ensureOpen();
        $this->onCredentialChange();
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
        $this->ensureOpen();
        $this->onCredentialChange();
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
        $this->ensureOpen();
        $this->onCredentialChange();
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
        $this->ensureOpen();
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
        $this->ensureOpen();
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
     * `POST /oauth2/par` (CONTRACT.md §26.1) — push the authorization request over the
     * back channel and get an opaque handle to redirect with.
     *
     * PAR moves the authorization request off the browser: instead of putting `scope`,
     * `redirect_uri`, `state` and the PKCE challenge into a URL the user agent carries,
     * the client POSTs them straight to AXIAM and puts an opaque `request_uri` in the
     * redirect, so what travels through the browser is a random string that cannot be
     * edited into meaning something else.
     *
     * **Required for a FAPI 2.0 client** (§21.1). Not retried, being a POST that creates
     * server state (§26.2 rule 4).
     *
     * @param string|list<string>|null $scope
     */
    public function oidcPar(
        AuthorizationRequest $request,
        string $redirectUri,
        ?OidcConfiguration $configuration = null,
        string|array|null $scope = null,
        ?string $tenantId = null,
    ): PushedAuthorizationRequest {
        $this->ensureOpen();

        return $this->oidc->oidcPar($request, $redirectUri, $configuration, $scope, $tenantId);
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
     * `POST /oauth2/device_authorization` (CONTRACT.md §14.1) — start the device grant
     * and obtain the code pair.
     *
     * **Unauthenticated by design**: a device that cannot show a browser also cannot hold
     * a client secret, so this never sends `client_secret` and never refuses a client
     * built without one.
     *
     * @throws AuthError when the discovery document advertises no
     *                   `device_authorization_endpoint`.
     */
    public function deviceAuthorize(
        ?string $scope = null,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
    ): DeviceAuthorization {
        return $this->oidc->deviceAuthorize($scope, $tenantId, $configuration);
    }

    /**
     * `POST /oauth2/token` with the device-code grant (CONTRACT.md §14.1) — **one** poll
     * attempt, for an application driving its own loop. Most callers want
     * {@see self::deviceLogin()}.
     */
    public function devicePoll(
        Sensitive|string $deviceCode,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
    ): OidcTokenSet {
        return $this->oidc->devicePoll($deviceCode, $tenantId, $configuration);
    }

    /**
     * The composed §14.3 helper: start the grant, hand the caller the user code (before
     * the first poll), poll to completion.
     *
     * Returns the token set; `$adoptAsCredential` is the same opt-in flag
     * {@see self::loginClientCredentials()} uses (§14.3 rule 4, contract 1.7).
     *
     * @param callable(DeviceAuthorization):void $onUserCode Invoked before the first poll.
     * @param (callable(int):void)|null $sleep Injectable sleeper, for tests.
     */
    public function deviceLogin(
        callable $onUserCode,
        ?string $scope = null,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
        bool $adoptAsCredential = false,
        ?callable $sleep = null,
    ): OidcTokenSet {
        return $this->oidc->deviceLogin($onUserCode, $scope, $tenantId, $configuration, $adoptAsCredential, $sleep);
    }

    /**
     * `POST /oauth2/token` with the RFC 8693 grant (CONTRACT.md §15.1) — exchange a token
     * for a **narrower** one.
     *
     * Requires confidential-client credentials. Never defaults `$actorToken`, never
     * auto-narrows after `invalid_scope`, never adopts the result.
     *
     * @param list<string>|null $scopes
     * @param string $subjectTokenType What kind of token `$subjectToken` is. Required (§15.1):
     *        {@see OidcClient::ACCESS_TOKEN_TYPE} for an AXIAM access token, or
     *        {@see OidcClient::JWT_TOKEN_TYPE} for a trusted external issuer's JWT (§15.7).
     *        Never inferred from the token.
     * @throws AuthError when no `oidcClientSecret` was configured.
     */
    public function tokenExchange(
        Sensitive|string $subjectToken,
        string $subjectTokenType,
        Sensitive|string|null $actorToken = null,
        ?array $scopes = null,
        ?string $audience = null,
        ?string $resource = null,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
    ): ExchangedToken {
        return $this->oidc->tokenExchange(
            $subjectToken,
            $subjectTokenType,
            $actorToken,
            $scopes,
            $audience,
            $resource,
            $tenantId,
            $configuration,
        );
    }

    /**
     * `POST /uma2/rreg/resource_set` (CONTRACT.md §20.1) — register a UMA resource set.
     *
     * The returned id **is** the AXIAM resource id, usable directly as a
     * {@see RequestedPermission}'s `$resourceId`.
     *
     * @param Sensitive|string $pat A client-credentials token carrying `uma_protection`
     *        (§20.2 rule 1) — never this client's session token.
     * @param list<string> $resourceScopes
     */
    public function umaRegisterResource(
        Sensitive|string $pat,
        string $name,
        ?string $type = null,
        array $resourceScopes = [],
    ): ResourceSet {
        return $this->oidc->umaRegisterResource($pat, $name, $type, $resourceScopes);
    }

    /** `GET /uma2/rreg/resource_set/{id}` (CONTRACT.md §20.1). */
    public function umaReadResource(Sensitive|string $pat, string $id): ResourceSet
    {
        return $this->oidc->umaReadResource($pat, $id);
    }

    /**
     * `PUT /uma2/rreg/resource_set/{id}` (CONTRACT.md §20.1) — replace a resource set.
     *
     * `$resourceScopes` **replaces** the declared list rather than merging with it
     * (§20.2 rule 8), so omitting a scope removes it.
     *
     * @param list<string> $resourceScopes
     */
    public function umaUpdateResource(
        Sensitive|string $pat,
        string $id,
        string $name,
        ?string $type = null,
        array $resourceScopes = [],
    ): ResourceSet {
        return $this->oidc->umaUpdateResource($pat, $id, $name, $type, $resourceScopes);
    }

    /** `DELETE /uma2/rreg/resource_set/{id}` (CONTRACT.md §20.1). */
    public function umaDeleteResource(Sensitive|string $pat, string $id): void
    {
        $this->oidc->umaDeleteResource($pat, $id);
    }

    /**
     * `GET /uma2/rreg/resource_set` (CONTRACT.md §20.1) — the ids this client registered.
     *
     * @return list<string>
     */
    public function umaListResources(Sensitive|string $pat): array
    {
        return $this->oidc->umaListResources($pat);
    }

    /**
     * `POST /uma2/perm` (CONTRACT.md §20.1) — mint a permission ticket.
     *
     * @param list<RequestedPermission> $permissions
     */
    public function umaRequestTicket(Sensitive|string $pat, array $permissions): Sensitive
    {
        return $this->oidc->umaRequestTicket($pat, $permissions);
    }

    /**
     * The UMA ticket grant (CONTRACT.md §20.1) — redeem a permission ticket for an RPT.
     *
     * **Never retried** (§20.2 rule 6, the one documented exception to §16): a ticket is
     * spent whether or not the exchange succeeded, so a retry is a second redemption. A
     * failure surfaces; request a *new* ticket. The result is never adopted as this
     * client's credentials and carries no refresh token.
     *
     * @throws AuthError when no `oidcClientSecret` was configured.
     */
    public function umaExchangeTicket(
        Sensitive|string $ticket,
        Sensitive|string $claimToken,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
    ): RequestingPartyToken {
        return $this->oidc->umaExchangeTicket($ticket, $claimToken, $tenantId, $configuration);
    }

    /**
     * Parse a `WWW-Authenticate: UMA …` header (CONTRACT.md §20.3) — local computation,
     * and deliberately **no** exchange of the ticket it finds.
     */
    public function umaParseChallenge(string $header): ?UmaChallenge
    {
        return $this->oidc->umaParseChallenge($header);
    }

    /** Format a `WWW-Authenticate: UMA` header (CONTRACT.md §20.3, emit half). */
    public function umaChallengeHeader(string $realm, string $asUri, Sensitive|string $ticket): string
    {
        return $this->oidc->umaChallengeHeader($realm, $asUri, $ticket);
    }

    /**
     * Build the RP-initiated logout URL to redirect the user agent to (CONTRACT.md
     * §12.7.2). Does **not** clear this client's own session.
     *
     * @throws AuthError when the discovery document advertises no `end_session_endpoint`.
     */
    public function logoutUrl(
        Sensitive|string $idToken,
        ?string $postLogoutRedirectUri = null,
        ?string $state = null,
        ?OidcConfiguration $configuration = null,
    ): string {
        return $this->oidc->logoutUrl($idToken, $postLogoutRedirectUri, $state, $configuration);
    }

    /**
     * Verify a back-channel logout token the OP pushed to this application's
     * `backchannel_logout_uri` (CONTRACT.md §12.7.3).
     *
     * Returns the `sid`/`sub`/`jti` the token names — never a bare `bool`, because the RP
     * has to know *which* session to end. **Dedup on `jti` yourself**: delivery is
     * at-least-once.
     *
     * @throws AuthError on any failed check.
     */
    public function verifyLogoutToken(
        string $logoutToken,
        ?OidcConfiguration $configuration = null,
    ): VerifiedLogoutToken {
        return $this->oidc->verifyLogoutToken($logoutToken, $configuration);
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
    // Verification seams: request guards (§10.1 rule 8) vs. outbound calls (D-02)
    // ------------------------------------------------------------------

    /**
     * Verify an INBOUND caller's token and nothing else — the seam every request guard
     * must use (CONTRACT.md §10.1 rule 8). Delegates straight to {@see JwksVerifier::verify()},
     * which applies the full §10.1 minimum local-verification set, and returns `null` on
     * any failure with **no fallback to another credential**.
     *
     * This is deliberately the *only* verification entry point offered to the framework
     * bridges. Its sibling {@see self::verifyLocallyOrFallback()} substitutes this client's
     * own session when verification fails, which is correct for the SDK's outbound calls
     * and an authentication bypass in a request guard — see SEC-085.
     *
     * @return array<string,mixed>|null Verified claims of the SUPPLIED token, or null.
     */
    public function verifyLocally(string $token, string $tenant): ?array
    {
        return $this->jwksVerifier->verify($token, $tenant);
    }

    /**
     * Local-first JWT verification with a reactive-refresh fallback (D-02) — for the SDK's
     * own OUTBOUND calls, where the token being verified is this client's own and refreshing
     * it is the intended recovery. Tries {@see JwksVerifier::verify()} first (no network call
     * on the happy path); if that fails (expired/unknown-kid/invalid token), attempts the
     * shared single-flight refresh (§9, D-06) and re-verifies the FRESH access token. Returns
     * `null` — never unverified claims — on any failure.
     *
     * ⚠ **Never call this from a request guard.** The fallback re-verifies *a different
     * credential* — this client's own session, typically a service account — so a caller
     * presenting an expired, foreign-tenant or forged token would be admitted under the
     * application's own identity (SEC-085). Request guards must call
     * {@see self::verifyLocally()}, which decides on the caller's credential alone.
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
    // OPAQUE, RFC 9807 (CONTRACT.md §23)
    // ------------------------------------------------------------------

    /**
     * `POST /api/v1/auth/opaque/login/start` followed by `/finish` — OPAQUE login, RFC 9807
     * (CONTRACT.md §23).
     *
     * A sibling of {@see self::login()}, not a replacement. It takes the same arguments and
     * returns the same {@see LoginResult}, MFA branch included, so an application can switch a
     * tenant to OPAQUE without touching its own code.
     *
     * **What this does that `login` does not.** The password never leaves this process. What
     * crosses the wire is a blinded group element and a MAC, neither useful without the account's
     * registration record *and* the tenant's OPRF seed — so a TLS-terminating proxy, an
     * accidentally verbose request log, or a heap dump on the server cannot capture a plaintext
     * password, because the server never has one. It also means a stolen record database is not
     * offline-crackable on its own, which is the pre-computation resistance SRP could not offer.
     * It does **not** protect against a compromised AXIAM server.
     *
     * **PHP is no longer doubly conditional.** The SRP client this replaces needed a bignum
     * extension *and* a tenant on `pbkdf2_sha256`, because no PHP runtime offers Argon2id with a
     * caller-supplied salt — so the AXIAM default was, for PHP, unreachable. The key stretching
     * now happens inside `libaxiam_opaque_ffi`, so the only remaining condition is that the
     * library and `ext-ffi` are present, which {@see self::opaqueAvailable()} reports.
     *
     * **One round trip, and no server-proof step.** SRP had to guess a group before the server
     * named one and restart the exchange if it guessed wrong; `KE1` does not depend on the
     * key-stretching function. And where the old §23.3 rule 6 had to mandate an `M2` check in
     * capitals — because skipping it kept only half the protocol — RFC 9807's AKE authenticates
     * the server during the handshake, so opening `KE2` *is* the proof that it holds the record.
     *
     * **Zeroization.** PHP strings are immutable and the runtime copies them freely, so this SDK
     * cannot clear the password — §23.3 rule 8 requires saying so rather than implying a
     * guarantee it cannot keep.
     *
     * **A failed `KE2` is not always the end (§23.4 rule 7, contract 1.29).** Nothing is ever sent
     * to `login/finish` when the envelope does not open, but what happens next depends on the
     * `mode` the `login/start` response named, and on nothing else. Under `"optional"` this method
     * retries over {@see self::login()} with the same credentials and returns that call's outcome
     * — its success, or its error. Under `"required"`, and for a response that carried no `mode`
     * at all (a server older than the field), the failure is an {@see AuthError} and there is no
     * retry. `optional` is the state a tenant lives in for the whole of a migration: every account
     * has no registration record the moment OPAQUE is enabled and acquires one only when its
     * password is next set, so treating the failed exchange as final would lock out every user of
     * the tenant. See {@see OpaqueMode} for why `mode` is **not** downgrade protection.
     *
     * @throws NetworkError if the tenant has OPAQUE disabled (the endpoint answers `404` — a
     *                      property of the tenant, not of any user), if `ext-ffi` or
     *                      `libaxiam_opaque_ffi` is absent, or if the server names a
     *                      key-stretching function this SDK cannot ask for. Deliberately not
     *                      {@see AuthError}: reporting a configuration gap as a credential
     *                      failure would send a user off to reset a password that works, and
     *                      would stop a caller falling back to {@see self::login()}
     * @throws AuthError    for a wrong password, an account that does not exist, and a server
     *                      that does not hold the record — indistinguishable by design. **Nothing
     *                      is sent to `login/finish` in that case** (§23.4 rule 7). Raised under
     *                      `mode: "required"` and under a response with no `mode`; under
     *                      `"optional"` the exchange is retried over {@see self::login()} first
     *                      and this carries that call's failure instead
     */
    public function loginOpaque(string $usernameOrEmail, string $password): LoginResult
    {
        $this->ensureOpen();
        $this->onCredentialChange();

        $exchange = Opaque::startLogin($password);

        try {
            $body = $this->opaqueWorkspaceBody();
            $body['username_or_email'] = $usernameOrEmail;
            $body['ke1'] = $exchange->ke1();

            $started = $this->opaqueStart(self::OPAQUE_LOGIN_START_PATH, $body, 'login/start');

            if (!\is_string($started['ke2'] ?? null)) {
                throw NetworkError::fromMessage('OPAQUE: login/start returned no `ke2`');
            }

            $mode = OpaqueMode::fromWire($started);

            try {
                $ke3 = $exchange->finish($password, $started['ke2'], KsfParams::fromWire($started));
            } catch (AuthError $credentialFailure) {
                // §23.4 rule 7. The envelope failing to open is the whole of the
                // client's authentication check, so KE3 is never sent -- but it is
                // NOT always the end of the login. Under `optional` an account with
                // no registration record is the ordinary case rather than an error:
                // every account has none the moment an operator enables OPAQUE, and
                // acquires one only as it next sets a password. Treating the failed
                // exchange as final there locks out every user of a tenant
                // mid-migration, which is the state `optional` exists to serve.
                //
                // `required` (and an absent `mode`, i.e. a server older than the
                // field) fails closed: /auth/login answers 403 opaque_required for
                // every principal in the tenant, so a retry would put a plaintext
                // password on the wire only to be refused.
                if (!$mode->allowsPasswordFallback()) {
                    throw $credentialFailure;
                }

                $ke3 = null;
            }
        } finally {
            // A no-op once finish() has spent the handle; the point is the paths
            // where it has not -- a refused KSF, a malformed response.
            $exchange->close();
        }

        if ($ke3 === null) {
            // The plaintext path, unmodified -- same body construction, same result
            // handling, same errors -- so the two logins cannot drift. Its outcome is
            // this call's outcome, success or failure.
            return $this->login($usernameOrEmail, $password);
        }

        $response = $this->post($this->plainHttp, self::OPAQUE_LOGIN_FINISH_PATH, [
            'opaque_session' => \is_string($started['opaque_session'] ?? null)
                ? $started['opaque_session']
                : '',
            'ke3' => $ke3,
        ]);

        $status = $response->getStatusCode();
        if ($status !== 200 && $status !== 202) {
            throw ErrorMapper::fromResponse($response, 'OPAQUE login/finish failed');
        }

        return $this->handleLoginResponse($response);
    }

    /**
     * Builds a registration record for `$password`, to send with any request that sets one:
     * `POST /api/v1/users`, `/auth/password/change`, `/auth/reset/confirm` and
     * `/admin/bootstrap`.
     *
     * The server cannot build this — it never sees the plaintext — so it has to arrive with the
     * request or not at all.
     *
     * Unlike the `srpEnrollment` it replaces this performs I/O: one `register/start` round trip.
     * OPAQUE's envelope is sealed under the server's oblivious PRF, so there is no offline
     * computation that produces a valid record.
     *
     * Note the parameters that are gone. There is no `$identity`: the SRP version required the
     * account's USERNAME, and an email there produced a verifier no login could ever satisfy,
     * whereas a record binds to a credential identifier the server chooses. And there is no
     * `$group` or `$params`, because those come from the `register/start` response — a caller
     * cannot pick a cost the server will not honour.
     *
     * @throws NetworkError if the tenant has OPAQUE disabled, if `ext-ffi` or
     *                      `libaxiam_opaque_ffi` is absent, or if the server names a
     *                      key-stretching function this SDK cannot ask for
     */
    public function opaqueEnrollment(string $password): OpaqueEnrollment
    {
        $this->ensureOpen();

        $exchange = Opaque::startRegistration($password);

        try {
            $body = $this->opaqueWorkspaceBody();
            $body['registration_request'] = $exchange->request();

            $started = $this->opaqueStart(
                self::OPAQUE_REGISTER_START_PATH,
                $body,
                'register/start'
            );

            $record = $exchange->finish(
                $password,
                \is_string($started['registration_response'] ?? null)
                    ? $started['registration_response']
                    : '',
                KsfParams::fromWire($started),
            );
        } finally {
            $exchange->close();
        }

        return new OpaqueEnrollment(
            \is_string($started['opaque_session'] ?? null) ? $started['opaque_session'] : '',
            $record,
        );
    }

    /**
     * Whether this installation can perform OPAQUE (§23.2).
     *
     * PHP remains the AXIAM SDK language where this genuinely answers `false` — but for a
     * different and simpler reason than before. The SRP equivalent was `false` when neither
     * `ext-gmp` nor `ext-bcmath` was present, and even a `true` there did not promise every
     * tenant would work: an `argon2id` tenant was refused at login time, because no PHP runtime
     * offers Argon2id with a caller-supplied salt. That second condition is gone. The key
     * stretching happens inside `libaxiam_opaque_ffi`, so a `true` here means every tenant works.
     */
    public function opaqueAvailable(): bool
    {
        return Opaque::available();
    }

    /**
     * Sends one `/start` request and returns the decoded response.
     *
     * Shared by both OPAQUE paths so the meaning of a failure cannot drift between them. A `404`
     * is a property of the tenant ("OPAQUE is off here"), not of the user and not of the
     * credentials — so it is a {@see NetworkError} a caller can fall back on, never an
     * {@see AuthError} that would be shown as "invalid password".
     *
     * @param array<string,mixed> $body
     *
     * @return array<string,mixed>
     */
    private function opaqueStart(string $path, array $body, string $what): array
    {
        $response = $this->postAllowingErrorStatus($path, $body);

        if ($response->getStatusCode() === 404) {
            throw NetworkError::fromMessage(
                'OPAQUE: this tenant does not offer OPAQUE (opaque_mode is disabled); ' .
                'use login() instead'
            );
        }
        if ($response->getStatusCode() !== 200) {
            throw ErrorMapper::fromResponse($response, 'OPAQUE ' . $what . ' failed');
        }

        $wire = json_decode((string) $response->getBody(), true);
        if (!\is_array($wire)) {
            throw NetworkError::fromMessage(
                'OPAQUE: the ' . $what . ' response was not a JSON object'
            );
        }

        /** @var array<string,mixed> $wire */
        return $wire;
    }

    /**
     * The tenant/org fields every OPAQUE request carries.
     *
     * Reuses {@see self::loginBody()}'s resolution so the two login paths cannot drift, then
     * drops both the password and the username — the password because that absence is the entire
     * point of the exchange, and the username because `register/start` names no account at all.
     * The login path puts its own back.
     *
     * @return array<string,mixed>
     */
    private function opaqueWorkspaceBody(): array
    {
        $body = $this->loginBody('', '');
        unset($body['password'], $body['username_or_email']);

        return $body;
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

            // H8 fix (SDK bench harness validation): a successful login/
            // verifyMfa establishes the session's FIRST CSRF token (§3
            // non-browser CSRF capture) — without capturing it here, every
            // state-changing call this client ever makes (refresh,
            // checkAccess, batchCheck) omits X-CSRF-Token and fails with
            // "CSRF validation failed" (403), since Session::csrfToken()
            // stays null forever. Session::captureCsrfTokenFromResponse()
            // existed as a public method for exactly this but had no
            // caller anywhere in the codebase.
            $this->session->captureCsrfTokenFromResponse($response);

            return new LoginResult(mfaRequired: false, userId: $userId, tenantId: $this->tenant);
        }

        if ($status === 202) {
            $challengeToken = is_array($wire) ? ($wire['challenge_token'] ?? null) : null;
            if (!is_string($challengeToken) || $challengeToken === '') {
                throw NetworkError::fromResponse($response, 'login: MFA challenge response missing challenge_token');
            }

            return new LoginResult(mfaRequired: true, challengeToken: new Sensitive($challengeToken));
        }

        if ($status === 403) {
            // CONTRACT.md §25.2 rule 1: a 403 carrying mfa_setup_required is an OUTCOME,
            // not a refusal. The tenant requires MFA, this account has none, and the
            // server handed back the token to finish with.
            //
            // Matched on the body's own discriminant rather than the status alone: a
            // genuine authorization refusal is also a 403, and only one of the two
            // carries a setup_token. The body was decoded once above, so a non-matching
            // 403 still falls through to ErrorMapper with the response untouched.
            $setupToken = is_array($wire) ? ($wire['setup_token'] ?? null) : null;
            $flagged = is_array($wire) && ($wire['mfa_setup_required'] ?? false) === true;
            if ($flagged && is_string($setupToken) && $setupToken !== '') {
                return new LoginResult(
                    mfaRequired: false,
                    mfaSetupRequired: true,
                    setupToken: new Sensitive($setupToken),
                );
            }
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
     * `POST` that returns the response whatever its status, instead of throwing on 4xx/5xx.
     *
     * Guzzle's default `http_errors` turns every error status into the same exception shape, which
     * is fine everywhere the status does not change the meaning. It does here: §23 gives `404` a
     * specific, non-error meaning on the OPAQUE `/start` endpoints ("this tenant has OPAQUE
     * disabled"), and that has to be told apart from a genuine transport failure.
     *
     * @param array<string,mixed> $body
     */
    private function postAllowingErrorStatus(string $path, array $body): ResponseInterface
    {
        try {
            return $this->plainHttp->post($path, ['json' => $body, 'http_errors' => false]);
        } catch (GuzzleException $e) {
            throw NetworkError::fromException($e, $path . ' failed');
        }
    }


    // ------------------------------------------------------------------
    // §25 Account lifecycle and MFA enrolment
    // ------------------------------------------------------------------

    /**
     * `POST /api/v1/auth/mfa/enroll` (CONTRACT.md §25.1) — start voluntary TOTP enrolment for
     * the signed-in user.
     *
     * Changes nothing about the current session. In particular it does **not** clear the §17
     * decision memo: the subject has not changed, and discarding a warm memo on an unrelated
     * profile action costs a round trip on every check that follows (§25.2 rule 3).
     */
    public function mfaEnroll(): MfaEnrollment
    {
        $this->ensureOpen();

        return $this->readMfaEnrollment(
            $this->postAllowingErrorStatus(self::MFA_ENROLL_PATH, []),
            'mfaEnroll',
        );
    }

    /**
     * `POST /api/v1/auth/mfa/confirm` (CONTRACT.md §25.1) — activate the factor
     * {@see self::mfaEnroll()} offered. Returns whether MFA is now enabled.
     */
    public function mfaConfirm(string $totpCode): bool
    {
        $this->ensureOpen();
        $http = $this->postAllowingErrorStatus(self::MFA_CONFIRM_PATH, ['totp_code' => $totpCode]);
        if ($http->getStatusCode() !== 200) {
            throw ErrorMapper::fromResponse($http, 'mfaConfirm failed');
        }

        $wire = json_decode((string) $http->getBody(), true);

        return is_array($wire) && ($wire['mfa_enabled'] ?? false) === true;
    }

    /**
     * `POST /api/v1/auth/mfa/setup/enroll` (CONTRACT.md §25.1) — start the enrolment a
     * {@see self::login()} demanded.
     *
     * Reached when `login()` returns {@see LoginResult::$mfaSetupRequired}: the tenant requires
     * MFA and this account has none. There is no session yet — the setup token *is* the
     * credential.
     */
    public function mfaSetupEnroll(Sensitive|string $setupToken): MfaEnrollment
    {
        $this->ensureOpen();

        return $this->readMfaEnrollment(
            $this->postAllowingErrorStatus(self::MFA_SETUP_ENROLL_PATH, [
                'setup_token' => $this->reveal($setupToken),
            ]),
            'mfaSetupEnroll',
        );
    }

    /**
     * `POST /api/v1/auth/mfa/setup/confirm` (CONTRACT.md §25.1) — finish forced enrolment and,
     * with it, the login that was interrupted.
     *
     * Adopts credentials exactly as {@see self::login()} does, because it *is* the completion
     * of a login (§25.2 rule 2) — including capturing the session's first CSRF token.
     */
    public function mfaSetupConfirm(Sensitive|string $setupToken, string $totpCode): LoginResult
    {
        $this->ensureOpen();
        $this->onCredentialChange();

        $http = $this->postAllowingErrorStatus(self::MFA_SETUP_CONFIRM_PATH, [
            'setup_token' => $this->reveal($setupToken),
            'totp_code' => $totpCode,
        ]);

        return $this->handleLoginResponse($http);
    }

    /**
     * `POST /api/v1/auth/verify-email` (CONTRACT.md §25.1).
     *
     * Unauthenticated: a user whose address is unverified may have no session at all.
     * `$tenantId` is a **body** field here — this is not an `/oauth2` endpoint, so §12.1 rule 2's
     * query-parameter convention does not reach it.
     */
    public function verifyEmail(Sensitive|string $token, string $tenantId): void
    {
        $this->ensureOpen();
        $this->postExpectingNoContent(self::VERIFY_EMAIL_PATH, [
            'token' => $this->reveal($token),
            'tenant_id' => $tenantId,
        ], 'verifyEmail');
    }

    /** `POST /api/v1/auth/resend-verification` (CONTRACT.md §25.1). */
    public function resendVerification(string $email, string $tenantId): void
    {
        $this->ensureOpen();
        $this->postExpectingNoContent(self::RESEND_VERIFICATION_PATH, [
            'email' => $email,
            'tenant_id' => $tenantId,
        ], 'resendVerification');
    }

    /**
     * `POST /api/v1/auth/reset` (CONTRACT.md §25.1) — ask for a reset mail.
     *
     * **Returns normally whether or not the address exists**, and this SDK exposes no way to
     * tell the two apart. That is not an omission to improve on: a client that surfaced a
     * "no such user" state — even one inferred from timing — would turn the endpoint into the
     * account-enumeration oracle its uniform response exists to prevent (§25.4).
     */
    public function requestPasswordReset(PasswordResetRequest $request): void
    {
        $this->ensureOpen();

        $body = ['email' => $request->email];
        $orgSlug = $request->orgSlug ?? $this->orgSlug;
        if ($orgSlug !== null) {
            $body['org_slug'] = $orgSlug;
        }
        if ($request->tenantId !== null) {
            $body['tenant_id'] = $request->tenantId;
        } else {
            $body['tenant_slug'] = $request->tenantSlug ?? $this->tenant;
        }

        $this->postExpectingNoContent(self::RESET_PATH, $body, 'requestPasswordReset');
    }

    /**
     * `GET /api/v1/auth/reset/context` (CONTRACT.md §25.1) — the OPAQUE policy for the account
     * a reset token belongs to.
     *
     * Call this before {@see self::confirmPasswordReset()} on any tenant that might have §23
     * enabled: the client has to build a registration record, and building one needs parameters
     * it cannot know before it has a token to ask with. Sending a plaintext password to a
     * tenant in `opaque_mode: required` is refused, and refused late (§25.4 rule 1).
     *
     * A `404` means unknown, expired **or** already-consumed, deliberately without
     * distinguishing them; this SDK does not distinguish them either (§25.4 rule 3).
     */
    public function passwordResetContext(Sensitive|string $token): PasswordResetContext
    {
        $this->ensureOpen();

        try {
            // The token travels as a query PARAMETER, built through Guzzle's `query` option
            // rather than string concatenation: a token spliced onto "?token=" unescaped can
            // end the query early, and one escaped into the PATH 404s in a way that reads
            // exactly like an expired token.
            $http = $this->plainHttp->get(self::RESET_CONTEXT_PATH, [
                'query' => ['token' => $this->reveal($token)],
                'http_errors' => false,
            ]);
        } catch (GuzzleException $e) {
            throw NetworkError::fromException($e, self::RESET_CONTEXT_PATH . ' failed');
        }

        if ($http->getStatusCode() !== 200) {
            throw ErrorMapper::fromResponse($http, 'passwordResetContext failed');
        }

        $wire = json_decode((string) $http->getBody(), true);
        $opaque = is_array($wire) ? ($wire['opaque'] ?? null) : null;

        return new PasswordResetContext(is_array($opaque) ? $opaque : null);
    }

    /** `POST /api/v1/auth/reset/confirm` (CONTRACT.md §25.1) — set the new password. */
    public function confirmPasswordReset(PasswordResetConfirmation $confirmation): void
    {
        $this->ensureOpen();

        $body = [
            'token' => $this->reveal($confirmation->token),
            'new_password' => $this->reveal($confirmation->newPassword),
            'tenant_id' => $confirmation->tenantId,
        ];
        if ($confirmation->opaque !== null) {
            $body['opaque'] = $confirmation->opaque;
        }

        $this->postExpectingNoContent(self::RESET_CONFIRM_PATH, $body, 'confirmPasswordReset');
    }

    private function readMfaEnrollment(ResponseInterface $http, string $operation): MfaEnrollment
    {
        if ($http->getStatusCode() !== 200) {
            throw ErrorMapper::fromResponse($http, $operation . ' failed');
        }

        $wire = json_decode((string) $http->getBody(), true);
        if (!is_array($wire)) {
            throw NetworkError::fromResponse($http, $operation . ': response body is not a JSON object');
        }

        return new MfaEnrollment(
            secretBase32: new Sensitive((string) ($wire['secret_base32'] ?? '')),
            totpUri: new Sensitive((string) ($wire['totp_uri'] ?? '')),
        );
    }

    /** @param array<string,mixed> $body */
    private function postExpectingNoContent(string $path, array $body, string $operation): void
    {
        $http = $this->postAllowingErrorStatus($path, $body);
        $status = $http->getStatusCode();
        if ($status !== 200 && $status !== 202 && $status !== 204) {
            throw ErrorMapper::fromResponse($http, $operation . ' failed');
        }
    }


    // ------------------------------------------------------------------
    // §24 WebAuthn / passkeys — the relying-party layer
    //
    // PHP runs on a server, which has no authenticator, so §24.6b's linked-API
    // helper is deliberately absent: rule 2 forbids emulating one in software,
    // and a "credential" held in process memory is not a second factor. What is
    // here is the half that talks to AXIAM, plus §24.6a's JSON bridge — which is
    // what lets the browser half of a PHP relying party run the ceremony with
    // its own platform API and hand the response string straight back.
    // ------------------------------------------------------------------

    /**
     * `POST /api/v1/auth/webauthn/register/start` (CONTRACT.md §24.1) — begin enrolling a
     * passkey for the signed-in user.
     *
     * Requires a session, and refuses **client-side with no wire call** when there is none —
     * the shape §1.1 rule 3 requires of `getUserInfo`.
     *
     * The returned options are the server's, untouched (§24.0). A `503` here means the
     * tenant's attestation policy needs FIDO metadata the server cannot reach: a configuration
     * state, not a transient one, and §24.4 rule 2 deliberately does not retry it.
     */
    public function webauthnRegisterStart(): WebauthnChallenge
    {
        $this->ensureOpen();
        $this->requireWebauthnSession('webauthnRegisterStart');

        return $this->webauthnStart(self::WEBAUTHN_REGISTER_START_PATH, '{}');
    }

    /**
     * `POST /api/v1/auth/webauthn/register/finish` (CONTRACT.md §24.1) — hand the
     * authenticator's answer back and store the credential.
     *
     * `$response` is the platform's own response JSON, **verbatim** (§24.6a rule 2):
     * `credential.toJSON()` from a browser, or `registrationResponseJson` from Android's
     * Credential Manager relayed by a mobile client. It reaches the wire byte for byte,
     * because re-encoding a signed buffer is three chances to corrupt it in service of
     * nothing.
     */
    public function webauthnRegisterFinish(
        Sensitive|string $stateToken,
        string $credentialName,
        string $response,
    ): WebauthnCredential {
        $this->ensureOpen();
        $this->requireWebauthnSession('webauthnRegisterFinish');

        $body = $this->webauthnFinishBody(
            $stateToken,
            $response,
            'webauthnRegisterFinish',
            ['credential_name' => $credentialName],
        );

        $http = $this->postRawJson(self::WEBAUTHN_REGISTER_FINISH_PATH, $body);
        $status = $http->getStatusCode();
        if ($status !== 200 && $status !== 201) {
            throw $this->registerFinishError($http);
        }

        $wire = $this->webauthnWire($http, 'webauthnRegisterFinish');
        $lastUsed = $wire['last_used_at'] ?? null;

        return new WebauthnCredential(
            id: (string) ($wire['id'] ?? ''),
            credentialId: (string) ($wire['credential_id'] ?? ''),
            name: (string) ($wire['name'] ?? ''),
            credentialType: (string) ($wire['credential_type'] ?? ''),
            createdAt: (string) ($wire['created_at'] ?? ''),
            lastUsedAt: is_string($lastUsed) && $lastUsed !== '' ? $lastUsed : null,
        );
    }

    /**
     * `POST /api/v1/auth/webauthn/authenticate/start` (CONTRACT.md §24.1) — begin the
     * **second-factor** ceremony.
     *
     * Continues a {@see self::login()} that answered `mfaRequired` with `"webauthn"` among its
     * available methods; `$challengeToken` is that login's token. A different flow from
     * {@see self::webauthnDiscoverableStart()}, not the same one with a flag (§24.2) — which
     * is why the token is required here and absent there.
     */
    public function webauthnAuthenticateStart(Sensitive|string $challengeToken): WebauthnChallenge
    {
        $this->ensureOpen();
        $body = json_encode(
            ['challenge_token' => $this->reveal($challengeToken)],
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
        );

        return $this->webauthnStart(self::WEBAUTHN_AUTH_START_PATH, $body);
    }

    /**
     * `POST /api/v1/auth/webauthn/authenticate/finish` (CONTRACT.md §24.1).
     *
     * On success the client is signed in: the server sets the same cookie triple
     * `POST /api/v1/auth/login` sets, and the §17 decision memo is cleared because the subject
     * changed (§24.3).
     */
    public function webauthnAuthenticateFinish(Sensitive|string $stateToken, string $response): WebauthnLoginResult
    {
        return $this->webauthnFinish(
            self::WEBAUTHN_AUTH_FINISH_PATH,
            $stateToken,
            $response,
            'webauthnAuthenticateFinish',
        );
    }

    /**
     * `POST /api/v1/auth/webauthn/authenticate/discoverable/start` (CONTRACT.md §24.1) —
     * begin the usernameless ceremony.
     *
     * A **primary factor**: nothing precedes it, `allowCredentials` comes back empty, and the
     * assertion itself identifies the user. Pass `null` for `$workspace` to have it filled
     * from this client's own configured identity.
     *
     * Unlike `authenticate/finish`, `discoverable/finish` fires the `login.post_auth` reactor
     * hook (§22.5) — the former continues a login already gated at its password step, and this
     * one has no such step.
     */
    public function webauthnDiscoverableStart(?WebauthnWorkspace $workspace = null): WebauthnChallenge
    {
        $this->ensureOpen();

        return $this->webauthnStart(
            self::WEBAUTHN_DISCOVERABLE_START_PATH,
            json_encode($this->webauthnWorkspaceBody($workspace), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
        );
    }

    /**
     * `POST /api/v1/auth/webauthn/authenticate/discoverable/finish` (CONTRACT.md §24.1).
     * Adopts credentials exactly as {@see self::webauthnAuthenticateFinish()} does.
     */
    public function webauthnDiscoverableFinish(Sensitive|string $stateToken, string $response): WebauthnLoginResult
    {
        return $this->webauthnFinish(
            self::WEBAUTHN_DISCOVERABLE_FINISH_PATH,
            $stateToken,
            $response,
            'webauthnDiscoverableFinish',
        );
    }

    /** Runs either `*_start` call and returns the options untouched. */
    private function webauthnStart(string $path, string $body): WebauthnChallenge
    {
        $http = $this->postRawJson($path, $body);
        if ($http->getStatusCode() !== 200) {
            throw ErrorMapper::fromResponse($http, 'webauthn start failed');
        }

        $wire = $this->webauthnWire($http, 'webauthn start');
        $challenge = $wire['challenge'] ?? [];
        $stateToken = $wire['state_token'] ?? '';

        return new WebauthnChallenge(
            challenge: is_array($challenge) ? $challenge : [],
            stateToken: new Sensitive(is_string($stateToken) ? $stateToken : ''),
        );
    }

    /** The shared tail of both authentication ceremonies. */
    private function webauthnFinish(
        string $path,
        Sensitive|string $stateToken,
        string $response,
        string $operation,
    ): WebauthnLoginResult {
        $this->ensureOpen();
        // §17.1 rule 9 / §24.3 rule 4: memo entries are keyed by subject, and this call
        // changes the subject.
        $this->onCredentialChange();

        $http = $this->postRawJson($path, $this->webauthnFinishBody($stateToken, $response, $operation));
        if ($http->getStatusCode() !== 200) {
            throw ErrorMapper::fromResponse($http, $operation . ' failed');
        }

        $this->session->captureCsrfTokenFromResponse($http);
        $wire = $this->webauthnWire($http, $operation);

        return new WebauthnLoginResult(
            accessToken: new Sensitive((string) ($wire['access_token'] ?? '')),
            refreshToken: new Sensitive((string) ($wire['refresh_token'] ?? '')),
            sessionId: (string) ($wire['session_id'] ?? ''),
            expiresIn: (int) ($wire['expires_in'] ?? 0),
        );
    }

    /**
     * Builds a `*_finish` body **as text**, splicing the caller's response JSON in verbatim
     * (§24.0, §24.6a rule 2).
     *
     * Decoding the string and re-encoding it would reorder nothing predictably, round every
     * number through a float, and generally hand the server a byte sequence the authenticator
     * never signed. The one thing this does check is that the string IS a JSON object — the
     * SDK will not POST a body it already knows the server cannot verify.
     *
     * @param array<string,string> $extraFields
     */
    private function webauthnFinishBody(
        Sensitive|string $stateToken,
        string $response,
        string $operation,
        array $extraFields = [],
    ): string {
        $trimmed = trim($response);
        try {
            $parsed = json_decode($trimmed, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            throw new AuthError(sprintf(
                '%s: the authenticator response string is not valid JSON. Pass the platform\'s '
                . 'response JSON verbatim (CONTRACT.md §24.6a). %s',
                $operation,
                $e->getMessage(),
            ));
        }

        if (!is_array($parsed) || array_is_list($parsed)) {
            throw new AuthError(sprintf(
                '%s: the authenticator response must be a JSON object (CONTRACT.md §24.6a).',
                $operation,
            ));
        }

        $fields = ['state_token' => $this->reveal($stateToken)] + $extraFields;
        $pairs = [];
        foreach ($fields as $key => $value) {
            $pairs[] = json_encode($key, JSON_THROW_ON_ERROR) . ':' . json_encode($value, JSON_THROW_ON_ERROR);
        }
        $pairs[] = '"response":' . $trimmed;

        return '{' . implode(',', $pairs) . '}';
    }

    /**
     * §24.1: `register/…` needs a session, and the refusal is raised client-side with **no
     * wire call**.
     *
     * The signal is the cached access token rather than a separate flag: this SDK has never
     * kept one, and a second source of truth for "am I signed in" is a second thing to get out
     * of step with the jar.
     */
    private function requireWebauthnSession(string $operation): void
    {
        if ($this->session->accessToken() === null) {
            throw new AuthError(sprintf(
                '%s requires an authenticated session: enrol a passkey while signed in '
                . '(CONTRACT.md §24.1).',
                $operation,
            ));
        }
    }

    /**
     * §24.4 rule 1: the `403` from `register/finish` is the one whose *body* matters.
     *
     * The generic §2 mapping would raise an authorization error reading
     * "webauthnRegisterFinish failed", which tells the person holding the key nothing they can
     * act on. The tenant's attestation policy rejected *this* authenticator, and the server's
     * message is the only place that says which one would be accepted.
     */
    private function registerFinishError(ResponseInterface $http): \Throwable
    {
        $context = 'webauthnRegisterFinish failed';
        if ($http->getStatusCode() === 403) {
            $wire = json_decode((string) $http->getBody(), true);
            $message = is_array($wire) ? ($wire['message'] ?? null) : null;
            if (is_string($message) && $message !== '') {
                $context .= ': ' . $message;
            }
        }

        return ErrorMapper::fromResponse($http, $context);
    }

    /**
     * Fills the discoverable ceremony's workspace from this client's own configuration when
     * the caller passed none.
     *
     * Only fields that actually have a value are emitted: the server takes either form at
     * either level, and sending `null` for the ones it does not have is indistinguishable from
     * asking it to resolve nothing.
     *
     * @return array<string,string>
     */
    private function webauthnWorkspaceBody(?WebauthnWorkspace $workspace): array
    {
        $orgId = $workspace?->orgId;
        $orgSlug = $workspace?->orgSlug;
        if ($orgId === null && $orgSlug === null) {
            $orgId = $this->orgId;
            $orgSlug = $this->orgSlug;
        }

        if ($orgId !== null) {
            $body = ['org_id' => $orgId];
        } elseif ($orgSlug !== null) {
            $body = ['org_slug' => $orgSlug];
        } else {
            throw new AuthError(
                'webauthnDiscoverableStart needs an organization: construct the client with one, '
                . 'or pass it in the workspace argument (CONTRACT.md §24.1).',
            );
        }

        $tenantId = $workspace !== null ? $workspace->tenantId : null;
        $tenantSlug = $workspace !== null ? $workspace->tenantSlug : null;
        if ($tenantId !== null) {
            $body['tenant_id'] = $tenantId;
        } else {
            $body['tenant_slug'] = $tenantSlug ?? $this->tenant;
        }

        return $body;
    }

    /**
     * Decodes a §24 response body, which is always a JSON object.
     *
     * @return array<string,mixed>
     */
    private function webauthnWire(ResponseInterface $http, string $operation): array
    {
        $wire = json_decode((string) $http->getBody(), true);
        if (!is_array($wire)) {
            throw NetworkError::fromResponse($http, $operation . ': response body is not a JSON object');
        }

        return $wire;
    }

    /**
     * POSTs a body that is already JSON **text**, so the caller's bytes reach the wire
     * unmodified (§24.0). Goes through the same Guzzle client every other REST call uses, so
     * §3 CSRF, §4 cookies, §5 tenant header and §6 TLS all apply.
     */
    private function postRawJson(string $path, string $json): ResponseInterface
    {
        try {
            return $this->plainHttp->post($path, [
                'body' => $json,
                'headers' => ['Content-Type' => 'application/json'],
                'http_errors' => false,
            ]);
        } catch (GuzzleException $e) {
            throw NetworkError::fromException($e, $path . ' failed');
        }
    }

    /** Accepts a secret either wrapped or bare, like every other §12/§20 secret input. */
    private function reveal(Sensitive|string $value): string
    {
        return $value instanceof Sensitive ? $value->reveal() : $value;
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
