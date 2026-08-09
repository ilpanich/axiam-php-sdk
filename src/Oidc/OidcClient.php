<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Auth\JwksVerifier;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\ErrorMapper;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\OAuthProtocolError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Session;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * The OIDC / SSO relying-party engine (CONTRACT.md §12) behind {@see
 * \Axiam\Sdk\AxiamClient}'s nine public `oidc*`/`introspect`/`revoke`/`sso*` methods.
 *
 * Per the T1 TypeScript reference's own judgment call 1 ("Host object"): unlike the
 * TypeScript SDK (whose CI forbids Node-only crypto from leaking into a browser
 * bundle, forcing a separate `OidcClient`), THIS SDK has no such constraint — the
 * canonical §12.2 method names live directly on {@see \Axiam\Sdk\AxiamClient}, exactly
 * as the plan's T8 item says. This class is the internal engine {@see
 * \Axiam\Sdk\AxiamClient} composes (mirroring how it already composes {@see
 * \Axiam\Sdk\AuthzDispatcher} for §1 authz) — never part of the public API surface
 * itself.
 *
 * Everything below is reuse, not reimplementation (§12 forbids forking):
 *   * transport, §4 cookie jar, §5 tenant header, §6 TLS   → the `$http` Guzzle client
 *     ({@see \Axiam\Sdk\AxiamClient}'s OWN `$plainHttp` — AuthMiddleware only, so a 401
 *     from `/oauth2/introspect`/`/oauth2/revoke` structurally can never reach
 *     {@see \Axiam\Sdk\Rest\RefreshMiddleware} and therefore never enters the §9 guard,
 *     §12.3 rule 3);
 *   * §9 single-flight refresh                             → {@see Session::refreshGuard()};
 *   * §12.4 rules 1–2 (alg/kid/signature)                  → {@see JwksVerifier::verifyIdTokenSignature()},
 *     the SAME verifier instance the §10 middleware already uses for AXIAM's own access
 *     tokens (AXIAM's OIDC provider and its own auth server are the SAME origin, so
 *     there is exactly one JWKS to trust — no separate per-`jwks_uri` verifier map is
 *     needed here, unlike a generic multi-issuer RP);
 *   * §12.4 rules 3–6 (issuer/audience/time/nonce)          → {@see IdTokenValidator};
 *   * §7/§12.5 redaction                                    → {@see Sensitive}.
 */
final class OidcClient
{
    public const DISCOVERY_PATH = '/.well-known/openid-configuration';
    public const SSO_START_PATH = '/api/v1/auth/federation/oidc/start';
    public const SSO_CALLBACK_PATH = '/api/v1/auth/federation/oidc/callback';

    /**
     * Minimum — and default — discovery-cache TTL, in seconds. CONTRACT.md §12.3 rule 6
     * sets a floor of 5 minutes; a smaller configured value is raised to it.
     */
    public const MIN_DISCOVERY_TTL_SECONDS = 300;

    /**
     * The eight query parameters `oidcBegin` owns (§12.1 rule 5). Caller-supplied
     * `$extraParams` may add to the authorization request but never override these.
     *
     * @var list<string>
     */
    private const RESERVED_AUTHORIZE_PARAMS = [
        'response_type', 'client_id', 'redirect_uri', 'scope',
        'state', 'nonce', 'code_challenge', 'code_challenge_method',
    ];

    /** Shape of a UUID, used to reject a slug where §12.3 rule 4 requires a UUID. */
    private const UUID_RE = '/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i';

    /** @var array<string, array{document: OidcConfiguration, expiresAt: int}> */
    private array $discoveryCache = [];

    /** @var array<string, PromiseInterface> */
    private array $discoveryInFlight = [];

    private readonly int $discoveryTtlSeconds;

    private readonly int $clockSkewSec;

    /**
     * @param Client $http AuthMiddleware ONLY — never RefreshMiddleware (§12.3 rule 3/rule 4).
     * @param string $baseUrl The AXIAM server base URL this engine's client is bound to.
     * @param Session $session The shared session (cookie jar, CSRF, §9 refresh guard).
     * @param JwksVerifier $jwksVerifier The SAME verifier the §10 middleware uses for AXIAM's own access tokens.
     * @param string|null $clientId The relying party's OAuth2 `client_id`.
     * @param Sensitive|null $clientSecret The confidential client's `client_secret`, already Sensitive-wrapped.
     * @param string|null $tenantId Client-level `tenant_id` UUID fallback (§12.3 rule 4).
     * @param string|null $orgId Client-level organization UUID fallback for `ssoStart` (§5.1).
     * @param string|null $orgSlug Client-level organization slug fallback for `ssoStart` (§5.1).
     * @param string|null $tenantSlugForSso Client-level tenant slug fallback for `ssoStart` (§5.1).
     * @param int $discoveryTtlSeconds Discovery-cache TTL, floored to {@see self::MIN_DISCOVERY_TTL_SECONDS}.
     * @param int $clockSkewSec Permitted ID-token clock skew, clamped to {@see IdTokenValidator::MAX_CLOCK_SKEW_SEC}.
     */
    public function __construct(
        private readonly Client $http,
        private readonly string $baseUrl,
        private readonly Session $session,
        private readonly JwksVerifier $jwksVerifier,
        private readonly ?string $clientId = null,
        private readonly ?Sensitive $clientSecret = null,
        private readonly ?string $tenantId = null,
        private readonly ?string $orgId = null,
        private readonly ?string $orgSlug = null,
        private readonly ?string $tenantSlugForSso = null,
        int $discoveryTtlSeconds = self::MIN_DISCOVERY_TTL_SECONDS,
        int $clockSkewSec = IdTokenValidator::MAX_CLOCK_SKEW_SEC,
    ) {
        $this->discoveryTtlSeconds = max($discoveryTtlSeconds, self::MIN_DISCOVERY_TTL_SECONDS);
        $this->clockSkewSec = IdTokenValidator::resolveClockSkewSec($clockSkewSec);
    }

    // -------------------------------------------------------------------------
    // 1. oidcDiscover
    // -------------------------------------------------------------------------

    /**
     * `GET /.well-known/openid-configuration` (§12.1) — fetch the OIDC discovery
     * document, cached per origin with a ≥5-minute TTL and single-flight
     * de-duplication of concurrent callers (§12.3 rule 6).
     */
    public function oidcDiscover(): OidcConfiguration
    {
        return $this->oidcDiscoverAsync()->wait();
    }

    /**
     * Async entry point exercised directly by tests wanting to prove single-flight
     * de-duplication under Guzzle's async interface — mirrors
     * {@see JwksVerifier}'s own `ensureFreshAsync()`/`ensureFresh()` split.
     */
    public function oidcDiscoverAsync(): PromiseInterface
    {
        $originKey = self::normalizeOrigin($this->baseUrl);

        $cached = $this->discoveryCache[$originKey] ?? null;
        if ($cached !== null && $cached['expiresAt'] > time()) {
            return Create::promiseFor($cached['document']);
        }

        $pending = $this->discoveryInFlight[$originKey] ?? null;
        if ($pending !== null) {
            return $pending;
        }

        $fetch = $this->http->requestAsync('GET', self::DISCOVERY_PATH)
            ->then(function (ResponseInterface $response) use ($originKey): OidcConfiguration {
                $document = OidcConfiguration::fromWire($response);
                $this->discoveryCache[$originKey] = ['document' => $document, 'expiresAt' => time() + $this->discoveryTtlSeconds];

                return $document;
            }, function (\Throwable $reason): never {
                throw $this->mapTransportFailure($reason, self::DISCOVERY_PATH, 'oidc discovery request failed');
            });

        $this->discoveryInFlight[$originKey] = $fetch->then(
            function (OidcConfiguration $document) use ($originKey): OidcConfiguration {
                unset($this->discoveryInFlight[$originKey]);

                return $document;
            },
            function (\Throwable $reason) use ($originKey): never {
                unset($this->discoveryInFlight[$originKey]);

                throw $reason;
            },
        );

        return $this->discoveryInFlight[$originKey];
    }

    /**
     * Normalize a URL to its cache key: lowercased scheme and host with the port always
     * explicit (§12.3 rule 6). `https://IAM.example.com/` and
     * `https://iam.example.com:443/x` therefore share one key, while
     * `http://iam.example.com` gets its own.
     */
    public static function normalizeOrigin(string $url): string
    {
        $parts = parse_url($url);
        $scheme = strtolower((string) ($parts['scheme'] ?? 'https'));
        $host = strtolower((string) ($parts['host'] ?? ''));
        $defaultPort = $scheme === 'https' ? 443 : ($scheme === 'http' ? 80 : 0);
        $port = $parts['port'] ?? $defaultPort;

        return sprintf('%s://%s:%d', $scheme, $host, $port);
    }

    // -------------------------------------------------------------------------
    // 2. oidcBegin
    // -------------------------------------------------------------------------

    /**
     * Build an authorization request (§12.1) — **pure local computation, no network
     * I/O**.
     *
     * Generates a 32-byte CSPRNG `state` and `nonce` (base64url, unpadded) and a fresh
     * PKCE verifier/challenge pair using **S256 only** — `plain` is not implemented
     * anywhere in this SDK. The URL is built from the discovery document's
     * `authorization_endpoint` with exactly the eight parameters §12.1 rule 5 mandates,
     * plus any `$extraParams` the caller adds.
     *
     * Nothing is stored: persist the returned `state`, `nonce` and `codeVerifier`
     * yourself (§12.3 rule 1).
     *
     * @param string|list<string> $scope
     * @param array<string,string> $extraParams
     *
     * @throws \InvalidArgumentException when `$extraParams` tries to override one of the
     *                                    eight SDK-owned parameters — a programming
     *                                    error, caught at call time.
     */
    public function oidcBegin(
        OidcConfiguration $configuration,
        string $redirectUri,
        string|array|null $scope = null,
        array $extraParams = [],
    ): AuthorizationRequest {
        $clientId = $this->requireClientId('oidcBegin');
        $state = Pkce::randomUrlSafeToken();
        $nonce = Pkce::randomUrlSafeToken();
        $codeVerifier = Pkce::generateCodeVerifier();
        $codeChallenge = Pkce::computeCodeChallenge($codeVerifier->reveal());
        $normalizedScope = self::normalizeScope($scope);

        $query = [];
        foreach ($extraParams as $key => $value) {
            if (in_array($key, self::RESERVED_AUTHORIZE_PARAMS, true)) {
                throw new \InvalidArgumentException(sprintf(
                    'oidcBegin: extraParams may not override the SDK-owned authorization parameter "%s" (CONTRACT.md §12.1 rule 5).',
                    $key,
                ));
            }
            $query[$key] = $value;
        }

        $query['response_type'] = 'code';
        $query['client_id'] = $clientId;
        $query['redirect_uri'] = $redirectUri;
        $query['scope'] = $normalizedScope;
        $query['state'] = $state;
        $query['nonce'] = $nonce;
        $query['code_challenge'] = $codeChallenge;
        $query['code_challenge_method'] = Pkce::CODE_CHALLENGE_METHOD_S256;

        $url = self::withQuery($configuration->authorization_endpoint, $query);

        return new AuthorizationRequest($url, $state, $nonce, $codeVerifier);
    }

    /**
     * Normalize the requested scope to a space-separated string that always contains
     * `openid` (§12.1 rule 4 — the helper adds it when the caller omits it). Duplicate
     * entries are collapsed so `"openid openid profile"` cannot be produced.
     *
     * @param string|list<string>|null $scope
     */
    private static function normalizeScope(string|array|null $scope): string
    {
        $requested = is_array($scope) ? $scope : explode(' ', $scope ?? '');
        $values = array_values(array_filter(array_map('trim', $requested), static fn (string $v): bool => $v !== ''));
        if (!in_array('openid', $values, true)) {
            array_unshift($values, 'openid');
        }

        return implode(' ', array_values(array_unique($values)));
    }

    /**
     * Append `$query` to `$url`'s existing query string, RFC 3986-percent-encoding
     * every value (§12.1 rule 5) — notably encoding a space as `%20`, never PHP's
     * `http_build_query()` default `+` (port-brief addendum item 10).
     *
     * @param array<string,string> $query
     */
    private static function withQuery(string $url, array $query): string
    {
        $parts = parse_url($url);
        $existing = [];
        if (isset($parts['query']) && is_string($parts['query'])) {
            parse_str($parts['query'], $existing);
        }
        /** @var array<string,string> $merged */
        $merged = array_merge($existing, $query);

        $pairs = [];
        foreach ($merged as $key => $value) {
            $pairs[] = rawurlencode((string) $key) . '=' . rawurlencode((string) $value);
        }

        $rebuilt = ($parts['scheme'] ?? 'https') . '://' . ($parts['host'] ?? '');
        if (isset($parts['port'])) {
            $rebuilt .= ':' . $parts['port'];
        }
        $rebuilt .= $parts['path'] ?? '';
        if ($pairs !== []) {
            $rebuilt .= '?' . implode('&', $pairs);
        }
        if (isset($parts['fragment'])) {
            $rebuilt .= '#' . $parts['fragment'];
        }

        return $rebuilt;
    }

    // -------------------------------------------------------------------------
    // 3. oidcExchange
    // -------------------------------------------------------------------------

    /**
     * `POST /oauth2/token` with `grant_type=authorization_code` (§12.1) — exchange an
     * authorization code for a token set, validating the returned ID token in full
     * before returning.
     *
     * The `$nonce` argument is mandatory: this grant always requests the `openid`
     * scope, so §12.4 rule 6 always applies. If **any** §12.4 rule fails, the whole
     * token set is discarded and {@see AuthError} is raised with the matching reason
     * code — the access and refresh tokens from the same response are never returned
     * (§12.4 rule 7).
     */
    public function oidcExchange(
        string $code,
        Sensitive|string $codeVerifier,
        string $redirectUri,
        string $nonce,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
    ): OidcTokenSet {
        $clientId = $this->requireClientId('oidcExchange');
        $configuration ??= $this->oidcDiscover();

        $form = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'code_verifier' => self::exposeSecret($codeVerifier),
            'redirect_uri' => $redirectUri,
            'client_id' => $clientId,
        ];
        $this->appendClientSecret($form);

        $wire = $this->postToken($configuration, $form, $tenantId);

        return $this->toTokenSet($wire, $configuration, $nonce);
    }

    // -------------------------------------------------------------------------
    // 4. oidcRefresh
    // -------------------------------------------------------------------------

    /**
     * `POST /oauth2/token` with `grant_type=refresh_token` (§12.1) — refresh an
     * {@see OidcTokenSet}, governed by a §9-conformant single-flight refresh guard.
     *
     * This is a **distinct operation** from `AxiamClient::refresh()`, which drives the
     * cookie/opaque-token session path at `POST /api/v1/auth/refresh`. The two are
     * never merged or aliased and neither falls back to the other (§12.1). They DO
     * share {@see Session}'s single §9 guard slot, tagged with
     * {@see Session::REFRESH_KIND_OIDC}, so at most one refresh of either kind is ever
     * in flight for a session:
     *
     *   - If the guard is busy with ANOTHER `oidcRefresh` call (same kind), this call
     *     does **not** issue its own wire call — it awaits and reuses that one leader's
     *     outcome (CONTRACT.md §9 rule 2, F-06). Refresh tokens are single-use with
     *     rotation, so a second wire call here would replay an already-consumed token
     *     and fail `invalid_grant`; sharing the result is the whole point of the guard.
     *   - If the guard is busy with a cookie-session refresh (different kind, which
     *     cannot produce an `OidcTokenSet`), this call retries (bounded, 3 attempts)
     *     once that refresh settles, rather than returning a stale/foreign result.
     *
     * An `id_token` in the response is validated against §12.4 rules 1–5 and 7; rule 6
     * (nonce) is skipped, since OIDC Core §12.2 does not require a nonce in a
     * refresh-issued ID token.
     */
    public function oidcRefresh(
        Sensitive|string $refreshToken,
        ?string $scope = null,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
    ): OidcTokenSet {
        $clientId = $this->requireClientId('oidcRefresh');
        $configuration ??= $this->oidcDiscover();

        $form = [
            'grant_type' => 'refresh_token',
            'refresh_token' => self::exposeSecret($refreshToken),
            'client_id' => $clientId,
        ];
        $this->appendClientSecret($form);
        if ($scope !== null) {
            $form['scope'] = $scope;
        }

        for ($attempt = 0; $attempt < 3; $attempt++) {
            $guarded = $this->session->refreshGuard(
                fn (): PromiseInterface => $this->postTokenAsync($configuration, $form, $tenantId),
                kind: Session::REFRESH_KIND_OIDC,
            );

            if ($guarded['ran'] || $guarded['kind'] === Session::REFRESH_KIND_OIDC) {
                // Either WE started this refresh, or another concurrent oidcRefresh
                // call already did and this call is sharing its single outcome
                // (CONTRACT.md §9 rule 2 / rule 5, F-06) — never a second wire call.
                /** @var array<string,mixed> $wire */
                $wire = $guarded['promise']->wait();

                return $this->toTokenSet($wire, $configuration, null);
            }

            // The guard was busy with a DIFFERENT KIND of refresh (the §1
            // cookie-session path, which cannot produce an OidcTokenSet) — wait for
            // it to settle (we don't care whether IT succeeded or failed) and try to
            // acquire the guard again.
            try {
                $guarded['promise']->wait();
            } catch (\Throwable) {
                // Not our call — ignore and retry acquiring the guard for our own.
            }
        }

        throw new AuthError(
            'oidcRefresh could not acquire the single-flight refresh guard (CONTRACT.md §9); another refresh kept it busy.',
        );
    }

    // -------------------------------------------------------------------------
    // 5. loginClientCredentials
    // -------------------------------------------------------------------------

    /**
     * `POST /oauth2/token` with `grant_type=client_credentials` (§12.1) —
     * service-account machine-to-machine login.
     *
     * Requests no `openid` scope, so the response carries no `id_token`. Pass
     * `$adoptAsCredential: true` to additionally use the returned access token as this
     * session's bearer credential for subsequent REST calls (§12.1, a MAY).
     *
     * @throws AuthError when no `clientSecret` is configured — this grant cannot be
     *                    performed by a public client.
     */
    public function loginClientCredentials(
        ?string $scope = null,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
        bool $adoptAsCredential = false,
    ): OidcTokenSet {
        $clientId = $this->requireClientId('loginClientCredentials');
        $configuration ??= $this->oidcDiscover();

        $form = [
            'grant_type' => 'client_credentials',
            'client_id' => $clientId,
            'client_secret' => $this->requireClientSecret('loginClientCredentials'),
        ];
        if ($scope !== null) {
            $form['scope'] = $scope;
        }

        $wire = $this->postToken($configuration, $form, $tenantId);
        // No nonce: rule 6 does not apply to this grant (§12.4 rule 6).
        $tokenSet = $this->toTokenSet($wire, $configuration, null);

        if ($adoptAsCredential) {
            $this->adoptCredential($tokenSet->accessToken);
        }

        return $tokenSet;
    }

    // -------------------------------------------------------------------------
    // §14 Device Authorization Grant (RFC 8628)
    // -------------------------------------------------------------------------

    /** `grant_type` of the device access-token request (RFC 8628 §3.4). */
    public const DEVICE_CODE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';

    /**
     * Polling interval used when the authorization response omits `interval`
     * (RFC 8628 §3.2, §14.2 rule 2). An SDK MUST NOT hard-code a faster floor.
     */
    public const DEFAULT_POLL_INTERVAL_SECONDS = 5;

    /**
     * Seconds added to the polling interval on each `slow_down` (§14.2 rule 1). The
     * increase is permanent and cumulative.
     */
    public const SLOW_DOWN_INCREMENT_SECONDS = 5;

    /** `grant_type` of an RFC 8693 exchange. */
    public const TOKEN_EXCHANGE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:token-exchange';

    /** The only `subject_token_type`/`actor_token_type` AXIAM accepts. */
    public const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';

    /**
     * The `events` member that distinguishes a logout token from an ID token
     * (OIDC Back-Channel Logout 1.0 §2.4).
     */
    public const BACKCHANNEL_LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';

    /**
     * Maximum accepted age for a logout token's `iat`, in seconds. AXIAM issues them
     * with a 120 s lifetime; this bound is the same order and stops a token captured
     * from a mis-configured RP being replayed days later.
     */
    public const MAX_LOGOUT_TOKEN_AGE_SECONDS = 300;

    /**
     * `POST /oauth2/device_authorization` (§14.1) — start the device grant and obtain
     * the code pair.
     *
     * **Unauthenticated by design.** A device that cannot show a browser also cannot
     * hold a client secret, so this never sends `client_secret` and never refuses a
     * client built without one (§14.1).
     *
     * @throws AuthError when the discovery document advertises no
     *   `device_authorization_endpoint`. The URL is never built by concatenation onto
     *   the issuer: that works against AXIAM and breaks against every other OP the same
     *   code is pointed at.
     */
    public function deviceAuthorize(
        ?string $scope = null,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
    ): DeviceAuthorization {
        $clientId = $this->requireClientId('deviceAuthorize');
        $configuration ??= $this->oidcDiscover();

        $endpoint = $configuration->device_authorization_endpoint;
        if ($endpoint === null) {
            throw new AuthError(
                'the authorization server\'s discovery document advertises no '
                . 'device_authorization_endpoint: this server does not support the device '
                . 'grant (CONTRACT.md §14.1)'
            );
        }

        $form = ['client_id' => $clientId];
        if ($scope !== null) {
            $form['scope'] = $scope;
        }

        $url = $this->endpointUrl($endpoint, $tenantId);
        $response = $this->postForm($url, $form, 'device authorization request failed');
        $wire = self::decodeJsonObject($response, 'device authorization: response body is not a JSON object');

        $deviceCode = $wire['device_code'] ?? null;
        $userCode = $wire['user_code'] ?? null;
        $verificationUri = $wire['verification_uri'] ?? null;
        $expiresIn = $wire['expires_in'] ?? null;
        if (!is_string($deviceCode) || $deviceCode === ''
            || !is_string($userCode) || $userCode === ''
            || !is_string($verificationUri) || $verificationUri === ''
            || !is_int($expiresIn)) {
            throw NetworkError::fromMessage(
                'device authorization: malformed DeviceAuthorizationResponse '
                . '(missing device_code/user_code/verification_uri/expires_in)'
            );
        }

        $interval = $wire['interval'] ?? null;

        return new DeviceAuthorization(
            deviceCode: new Sensitive($deviceCode),
            userCode: $userCode,
            verificationUri: $verificationUri,
            verificationUriComplete: is_string($wire['verification_uri_complete'] ?? null) && $wire['verification_uri_complete'] !== ''
                ? $wire['verification_uri_complete']
                : null,
            expiresIn: $expiresIn,
            // §14.2 rule 2: the interval comes from the response; only its absence falls
            // back to the RFC default. A server-sent 0 is treated as absent — polling
            // with no delay is never what the server meant.
            interval: is_int($interval) && $interval > 0 ? $interval : self::DEFAULT_POLL_INTERVAL_SECONDS,
        );
    }

    /**
     * `POST /oauth2/token` with the device-code grant (§14.1) — **one** poll attempt.
     *
     * The raw single call, so an application driving its own loop (a UI rendering a
     * countdown, say) can. All five RFC 8628 §3.5 answers surface as
     * {@see \Axiam\Sdk\Core\OAuthProtocolError} — `authorization_pending` and
     * `slow_down` included — so a hand-rolled loop sees exactly what {@see deviceLogin}
     * sees. Most callers want `deviceLogin`.
     */
    public function devicePoll(
        Sensitive|string $deviceCode,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
    ): OidcTokenSet {
        $clientId = $this->requireClientId('devicePoll');
        $configuration ??= $this->oidcDiscover();

        $form = [
            'grant_type' => self::DEVICE_CODE_GRANT_TYPE,
            'device_code' => self::exposeSecret($deviceCode),
            'client_id' => $clientId,
        ];

        $wire = $this->postToken($configuration, $form, $tenantId);

        // No nonce: the device grant has no authorization request to carry one.
        return $this->toTokenSet($wire, $configuration, null);
    }

    /**
     * The composed §14.3 helper: start the grant, hand the caller the user code, poll to
     * completion.
     *
     * `$onUserCode` is called with the {@see DeviceAuthorization} **before the first
     * poll** — §14.3 rule 2 requires the caller to have had the chance to display the
     * code before polling begins. The SDK never prints it: what the device does with it
     * (screen, QR code, e-ink panel) is the application's decision.
     *
     * Per §14.3 rule 4 (contract 1.7 errata) the token set is **returned**; whether it is
     * adopted is `$adoptAsCredential`, the same opt-in flag
     * {@see loginClientCredentials} uses in this SDK.
     *
     * Polling follows §14.2: the interval comes from the response; `slow_down` adds 5 s
     * **permanently**; `authorization_pending` loops; `access_denied` and `expired_token`
     * raise distinct errors; polling stops at `expiresIn` even if the server has not yet
     * said `expired_token`. A 5xx or transport failure mid-poll is **not** terminal
     * (rule 6) — a server restart must not lose a grant the user has already approved.
     *
     * @param callable(DeviceAuthorization):void $onUserCode Invoked before the first poll.
     * @param (callable(int):void)|null $sleep Injectable sleeper, so tests can assert the
     *   §14.2 arithmetic without spending it in wall-clock time. Defaults to `sleep()`.
     */
    public function deviceLogin(
        callable $onUserCode,
        ?string $scope = null,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
        bool $adoptAsCredential = false,
        ?callable $sleep = null,
    ): OidcTokenSet {
        $configuration ??= $this->oidcDiscover();
        $sleep ??= static function (int $seconds): void {
            sleep($seconds);
        };

        $authorization = $this->deviceAuthorize($scope, $tenantId, $configuration);

        // §14.3 rule 2 — before any polling.
        $onUserCode($authorization);

        $intervalSeconds = $authorization->interval;
        $remainingSeconds = $authorization->expiresIn;

        while (true) {
            // §14.2 rule 4: the deadline is authoritative. Checking before sleeping keeps
            // the SDK from issuing a request that can only be refused, and reports it
            // under the same `expired_token` code the server would have used — so a
            // caller's branch does not care which side noticed first.
            if ($intervalSeconds >= $remainingSeconds) {
                throw new OAuthProtocolError(
                    'expired_token',
                    'the device authorization expired before the user completed it '
                    . '(client-side deadline from expires_in; CONTRACT.md §14.2 rule 4)'
                );
            }
            $remainingSeconds -= $intervalSeconds;

            $sleep($intervalSeconds);

            try {
                $tokenSet = $this->devicePoll($authorization->deviceCode, $tenantId, $configuration);
                if ($adoptAsCredential) {
                    $this->adoptCredential($tokenSet->accessToken);
                }

                return $tokenSet;
            } catch (OAuthProtocolError $e) {
                if ($e->error === 'authorization_pending') {
                    continue;
                }
                if ($e->error === 'slow_down') {
                    // §14.2 rule 1: cumulative, never reset.
                    $intervalSeconds += self::SLOW_DOWN_INCREMENT_SECONDS;
                    continue;
                }
                // expired_token / access_denied / invalid_grant — terminal.
                throw $e;
            } catch (NetworkError $e) {
                // §14.2 rule 6: transport and 5xx failures are not among the five protocol
                // answers and are not terminal.
                continue;
            }
        }
    }

    // -------------------------------------------------------------------------
    // §15 Token Exchange (RFC 8693)
    // -------------------------------------------------------------------------

    /**
     * `POST /oauth2/token` with the RFC 8693 grant (§15.1) — exchange a token for a
     * **narrower** one.
     *
     * The exchanging client authenticates (`client_secret_post`): unlike §14's device,
     * this is a confidential service, so a client with no secret fails here client-side,
     * with no wire call.
     *
     * What this method deliberately does **not** do:
     *
     * - **No default `$actorToken`** (§15.2 rule 1). Passing `null` asks for
     *   *impersonation*; the SDK will not quietly reuse the client's own session token as
     *   the actor and turn that into a delegation.
     * - **No retry or downgrade on `unauthorized_client`** (rule 2) — a registration fact
     *   an operator must fix.
     * - **No auto-narrowing on `invalid_scope`** (rule 3). The server refuses instead of
     *   silently narrowing precisely so the caller finds out here.
     * - **No adoption** (rule 5), and no flag to enable it — a MUST NOT, where
     *   {@see loginClientCredentials} adoption is a MAY.
     *
     * A cross-tenant subject token answers `invalid_grant`, identically to an expired
     * one. The SDK does not try to tell them apart (§15.3): the server collapses them
     * because distinguishing them is a tenant-enumeration signal.
     *
     * @param list<string>|null $scopes Omitted from the body when `null` or empty.
     * @throws AuthError when no `clientSecret` is configured.
     */
    public function tokenExchange(
        Sensitive|string $subjectToken,
        Sensitive|string|null $actorToken = null,
        ?array $scopes = null,
        ?string $audience = null,
        ?string $resource = null,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
    ): ExchangedToken {
        $clientId = $this->requireClientId('tokenExchange');
        $configuration ??= $this->oidcDiscover();

        $form = [
            'grant_type' => self::TOKEN_EXCHANGE_GRANT_TYPE,
            'subject_token' => self::exposeSecret($subjectToken),
            'subject_token_type' => self::ACCESS_TOKEN_TYPE,
            'client_id' => $clientId,
            'client_secret' => $this->requireClientSecret('tokenExchange'),
        ];
        if ($actorToken !== null) {
            $form['actor_token'] = self::exposeSecret($actorToken);
            // Sent exactly when `actor_token` is: RFC 8693 §2.1 requires the pair, and the
            // type alone is a malformed request.
            $form['actor_token_type'] = self::ACCESS_TOKEN_TYPE;
        }
        if ($scopes !== null && $scopes !== []) {
            $form['scope'] = implode(' ', $scopes);
        }
        if ($audience !== null) {
            $form['audience'] = $audience;
        }
        if ($resource !== null) {
            $form['resource'] = $resource;
        }

        $url = $this->endpointUrl($configuration->token_endpoint, $tenantId);
        $response = $this->postForm($url, $form, 'token exchange request failed');
        $wire = self::decodeJsonObject($response, 'token exchange: response body is not a JSON object');

        $accessToken = $wire['access_token'] ?? null;
        $issuedTokenType = $wire['issued_token_type'] ?? null;
        $tokenType = $wire['token_type'] ?? null;
        $expiresIn = $wire['expires_in'] ?? null;
        if (!is_string($accessToken) || $accessToken === ''
            || !is_string($issuedTokenType) || $issuedTokenType === ''
            || !is_string($tokenType)
            || !is_int($expiresIn)) {
            throw NetworkError::fromMessage(
                'token exchange: malformed TokenExchangeResponse '
                . '(missing access_token/issued_token_type/token_type/expires_in)'
            );
        }

        return new ExchangedToken(
            accessToken: new Sensitive($accessToken),
            issuedTokenType: $issuedTokenType,
            tokenType: $tokenType,
            expiresIn: $expiresIn,
            scope: is_string($wire['scope'] ?? null) ? $wire['scope'] : null,
        );
    }

    // -------------------------------------------------------------------------
    // §12.7 Logout helpers
    // -------------------------------------------------------------------------

    /**
     * Build the RP-initiated logout URL to redirect the user agent to (§12.7.2).
     *
     * Performs **no network I/O** beyond the discovery fetch the SDK caches anyway, and
     * does **not** clear this client's own session: whether the local session ends is the
     * application's decision — a backend holding a service-account session must not lose
     * it because a *user* logged out.
     *
     * `end_session_endpoint` is read from discovery and never synthesised from the issuer
     * (rule 1). `$postLogoutRedirectUri` is passed through **unvalidated against any local
     * list** (rule 3): the allow-list lives in the client's server-side registration, and
     * a client-side copy would drift and reject a URI an operator had just registered.
     *
     * @throws AuthError when the discovery document advertises no `end_session_endpoint`.
     */
    public function logoutUrl(
        Sensitive|string $idToken,
        ?string $postLogoutRedirectUri = null,
        ?string $state = null,
        ?OidcConfiguration $configuration = null,
    ): string {
        $configuration ??= $this->oidcDiscover();

        $endpoint = $configuration->end_session_endpoint;
        if ($endpoint === null) {
            throw new AuthError(
                'the authorization server\'s discovery document advertises no '
                . 'end_session_endpoint: this server does not support RP-initiated logout '
                . '(CONTRACT.md §12.7.2 rule 1)'
            );
        }

        $query = ['id_token_hint' => self::exposeSecret($idToken)];
        if ($postLogoutRedirectUri !== null) {
            $query['post_logout_redirect_uri'] = $postLogoutRedirectUri;
        }
        if ($state !== null) {
            $query['state'] = $state;
        }

        return self::withQuery($endpoint, $query);
    }

    /**
     * Verify a back-channel logout token the OP POSTed to this application's
     * `backchannel_logout_uri` (§12.7.3).
     *
     * Every check exists because skipping it has a name:
     *
     * 1. **Signature**, through the same §12.4 JWKS verifier the ID-token path uses — no
     *    second key-fetching path — which already pins EdDSA and requires a `kid`.
     * 2. **`iss`/`aud`**: a token minted for another RP is not accepted here.
     * 3. **`events` carries the back-channel-logout key.** This is what distinguishes a
     *    logout token from an ID token; skipping it means accepting a replayed ID token
     *    as a logout instruction.
     * 4. **`nonce` is absent.** Back-Channel Logout 1.0 §2.4 forbids it, and its presence
     *    is the documented signature of an ID token being replayed. Rejected, not ignored.
     * 5. **At least one of `sid`/`sub`** — a token naming neither identifies nothing.
     * 6. **`exp` in the future, `iat` recent.**
     *
     * @return VerifiedLogoutToken The `sid`/`sub`/`jti` the token names — never a bare
     *   `bool`, because the RP has to know *which* session to end. **Dedup on `jti`
     *   yourself**: delivery is at-least-once, and an SDK-side guard would have no durable
     *   store and would silently drop a real second logout after a restart.
     * @throws AuthError on any failed check.
     */
    public function verifyLogoutToken(
        string $logoutToken,
        ?OidcConfiguration $configuration = null,
    ): VerifiedLogoutToken {
        $clientId = $this->requireClientId('verifyLogoutToken');
        $configuration ??= $this->oidcDiscover();

        // Same JWKS path — and therefore the same EdDSA pinning and kid discipline — as
        // §12.4. No second key-fetching route. The error it raises never embeds the
        // token: an unverifiable logout token is exactly the case a naive implementation
        // logs verbatim.
        $claims = $this->jwksVerifier->verifyIdTokenSignature($logoutToken);

        if (($claims['iss'] ?? null) !== $configuration->issuer) {
            throw new AuthError('logout token issuer does not match the discovery document');
        }
        if (!self::audienceContains($claims['aud'] ?? null, $clientId)) {
            throw new AuthError('logout token audience does not match this client_id');
        }

        // Without this check the whole method is an elaborate way to accept an ID token.
        if (!self::carriesBackchannelLogoutEvent($claims['events'] ?? null)) {
            throw new AuthError(
                'not a logout token: the events claim does not carry ' . self::BACKCHANNEL_LOGOUT_EVENT
            );
        }

        if (array_key_exists('nonce', $claims)) {
            throw new AuthError(
                'logout token carries a nonce, which Back-Channel Logout 1.0 §2.4 forbids: '
                . 'this is an ID token being replayed as a logout token'
            );
        }

        $sid = is_string($claims['sid'] ?? null) ? $claims['sid'] : null;
        $sub = is_string($claims['sub'] ?? null) ? $claims['sub'] : null;
        if ($sid === null && $sub === null) {
            throw new AuthError('logout token names neither sid nor sub, so it identifies no session');
        }

        $now = time();
        $skew = $this->clockSkewSec ?? 0;
        $exp = $claims['exp'] ?? null;
        $iat = $claims['iat'] ?? null;
        if (!is_int($exp) || $exp + $skew < $now) {
            throw new AuthError('logout token has expired');
        }
        if (!is_int($iat) || $iat - $skew > $now) {
            throw new AuthError('logout token was issued in the future');
        }
        if ($now - $iat > self::MAX_LOGOUT_TOKEN_AGE_SECONDS + $skew) {
            throw new AuthError('logout token is too old to be a live delivery');
        }

        $jti = $claims['jti'] ?? null;
        if (!is_string($jti) || $jti === '') {
            throw new AuthError('logout token carries no jti, so the RP cannot dedup redeliveries');
        }

        return new VerifiedLogoutToken(sid: $sid, sub: $sub, jti: $jti);
    }

    /**
     * Whether `events` carries the back-channel-logout key mapped to a JSON **object**.
     *
     * Two shapes have to be accepted on the way in: the JWT decoder hands nested JSON
     * objects back as `stdClass`, while an empty JSON object round-trips through
     * `json_decode(..., true)` as an empty array. Both are the same wire value, so both
     * count.
     *
     * The object-ness itself is the check that matters: Back-Channel Logout 1.0 §2.4
     * specifies a JSON object (normally empty), and accepting `null` or a string would
     * let a near-miss token through on a technicality.
     */
    private static function carriesBackchannelLogoutEvent(mixed $events): bool
    {
        $map = match (true) {
            is_array($events) => $events,
            $events instanceof \stdClass => (array) $events,
            default => null,
        };
        if ($map === null || !array_key_exists(self::BACKCHANNEL_LOGOUT_EVENT, $map)) {
            return false;
        }

        $entry = $map[self::BACKCHANNEL_LOGOUT_EVENT];

        return is_array($entry) || $entry instanceof \stdClass;
    }

    /**
     * `aud` may be a single string or a list (RFC 7519 §4.1.3); both must be honoured,
     * because rejecting the list form would refuse tokens the spec permits.
     */
    private static function audienceContains(mixed $aud, string $clientId): bool
    {
        if (is_string($aud)) {
            return $aud === $clientId;
        }
        if (is_array($aud)) {
            return in_array($clientId, $aud, true);
        }

        return false;
    }

    // -------------------------------------------------------------------------
    // 6. introspect
    // -------------------------------------------------------------------------

    /**
     * `POST /oauth2/introspect` (RFC 7662, §12.1) — ask the server whether a token is
     * active and, if so, for its metadata.
     *
     * Requires confidential-client credentials (§12.1 note 4). A `401` here is a
     * *client-credential* failure surfaced as {@see \Axiam\Sdk\Core\OAuthProtocolError};
     * it never enters the §9 refresh guard — this method's `$http` transport carries
     * NO `RefreshMiddleware` at all, so there is structurally no guard for it to enter
     * (§12.3 rule 3).
     *
     * @throws AuthError when no `clientSecret` is configured.
     */
    public function introspect(
        Sensitive|string $token,
        ?string $tokenTypeHint = null,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
    ): IntrospectionResult {
        $clientId = $this->requireClientId('introspect');
        $configuration ??= $this->oidcDiscover();

        $form = [
            'token' => self::exposeSecret($token),
            'client_id' => $clientId,
            'client_secret' => $this->requireClientSecret('introspect'),
        ];
        if ($tokenTypeHint !== null) {
            $form['token_type_hint'] = $tokenTypeHint;
        }

        $url = $this->endpointUrl($configuration->introspection_endpoint, $tenantId);
        $response = $this->postForm($url, $form, 'introspect request failed');
        $wire = json_decode((string) $response->getBody(), true);
        if (!is_array($wire)) {
            throw NetworkError::fromResponse($response, 'introspect: response body is not a JSON object');
        }

        return new IntrospectionResult(
            active: (bool) ($wire['active'] ?? false),
            sub: is_string($wire['sub'] ?? null) ? $wire['sub'] : null,
            clientId: is_string($wire['client_id'] ?? null) ? $wire['client_id'] : null,
            scope: is_string($wire['scope'] ?? null) ? $wire['scope'] : null,
            tokenType: is_string($wire['token_type'] ?? null) ? $wire['token_type'] : null,
            exp: is_int($wire['exp'] ?? null) ? $wire['exp'] : null,
            iat: is_int($wire['iat'] ?? null) ? $wire['iat'] : null,
        );
    }

    // -------------------------------------------------------------------------
    // 7. revoke
    // -------------------------------------------------------------------------

    /**
     * `POST /oauth2/revoke` (RFC 7009, §12.1) — revoke an access or refresh token.
     * Returns nothing.
     *
     * Per RFC 7009 the server answers `200` for unknown, expired and already-revoked
     * tokens alike, so revocation is **idempotent**: any `200` is success and no error
     * is raised for a token the server has never seen. Only a `401` (client
     * authentication failed) is an error, surfaced as
     * {@see \Axiam\Sdk\Core\OAuthProtocolError} (§12.1 note 5, §12.3 rule 3). A `5xx`
     * stays a {@see NetworkError} — it never becomes "success" just because RFC 7009
     * treats an unknown token as success.
     *
     * @throws AuthError when no `clientSecret` is configured.
     */
    public function revoke(
        Sensitive|string $token,
        ?string $tokenTypeHint = null,
        ?string $tenantId = null,
        ?OidcConfiguration $configuration = null,
    ): void {
        $clientId = $this->requireClientId('revoke');
        $configuration ??= $this->oidcDiscover();

        $form = [
            'token' => self::exposeSecret($token),
            'client_id' => $clientId,
            'client_secret' => $this->requireClientSecret('revoke'),
        ];
        if ($tokenTypeHint !== null) {
            $form['token_type_hint'] = $tokenTypeHint;
        }

        $url = $this->endpointUrl($configuration->revocation_endpoint, $tenantId);
        $this->postForm($url, $form, 'revoke request failed');
    }

    // -------------------------------------------------------------------------
    // 8. ssoStart
    // -------------------------------------------------------------------------

    /**
     * `POST /api/v1/auth/federation/oidc/start` (§12.1) — step 1 of first-time SSO
     * against an **upstream** IdP. No JWT required.
     *
     * One tenant form (`$tenantId` or `$tenantSlug`) and one org form (`$orgId` or
     * `$orgSlug`) must be resolvable, from the arguments or from the client's
     * construction options (§5.1). Redirect the browser to the returned
     * `authorizeUrl` and round-trip `state` back into {@see self::ssoComplete()}
     * unmodified — the server keeps the nonce to itself (§12.1 note 7).
     *
     * @throws AuthError client-side, without a wire call, when tenant or org context
     *                    cannot be resolved.
     */
    public function ssoStart(
        string $federationConfigId,
        string $redirectUri,
        ?string $tenantId = null,
        ?string $tenantSlug = null,
        ?string $orgId = null,
        ?string $orgSlug = null,
    ): SsoStartResult {
        $resolvedTenantId = $tenantId ?? $this->tenantId;
        $resolvedTenantSlug = $tenantSlug ?? $this->tenantSlugForSso ?? $this->session->tenant();
        $resolvedOrgId = $orgId ?? $this->orgId;
        $resolvedOrgSlug = $orgSlug ?? $this->orgSlug;

        if ($resolvedTenantId === null && $resolvedTenantSlug === '') {
            throw new AuthError(
                'ssoStart requires tenant context: pass tenantId or tenantSlug, or construct the client with one (CONTRACT.md §5.1).',
            );
        }
        if ($resolvedOrgId === null && $resolvedOrgSlug === null) {
            throw new AuthError(
                'ssoStart requires organization context: pass orgId or orgSlug, or construct the client with one (CONTRACT.md §5.1).',
            );
        }

        $body = [
            'federation_config_id' => $federationConfigId,
            'redirect_uri' => $redirectUri,
        ];
        // One tenant form AND one org form (§5.1) — the UUID form wins when both are
        // present, mirroring how a slug/UUID pair already resolves elsewhere in §5.
        if ($resolvedTenantId !== null) {
            $body['tenant_id'] = $resolvedTenantId;
        } else {
            $body['tenant_slug'] = $resolvedTenantSlug;
        }
        if ($resolvedOrgId !== null) {
            $body['org_id'] = $resolvedOrgId;
        } else {
            $body['org_slug'] = $resolvedOrgSlug;
        }

        $response = $this->postJson(self::SSO_START_PATH, $body, 'ssoStart request failed');
        $wire = json_decode((string) $response->getBody(), true);
        if (!is_array($wire) || !is_string($wire['authorize_url'] ?? null) || !is_string($wire['state'] ?? null)) {
            throw NetworkError::fromResponse($response, 'ssoStart: malformed response body');
        }

        return new SsoStartResult(
            authorizeUrl: $wire['authorize_url'],
            state: $wire['state'],
            expiresInSecs: (int) ($wire['expires_in_secs'] ?? 0),
        );
    }

    // -------------------------------------------------------------------------
    // 9. ssoComplete
    // -------------------------------------------------------------------------

    /**
     * `POST /api/v1/auth/federation/oidc/callback` (§12.1) — step 2 of upstream SSO:
     * consumes the single-use `state`, provisions or links the user, and establishes
     * the session.
     *
     * The session arrives as **`Set-Cookie`**, not in the response body (§12.1 note 6)
     * — `$this->http` shares {@see \Axiam\Sdk\AxiamClient}'s §4 cookie jar, so the
     * session is captured automatically. On success the §3 CSRF token freshly set by
     * the server is captured too, exactly as `login()` does.
     *
     * §12.4 does not apply here — no ID token ever reaches the SDK on the federation
     * path.
     */
    public function ssoComplete(string $state, string $code): SsoCompleteResult
    {
        $response = $this->postJson(self::SSO_CALLBACK_PATH, ['state' => $state, 'code' => $code], 'ssoComplete request failed');
        $this->session->captureCsrfTokenFromResponse($response);

        $wire = json_decode((string) $response->getBody(), true);
        if (
            !is_array($wire)
            || !is_string($wire['user_id'] ?? null)
            || !is_string($wire['session_id'] ?? null)
            || !is_string($wire['redirect_uri'] ?? null)
        ) {
            throw NetworkError::fromResponse($response, 'ssoComplete: malformed response body');
        }

        return new SsoCompleteResult(
            userId: $wire['user_id'],
            sessionId: $wire['session_id'],
            expiresIn: (int) ($wire['expires_in'] ?? 0),
            redirectUri: $wire['redirect_uri'],
        );
    }

    // -------------------------------------------------------------------------
    // internals
    // -------------------------------------------------------------------------

    /**
     * POST a form body to the token endpoint from the discovery document (synchronous).
     *
     * @param array<string,string> $form
     *
     * @return array<string,mixed>
     */
    private function postToken(OidcConfiguration $configuration, array $form, ?string $tenantId): array
    {
        $url = $this->endpointUrl($configuration->token_endpoint, $tenantId);
        $response = $this->postForm($url, $form, 'token request failed');

        return self::decodeJsonObject($response, 'token request: response body is not a JSON object');
    }

    /**
     * Decode a response body expected to be a JSON object, raising {@see NetworkError}
     * (built from the live `$response`, so its `Set-Cookie`/`Authorization` headers are
     * redacted per {@see NetworkError::fromResponse()}) when it is not.
     *
     * @return array<string,mixed>
     */
    private static function decodeJsonObject(ResponseInterface $response, string $context): array
    {
        $wire = json_decode((string) $response->getBody(), true);
        if (!is_array($wire)) {
            throw NetworkError::fromResponse($response, $context);
        }

        /** @var array<string,mixed> $wire */
        return $wire;
    }

    /**
     * Async variant used by {@see self::oidcRefresh()} so the wire call can run INSIDE
     * {@see Session::refreshGuard()}, which is itself Guzzle-promise-based (§9).
     *
     * @param array<string,string> $form
     *
     * @return PromiseInterface<array<string,mixed>, \Throwable>
     */
    private function postTokenAsync(OidcConfiguration $configuration, array $form, ?string $tenantId): PromiseInterface
    {
        $url = $this->endpointUrl($configuration->token_endpoint, $tenantId);

        return $this->http->requestAsync('POST', $url, [
            'form_params' => $form,
            'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'],
        ])->then(
            /** @return array<string,mixed> */
            function (ResponseInterface $response): array {
                return self::decodeJsonObject($response, 'token request: response body is not a JSON object');
            },
            function (\Throwable $reason): never {
                throw $this->mapTransportFailure($reason, 'oauth2 token endpoint', 'token request failed', oauth2: true);
            },
        );
    }

    /**
     * Convert a `TokenResponse` into an {@see OidcTokenSet}, validating any `id_token`
     * first (§12.4). Validation precedes construction, so a failure discards the whole
     * set — the caller never sees the access or refresh token from a response whose ID
     * token was rejected (§12.4 rule 7).
     *
     * @param array<string,mixed> $wire
     */
    private function toTokenSet(array $wire, OidcConfiguration $configuration, ?string $nonce): OidcTokenSet
    {
        $accessToken = $wire['access_token'] ?? null;
        $tokenType = $wire['token_type'] ?? null;
        $expiresIn = $wire['expires_in'] ?? null;
        if (!is_string($accessToken) || $accessToken === '' || !is_string($tokenType) || !is_int($expiresIn)) {
            throw NetworkError::fromMessage('token request: malformed TokenResponse (missing access_token/token_type/expires_in)');
        }

        $idClaims = null;
        $idToken = $wire['id_token'] ?? null;
        if (is_string($idToken) && $idToken !== '') {
            $signatureVerified = $this->jwksVerifier->verifyIdTokenSignature($idToken);
            $idClaims = IdTokenValidator::checkClaims(
                $signatureVerified,
                $configuration->issuer,
                $this->requireClientId('oidc id_token validation'),
                $nonce,
                $this->clockSkewSec,
            );
        }

        return new OidcTokenSet(
            accessToken: new Sensitive($accessToken),
            tokenType: $tokenType,
            expiresIn: $expiresIn,
            scope: is_string($wire['scope'] ?? null) ? $wire['scope'] : null,
            refreshToken: is_string($wire['refresh_token'] ?? null) ? new Sensitive($wire['refresh_token']) : null,
            idToken: is_string($idToken) && $idToken !== '' ? new Sensitive($idToken) : null,
            idClaims: $idClaims,
        );
    }

    /**
     * Build the final endpoint URL: the discovery document's endpoint plus the
     * mandatory `?tenant_id=<uuid>` query parameter (§12.1 note 2). Existing query
     * parameters on the endpoint are preserved.
     */
    private function endpointUrl(string $endpoint, ?string $tenantId): string
    {
        return self::withQuery($endpoint, ['tenant_id' => $this->resolveTenantId($tenantId)]);
    }

    /**
     * Resolve the tenant UUID for the `tenant_id` query parameter (§12.3 rule 4): the
     * explicit argument, else the client-level `tenantId` — and only ever a UUID. A
     * client with no UUID configured raises the taxonomy error client-side, with no
     * wire call, rather than sending a slug where the server requires a UUID.
     */
    private function resolveTenantId(?string $explicit): string
    {
        $candidate = $explicit ?? $this->tenantId;
        if ($candidate === null || $candidate === '') {
            throw new AuthError(
                'this operation requires a tenant_id UUID for the /oauth2 query parameter: pass tenantId explicitly, '
                . 'or construct the client with an oidcTenantId (UUID) (CONTRACT.md §12.3 rule 4).',
            );
        }
        if (preg_match(self::UUID_RE, $candidate) !== 1) {
            throw new AuthError(
                'tenant_id must be a UUID for the /oauth2 query parameter; a tenant slug cannot be substituted '
                . '(CONTRACT.md §12.3 rule 4).',
            );
        }

        return $candidate;
    }

    /**
     * Add `client_secret` to a form body for a confidential client, and omit it
     * entirely for a public client — §12.1 forbids sending an empty/null value for an
     * absent optional field.
     *
     * @param array<string,string> $form
     */
    private function appendClientSecret(array &$form): void
    {
        if ($this->clientSecret !== null) {
            $form['client_secret'] = $this->clientSecret->reveal();
        }
    }

    /** The `client_secret` for an operation that cannot be performed without one (§12.1 note 4). */
    private function requireClientSecret(string $operation): string
    {
        if ($this->clientSecret === null) {
            throw new AuthError(sprintf(
                '%s requires confidential-client credentials: construct the client with an oidcClientSecret (CONTRACT.md §12.1 note 4).',
                $operation,
            ));
        }

        return $this->clientSecret->reveal();
    }

    /** The configured `client_id`, or a clear client-side error when none was configured. */
    private function requireClientId(string $operation): string
    {
        if ($this->clientId === null || $this->clientId === '') {
            throw new AuthError(sprintf(
                '%s requires an OIDC client_id: construct the client with an oidcClientId (CONTRACT.md §12.1).',
                $operation,
            ));
        }

        return $this->clientId;
    }

    /**
     * Adopt an access token as this session's bearer credential (§12.1, opt-in).
     *
     * The token lives only behind {@see Sensitive} in {@see Session} — never on a
     * public property or the cookie jar — so it stays unreachable through any public
     * getter (§12.3 rule 2). It is deliberately NOT sent to `/oauth2/*`: those
     * endpoints authenticate the client through the form body (§12.1 note 3).
     */
    private function adoptCredential(Sensitive $accessToken): void
    {
        $this->session->adoptBearerCredential($accessToken);
    }

    /** Read a secret that the caller may have supplied wrapped or bare (§12.3 rule 6 judgment call). */
    private static function exposeSecret(Sensitive|string $value): string
    {
        return $value instanceof Sensitive ? $value->reveal() : $value;
    }

    /**
     * POST a form-encoded body (§12.1 note 1) through the session transport, synchronously.
     *
     * @param array<string,string> $form
     */
    private function postForm(string $url, array $form, string $context): ResponseInterface
    {
        try {
            return $this->http->post($url, [
                'form_params' => $form,
                'headers' => ['Content-Type' => 'application/x-www-form-urlencoded'],
            ]);
        } catch (RequestException $e) {
            throw $this->mapRequestException($e, $context, oauth2: true);
        } catch (GuzzleException $e) {
            throw NetworkError::fromException($e, $context);
        }
    }

    /**
     * POST a JSON body (the federation endpoints) through the session transport.
     *
     * @param array<string,string> $body
     */
    private function postJson(string $path, array $body, string $context): ResponseInterface
    {
        try {
            return $this->http->post($path, ['json' => $body]);
        } catch (RequestException $e) {
            // Port-brief addendum item 12: the federation endpoints document no
            // response schema for their errors — never OAuthProtocolError here.
            throw $this->mapRequestException($e, $context, oauth2: false);
        } catch (GuzzleException $e) {
            throw NetworkError::fromException($e, $context);
        }
    }

    private function mapRequestException(RequestException $e, string $context, bool $oauth2): \Axiam\Sdk\Core\AxiamException
    {
        $response = $e instanceof BadResponseException ? $e->getResponse() : null;
        if ($response === null) {
            return NetworkError::fromException($e, $context);
        }

        return $oauth2 ? ErrorMapper::fromOAuth2Response($response, $context) : ErrorMapper::fromResponse($response, $context);
    }

    /**
     * Maps a rejected Guzzle async promise's reason the same way
     * {@see self::mapRequestException()} maps a caught exception. `$url` is currently
     * unused (kept for parity with the synchronous call sites' context building) but is
     * part of the private call signature every `mapTransportFailure()` caller shares.
     */
    private function mapTransportFailure(\Throwable $reason, string $url, string $context, bool $oauth2 = false): \Throwable
    {
        if ($reason instanceof \Axiam\Sdk\Core\AxiamException) {
            return $reason;
        }
        if ($reason instanceof RequestException) {
            return $this->mapRequestException($reason, $context, $oauth2);
        }
        if ($reason instanceof GuzzleException) {
            return NetworkError::fromException($reason, $context);
        }

        return $reason;
    }
}
