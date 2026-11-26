<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\NetworkError;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Shared "Login with AXIAM" core (CONTRACT.md §12) — the ONE begin/complete +
 * state-store + error-mapping path BOTH {@see \Axiam\Sdk\Laravel\OidcLoginController}/
 * {@see \Axiam\Sdk\Laravel\OidcCallbackController} and
 * {@see \Axiam\Sdk\Symfony\OidcLoginController}/{@see \Axiam\Sdk\Symfony\OidcCallbackController}
 * call, mirroring the TypeScript reference's `middleware/oidcLoginCore.ts` (the ONE §12
 * path, exactly as `AccessEnforcer` is the one §11 path shared by both framework
 * bridges in this SDK).
 *
 * Framework-agnostic on purpose: it takes plain values in and returns a discriminated
 * {@see OidcLoginOutcome} out, so each framework controller only has to translate an
 * outcome into that framework's redirect/JSON response. It writes no session of its own
 * and touches no framework request/response object: the one cookie it needs — the
 * browser-binding cookie of CONTRACT.md §12.8 (contract 1.68; C7) — is handed to the
 * controller as a finished `Set-Cookie` value ({@see OidcLoginOutcome::$setCookie}) and
 * read back from the request by the controller, which passes its value to
 * {@see self::complete()}.
 *
 * **Browser binding (§12.8 rule 1; C7).** `begin()` draws a fresh random value, stores its
 * SHA-256 on the state entry and hands the value back as the
 * `__Host-axiam_oidc_bind` cookie; `complete()` consumes the entry FIRST and then refuses,
 * with the same `401` an unknown state gets, any callback that does not present the cookie
 * whose digest the entry holds — before any token request and before `$onSuccess`. Without
 * it, knowing a live `state` was treated as proof that the callback came from the browser
 * that started the login, so an attacker could finish THEIR login in a victim's browser.
 * There is no way to switch the binding off.
 *
 * **`return_to` (§12.8 rule 3; C6).** Only a same-origin relative path is ever stored or
 * followed ({@see self::isSafeReturnTo()}).
 *
 * The state store is what makes the two HTTP requests of a redirect flow into one
 * login: `oidcBegin` produces `state`/`nonce`/`code_verifier` on the login request, and
 * only `state` survives the round trip through the IdP, so the other two must be parked
 * somewhere the callback request can reach (§12.3 rule 1 — the SDK itself stores
 * nothing on its own).
 *
 * BOTH framework integrations are optional and off by default (CONTRACT.md §12,
 * plan T8 item 2): this class, and the controllers built on it, are only ever
 * `require`d when an application explicitly wires them into its own routing — nothing
 * in {@see \Axiam\Sdk\Laravel\AxiamServiceProvider} or
 * {@see \Axiam\Sdk\Symfony\AxiamBundle} registers a route automatically.
 */
final class OidcLoginFlow
{
    /** The browser-binding cookie's name (§12.8 rule 1 (a)). */
    public const BINDING_COOKIE_NAME = '__Host-axiam_oidc_bind';

    /**
     * The name used ONLY where the flow's own `redirect_uri` is plain-HTTP on a loopback host
     * (§12.8 rule 1 (b)), where a browser will not store a `Secure` cookie.
     */
    public const BINDING_COOKIE_LOOPBACK_NAME = 'axiam_oidc_bind';

    /** `Max-Age` of the binding cookie: the state store's maximum TTL. */
    private const BINDING_COOKIE_MAX_AGE_SECONDS = MemoryOidcStateStore::TTL_SECONDS;

    /**
     * @param AxiamClient $client Client configured with `oidcClientId` (and, for a
     *        confidential client, `oidcClientSecret`) — see
     *        {@see AxiamClient::__construct()}.
     * @param OidcStateStoreInterface $store Where in-flight login state is parked
     *        between the login redirect and the callback.
     *        {@see MemoryOidcStateStore} is a ready single-process implementation; a
     *        multi-instance deployment needs a shared one.
     * @param string $redirectUri The relying party's redirect URI — must be the public
     *        URL of the callback route, and is replayed verbatim on the token exchange.
     * @param string|list<string>|null $scope Requested scope. `openid` is added
     *        automatically when absent (§12.1 rule 4).
     * @param LoggerInterface $logger Debug-only logger. Receives failure reasons, never
     *        token material, `state`, `nonce`, the verifier or the binding-cookie value.
     *        Defaults to a silent {@see NullLogger}.
     * @param (\Closure(string): bool)|null $allowReturnTo OPTIONAL integrator predicate that
     *        MAY widen the `return_to` rule (§12.8 rule 3) — for example to an allowlist of the
     *        application's other origins. It is consulted, at login and again before the
     *        redirect, ONLY for a value the default same-origin-relative-path rule refuses, and
     *        the value is honoured only when it returns `true`; a predicate that throws accepts
     *        nothing. `null` (the default) leaves the default rule alone in charge. The SDK
     *        ships no predicate that accepts absolute URLs.
     */
    public function __construct(
        private readonly AxiamClient $client,
        private readonly OidcStateStoreInterface $store,
        private readonly string $redirectUri,
        private readonly string|array|null $scope = null,
        private readonly LoggerInterface $logger = new NullLogger(),
        private readonly ?\Closure $allowReturnTo = null,
    ) {
    }

    /**
     * The name of the binding cookie for a flow whose callback is `$redirectUri` — a pure
     * function of that URI (§12.8 rule 1 (b)): `axiam_oidc_bind` when it is `http:` on
     * `localhost`, `127.0.0.1` or `[::1]`, and `__Host-axiam_oidc_bind` for everything else,
     * every `https:` URI and plain HTTP to any other host included (on which the browser drops
     * the cookie and every callback fails closed). The fallback is never selectable off
     * loopback, by configuration or otherwise.
     */
    public static function bindingCookieNameFor(string $redirectUri): string
    {
        $parts = parse_url($redirectUri);
        if (is_array($parts)
            && isset($parts['scheme'], $parts['host'])
            && strtolower($parts['scheme']) === 'http'
            && in_array(strtolower($parts['host']), ['localhost', '127.0.0.1', '[::1]'], true)
        ) {
            return self::BINDING_COOKIE_LOOPBACK_NAME;
        }

        return self::BINDING_COOKIE_NAME;
    }

    /**
     * The cookie name THIS flow sets at login and reads at the callback — and ONLY this one:
     * a cookie of the other name is no cookie at all. Controllers read exactly this name from
     * the callback request and pass its value to {@see self::complete()}.
     */
    public function bindingCookieName(): string
    {
        return self::bindingCookieNameFor($this->redirectUri);
    }

    /**
     * §12.8 rule 3: true when `$returnTo` is a same-origin relative path — it starts with a
     * single `/`, does not start with `//` or `/\`, and contains no `\` anywhere and no
     * control character (U+0000–U+001F, U+007F). An absolute URL, a scheme-relative one, a
     * backslash form and a value with a control character are never honoured.
     */
    public static function isSafeReturnTo(string $returnTo): bool
    {
        if ($returnTo === '' || $returnTo[0] !== '/') {
            return false;
        }
        if (str_starts_with($returnTo, '//') || str_starts_with($returnTo, '/\\')) {
            return false;
        }

        return preg_match('/[\\\\\x00-\x1f\x7f]/', $returnTo) !== 1;
    }

    /** The default rule, widened — only for a value it refuses — by the integrator's predicate, if any. */
    private function returnToAllowed(string $returnTo): bool
    {
        if (self::isSafeReturnTo($returnTo)) {
            return true;
        }
        if ($this->allowReturnTo === null) {
            return false;
        }
        try {
            return ($this->allowReturnTo)($returnTo) === true;
        } catch (\Throwable) {
            return false; // a predicate that throws accepts nothing
        }
    }

    /**
     * The `Set-Cookie` value that sets (`$value` non-empty) or clears (`$value` empty,
     * `Max-Age=0`) the binding cookie. Built here, in ONE place, so no framework controller can
     * drift on attributes (§12.8 rule 1 (a), (b), (d)).
     */
    private function bindingCookieHeader(string $value): string
    {
        $name = $this->bindingCookieName();
        $attributes = $name === self::BINDING_COOKIE_LOOPBACK_NAME
            ? 'Path=/; HttpOnly; SameSite=Lax'
            : 'Path=/; HttpOnly; Secure; SameSite=Lax';
        $maxAge = $value === '' ? 0 : self::BINDING_COOKIE_MAX_AGE_SECONDS;

        return sprintf('%s=%s; %s; Max-Age=%d', $name, $value, $attributes, $maxAge);
    }

    /**
     * Step 1 — build the authorization request, park its state, and hand back the
     * redirect (CONTRACT.md §12.1 `oidc_begin`).
     *
     * Discovery is fetched through `oidcDiscover`, so its per-origin cache and
     * single-flight de-duplication apply and a busy login route does not hammer the
     * discovery endpoint (§12.3 rule 6).
     *
     * @param string|null $returnTo Optional application destination to restore after
     *        login; stored with the state entry and used as the post-login redirect
     *        when no explicit `$successRedirect` is given to {@see self::complete()}.
     *        Only a same-origin relative path is stored ({@see self::isSafeReturnTo()});
     *        anything else is DROPPED and the login proceeds as though none was given
     *        (§12.8 rule 3).
     *
     * @return OidcLoginOutcome A redirect to the IdP whose {@see OidcLoginOutcome::$setCookie}
     *         is the binding cookie the controller MUST send with it.
     */
    public function begin(?string $returnTo = null): OidcLoginOutcome
    {
        try {
            $configuration = $this->client->oidcDiscover();
            $request = $this->client->oidcBegin($configuration, $this->redirectUri, $this->scope);

            // §12.8 rule 1 (a): a NEW value on every login, never one the request presented —
            // a value an attacker could have planted beforehand must not become the binding.
            // The store keeps only its SHA-256.
            $binding = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');

            $this->store->save(new OidcStateEntry(
                state: $request->state,
                nonce: $request->nonce,
                codeVerifier: $request->codeVerifier,
                redirectUri: $this->redirectUri,
                returnTo: $returnTo !== null && $this->returnToAllowed($returnTo) ? $returnTo : null,
                bindingDigest: hash('sha256', $binding),
            ));

            return OidcLoginOutcome::redirect($request->url)->withSetCookie($this->bindingCookieHeader($binding));
        } catch (\Throwable $e) {
            // A login route that cannot reach AXIAM must fail closed with 503 rather
            // than redirect the browser somewhere half-built.
            $this->logger->debug('axiam_sdk.oidc: oidc login could not be started', [
                'reason' => $e->getMessage(),
            ]);

            return OidcLoginOutcome::error(503, 'oidc_unavailable', 'could not start the OIDC login flow');
        }
    }

    /**
     * Step 2 — validate the callback, consume the stored state, check it is the browser that
     * started the login, exchange the code, and hand back the post-login response
     * (CONTRACT.md §12.1 `oidc_exchange`, §12.8).
     *
     * Order (§12.8 rule 1 (c)): the IdP `error`, then missing `state`/`code`, then
     * **consume the entry**, then the binding check, then the exchange, then `$onSuccess`.
     * Consuming comes first so the `state` is single-use whatever happens next.
     *
     * Failure mapping (port-brief addendum item 19):
     * - IdP returned `$error` instead of a code → `401 authentication_failed`;
     * - `$state` or `$code` missing → `400 invalid_request`;
     * - `$state` unknown, already consumed, or expired → `401 authentication_failed`;
     * - `$bindingCookie` missing, the entry carries no `bindingDigest`, or the digest of the
     *   cookie differs (compared in constant time) → the SAME `401 authentication_failed`,
     *   with the SAME message, so the refusal does not say which check failed. The code is
     *   NOT exchanged (no request reaches the token endpoint) and `$onSuccess` is NOT
     *   called;
     * - any §12.4 ID-token failure or {@see \Axiam\Sdk\Core\OAuthProtocolError}
     *   (an {@see AuthError} sub-type) → `401 authentication_failed`;
     * - {@see NetworkError} → `503 oidc_unavailable`, never a silent success.
     *
     * EVERY outcome carries a clearing `Set-Cookie` for the binding cookie
     * ({@see OidcLoginOutcome::$setCookie}); the controller MUST send it (§12.8 rule 1 (d)).
     *
     * `$onSuccess`, when given, runs with the validated {@see OidcTokenSet}, the consumed
     * {@see OidcStateEntry} and — third — `$request`, the framework request that completed the
     * sign-in, exactly as the controller handed it over (§12.8 rule 2). It is where an
     * application establishes its OWN session (sign a cookie, write a session row, …) on THAT
     * request, with no ambient request context needed. This SDK deliberately does NOT do this
     * for you: what a session means is the application's decision. A two-parameter closure
     * keeps working: PHP ignores the extra argument.
     *
     * The post-login destination is `$successRedirect` when given, else the stored
     * `return_to` — but only if it is still a same-origin relative path
     * ({@see self::isSafeReturnTo()}); one that is not (an entry from a caller-supplied
     * store, or older glue) is not followed, and the JSON summary is returned instead
     * (§12.8 rule 3).
     *
     * @param string|null $bindingCookie The value of the cookie named
     *        {@see self::bindingCookieName()} on the callback request, or `null` when the
     *        request has none. A caller that passes none has every callback refused: there is
     *        no "binding disabled" mode.
     * @param mixed $request The framework request object, passed through to `$onSuccess`.
     * @param (\Closure(OidcTokenSet, OidcStateEntry, mixed): void)|null $onSuccess
     */
    public function complete(
        ?string $state,
        ?string $code,
        ?string $error = null,
        ?string $errorDescription = null,
        ?string $successRedirect = null,
        ?\Closure $onSuccess = null,
        ?string $bindingCookie = null,
        mixed $request = null,
    ): OidcLoginOutcome {
        return $this->withClearingCookie(
            $this->completeInner($state, $code, $error, $errorDescription, $successRedirect, $onSuccess, $bindingCookie, $request),
        );
    }

    /** Every callback response — success, the uniform 401 and every other error — clears the binding cookie. */
    private function withClearingCookie(OidcLoginOutcome $outcome): OidcLoginOutcome
    {
        return $outcome->withSetCookie($this->bindingCookieHeader(''));
    }

    private function completeInner(
        ?string $state,
        ?string $code,
        ?string $error,
        ?string $errorDescription,
        ?string $successRedirect,
        ?\Closure $onSuccess,
        ?string $bindingCookie,
        mixed $request,
    ): OidcLoginOutcome {
        if ($error !== null && $error !== '') {
            $this->logger->debug('axiam_sdk.oidc: idp returned an authorization error', ['error' => $error]);

            return OidcLoginOutcome::error(
                401,
                'authentication_failed',
                $errorDescription !== null && $errorDescription !== '' ? sprintf('%s: %s', $error, $errorDescription) : $error,
            );
        }

        if ($state === null || $state === '' || $code === null || $code === '') {
            return OidcLoginOutcome::error(400, 'invalid_request', 'callback is missing the state or code query parameter');
        }

        // Single-use consume (§12.3 rule 1) — ALWAYS before the binding check (§12.8 rule 1 (c)),
        // so a refused callback cannot leave the entry behind to be retried.
        $entry = $this->store->consume($state);
        if ($entry === null) {
            $this->logger->debug('axiam_sdk.oidc: no stored login state for the callback state', []);

            return self::uniformUnauthorized();
        }

        // §12.8 rule 1 (c): the callback must come from the browser that called the login
        // route. A missing cookie, an entry with no digest (a 1.67 store, older glue) or a
        // different digest is the SAME refusal as an unknown state, and the code is not
        // exchanged — it is the attacker's, and exchanging it would spend it and, on a
        // server that logs the exchange, attribute a sign-in to the victim's request.
        if (!$this->bindingMatches($entry, $bindingCookie)) {
            $this->logger->debug('axiam_sdk.oidc: callback is not bound to the browser that started the login', []);

            return self::uniformUnauthorized();
        }

        try {
            $tokens = $this->client->oidcExchange(
                code: $code,
                codeVerifier: $entry->codeVerifier,
                redirectUri: $entry->redirectUri,
                nonce: $entry->nonce,
            );
        } catch (NetworkError $e) {
            $this->logger->debug('axiam_sdk.oidc: token exchange transport failure', []);

            return OidcLoginOutcome::error(503, 'oidc_unavailable', 'the AXIAM token endpoint is unreachable');
        } catch (AuthError $e) {
            // AuthError (including OAuthProtocolError and every §12.4 reason code): a
            // login that cannot be proven is a failed login.
            $this->logger->debug('axiam_sdk.oidc: token exchange failed', ['reason' => $e->getMessage()]);

            return OidcLoginOutcome::error(401, 'authentication_failed', $e->getMessage());
        }

        if ($onSuccess !== null) {
            $onSuccess($tokens, $entry, $request);
        }

        // `return_to` is checked AGAIN here (§12.8 rule 3): the store may be the integrator's
        // and the entry older glue's, so what it holds is not trusted to have been validated.
        $returnTo = $entry->returnTo !== null && $this->returnToAllowed($entry->returnTo) ? $entry->returnTo : null;
        $destination = $successRedirect ?? $returnTo;
        if ($destination !== null && $destination !== '') {
            return OidcLoginOutcome::redirect($destination);
        }

        $sub = is_array($tokens->idClaims) && is_string($tokens->idClaims['sub'] ?? null) ? $tokens->idClaims['sub'] : null;

        return OidcLoginOutcome::json($sub, $tokens->expiresIn);
    }

    /** True when `$bindingCookie` is the value whose SHA-256 the entry holds (constant-time compare). */
    private function bindingMatches(OidcStateEntry $entry, ?string $bindingCookie): bool
    {
        if ($bindingCookie === null || $bindingCookie === '' || $entry->bindingDigest === null) {
            return false;
        }

        return hash_equals($entry->bindingDigest, hash('sha256', $bindingCookie));
    }

    /** The one 401 for an unknown/expired/used state and for a callback from another browser. */
    private static function uniformUnauthorized(): OidcLoginOutcome
    {
        return OidcLoginOutcome::error(401, 'authentication_failed', 'unknown, expired, or already-used login state');
    }
}
