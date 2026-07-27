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
 * outcome into that framework's redirect/JSON response. It performs no cookie/session
 * writing of its own and touches no framework request/response object.
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
     *        token material, `state`, `nonce`, or the verifier. Defaults to a silent
     *        {@see NullLogger}.
     */
    public function __construct(
        private readonly AxiamClient $client,
        private readonly OidcStateStoreInterface $store,
        private readonly string $redirectUri,
        private readonly string|array|null $scope = null,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {
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
     */
    public function begin(?string $returnTo = null): OidcLoginOutcome
    {
        try {
            $configuration = $this->client->oidcDiscover();
            $request = $this->client->oidcBegin($configuration, $this->redirectUri, $this->scope);
            $this->store->save(new OidcStateEntry(
                state: $request->state,
                nonce: $request->nonce,
                codeVerifier: $request->codeVerifier,
                redirectUri: $this->redirectUri,
                returnTo: $returnTo,
            ));

            return OidcLoginOutcome::redirect($request->url);
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
     * Step 2 — validate the callback, consume the stored state, exchange the code, and
     * hand back the post-login response (CONTRACT.md §12.1 `oidc_exchange`).
     *
     * Failure mapping (port-brief addendum item 19):
     * - IdP returned `$error` instead of a code → `401 authentication_failed`;
     * - `$state` or `$code` missing → `400 invalid_request`;
     * - `$state` unknown, already consumed, or expired → `401 authentication_failed`
     *   (all three are deliberately indistinguishable to the client);
     * - any §12.4 ID-token failure or {@see \Axiam\Sdk\Core\OAuthProtocolError}
     *   (an {@see AuthError} sub-type) → `401 authentication_failed`;
     * - {@see NetworkError} → `503 oidc_unavailable`, never a silent success.
     *
     * `$onSuccess`, when given, runs with the validated {@see OidcTokenSet} and the
     * consumed {@see OidcStateEntry} — the hook where an application establishes its
     * OWN session (sign a cookie, write a session row, …). This SDK deliberately does
     * NOT do this for you: what a session means is the application's decision.
     * `$returnTo` is stored but is explicitly the caller's own open-redirect
     * responsibility (port-brief addendum item 19) — this class never validates it.
     *
     * @param (\Closure(OidcTokenSet, OidcStateEntry): void)|null $onSuccess
     */
    public function complete(
        ?string $state,
        ?string $code,
        ?string $error = null,
        ?string $errorDescription = null,
        ?string $successRedirect = null,
        ?\Closure $onSuccess = null,
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

        // Single-use consume (§12.3 rule 1): a replayed callback finds nothing.
        $entry = $this->store->consume($state);
        if ($entry === null) {
            $this->logger->debug('axiam_sdk.oidc: no stored login state for the callback state', []);

            return OidcLoginOutcome::error(401, 'authentication_failed', 'unknown, expired, or already-used login state');
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
            $onSuccess($tokens, $entry);
        }

        $destination = $successRedirect ?? $entry->returnTo;
        if ($destination !== null && $destination !== '') {
            return OidcLoginOutcome::redirect($destination);
        }

        $sub = is_array($tokens->idClaims) && is_string($tokens->idClaims['sub'] ?? null) ? $tokens->idClaims['sub'] : null;

        return OidcLoginOutcome::json($sub, $tokens->expiresIn);
    }
}
