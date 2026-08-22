<?php

declare(strict_types=1);

/**
 * examples/par_login.php — CONTRACT.md §26, Pushed Authorization Requests (RFC 9126).
 *
 * PAR moves the authorization request off the browser. Instead of putting `scope`,
 * `redirect_uri`, `state` and the PKCE challenge into a URL the user agent carries, the
 * client POSTs them straight to AXIAM over an authenticated back channel and puts an
 * opaque `request_uri` in the redirect. What travels through the browser is then a random
 * string that cannot be edited into meaning something else.
 *
 * A FAPI 2.0 client has no choice: `profile: "fapi2"` refuses a registration that does not
 * set `require_par`, so such a client cannot authorize any other way (§21.1).
 *
 * Run: php examples/par_login.php
 * (illustrative/compilable — a failure here is expected in a sandbox with no live server.)
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Core\OAuthProtocolError;
use Axiam\Sdk\Oidc\OidcConfiguration;
use Axiam\Sdk\Oidc\PushedAuthorizationRequest;

function envOr(string $key, string $fallback): string
{
    $value = getenv($key);

    return $value === false ? $fallback : $value;
}

$redirectUri = envOr('AXIAM_REDIRECT_URI', 'https://app.example.com/callback');

$client = new AxiamClient(
    baseUrl: envOr('AXIAM_BASE_URL', 'https://localhost:8443'),
    tenant: envOr('AXIAM_TENANT', 'acme'),
    oidcClientId: envOr('AXIAM_CLIENT_ID', 'app'),
    oidcClientSecret: envOr('AXIAM_CLIENT_SECRET', 's3cret'),
    oidcTenantId: envOr('AXIAM_TENANT_ID', '00000000-0000-0000-0000-000000000000'),
);

try {
    $config = $client->oidcDiscover();

    // §26 is optional, so a server may advertise no endpoint at all. The SDK refuses
    // client-side rather than concatenating a URL onto the issuer and POSTing a
    // fully-formed authorization request at a 404 (§12.7.2 rule 1).
    if ($config->pushed_authorization_request_endpoint === null) {
        echo "this server does not support RFC 9126 — fall back to the plain oidcBegin redirect\n";

        return;
    }

    pushAndRedirect($client, $config, $redirectUri);
} catch (AxiamException $e) {
    echo 'no reachable server: ' . $e->getMessage() . "\n";
}

function pushAndRedirect(AxiamClient $client, OidcConfiguration $config, string $redirectUri): void
{
    // oidcBegin still runs first, and still owns state/nonce/PKCE. §26.2 rule 1 forbids a
    // second generator: two sources for any of those are two things that can disagree.
    $begun = $client->oidcBegin($config, $redirectUri, 'openid profile');

    try {
        $pushed = $client->oidcPar($begun, $redirectUri, $config, 'openid profile');
    } catch (OAuthProtocolError $e) {
        echo 'the server rejected the push: ' . $e->error . "\n";

        return;
    } catch (AuthError $e) {
        echo 'no PAR endpoint: ' . $e->getMessage() . "\n";

        return;
    }
    // Note there is no retry here, and there must not be. This is a POST that creates
    // server state, so it falls outside §16.2's read-only eligibility. The safe recovery
    // is a fresh push, which costs one round trip and cannot double-consume anything
    // (§26.2 rule 4).

    // The URL carries EXACTLY client_id and request_uri. The server refuses a request that
    // mixes a request_uri with inline authorization parameters rather than merging them —
    // an attacker supplies the inline value they want and lets the pushed copy satisfy
    // whichever check reads the other one. Re-adding scope "for compatibility" restores
    // the attack (§26.2 rule 2).
    echo "redirect the browser to: {$pushed->url}\n";
    echo "the handle expires in {$pushed->expiresIn}s\n";

    // Persist these three exactly as a non-PAR login would — the redirect being opaque
    // changes nothing about the callback's obligations. A real application uses its own
    // session, or an OidcStateStoreInterface; the SDK stores nothing (§12.3 rule 1).
    echo "  stashed state/nonce/verifier for the callback\n";

    completeTheCallback($client, $config, $pushed, $redirectUri);
}

function completeTheCallback(
    AxiamClient $client,
    OidcConfiguration $config,
    PushedAuthorizationRequest $pushed,
    string $redirectUri,
): void {
    $returnedState = envOr('AXIAM_STATE', 'the-state-from-the-redirect');
    if (!hash_equals($pushed->state, $returnedState)) {
        // state is not a secret (§12.3 rule 2), but this comparison is the CSRF guard, so
        // it is done in constant time.
        echo "state mismatch — drop this callback on the floor\n";

        return;
    }

    try {
        // The exchange is the ordinary §12 one. The request_uri is spent by now: it is
        // single-use, and a second redirect through it fails.
        $tokens = $client->oidcExchange(
            envOr('AXIAM_AUTH_CODE', 'the-code-from-the-redirect'),
            $pushed->codeVerifier,
            $redirectUri,
            $pushed->nonce,
            configuration: $config,
        );
        echo 'signed in, id token subject: ' . ($tokens->idClaims?->sub ?? '(none)') . "\n";
    } catch (AxiamException $e) {
        echo 'the exchange did not complete: ' . $e->getMessage() . "\n";
    }
}
