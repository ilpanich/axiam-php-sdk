<?php

declare(strict_types=1);

/**
 * examples/oidc_login.php — demonstrates CONTRACT.md §12's OIDC/SSO relying-party
 * helpers directly on `AxiamClient`: `oidcDiscover` -> `oidcBegin` -> (browser redirect,
 * IdP callback) -> `oidcExchange`, plus `loginClientCredentials`, `introspect`, and
 * `revoke`.
 *
 * Uses ONLY the public `AxiamClient` API — no internal collaborator is touched
 * directly, exactly as `examples/login_mfa.php` does for the §1 login flow.
 *
 * **The caller owns the login state** (§12.3 rule 1): `oidcBegin()` returns
 * `state`/`nonce`/`codeVerifier` and stores NONE of them — this example keeps them in
 * plain local variables to show the shape, but a real web application must persist
 * them in its own HTTP session (or an `Axiam\Sdk\Oidc\OidcStateStoreInterface`, see
 * `examples/laravel_app/oidc_routes.php` / `examples/symfony_app/oidc_routes.yaml` for
 * the framework-glue version of this exact flow) between the redirect and the callback.
 *
 * Run: php examples/oidc_login.php
 * (requires a reachable AXIAM server configured as an OIDC provider; without a live
 * server this script demonstrates the calls up through `oidcBegin()`, which performs no
 * network I/O, then reports the expected connection failure for `oidcDiscover()`/
 * `oidcExchange()` — it is illustrative/compilable, not a live-server smoke test.)
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Core\OAuthProtocolError;

function envOr(string $key, string $fallback): string
{
    $value = getenv($key);

    return $value === false ? $fallback : $value;
}

$baseUrl = envOr('AXIAM_BASE_URL', 'https://localhost:8443');
$tenant = envOr('AXIAM_TENANT', 'acme'); // §5/D-13: tenant is a REQUIRED constructor arg
$customCa = getenv('AXIAM_CUSTOM_CA') ?: null; // §6/D-12: the ONLY TLS escape hatch

// CONTRACT.md §12: `oidcClientId`/`oidcClientSecret` configure the relying-party
// credentials used by every oidc*/introspect/revoke operation. `oidcClientSecret` is
// required only for `introspect`/`revoke`/`loginClientCredentials` (confidential-client
// operations, §12.1 note 4); a public client may omit it and still use
// `oidcDiscover`/`oidcBegin`/`oidcExchange`/`oidcRefresh`.
$client = new AxiamClient(
    baseUrl: $baseUrl,
    tenant: $tenant,
    customCa: $customCa,
    oidcClientId: envOr('AXIAM_OIDC_CLIENT_ID', 'my-app'),
    oidcClientSecret: getenv('AXIAM_OIDC_CLIENT_SECRET') ?: null,
    // §12.3 rule 4: /oauth2/* calls need a tenant_id UUID for their query parameter —
    // distinct from the tenant SLUG above, which only ever goes on the X-Tenant-ID
    // header. A real application resolves this from its own tenant registry.
    oidcTenantId: getenv('AXIAM_OIDC_TENANT_ID') ?: null,
);

// --- Step 1: discover the provider, then build the authorization request -----------
try {
    $configuration = $client->oidcDiscover();
    echo "Discovered issuer: {$configuration->issuer}\n";
} catch (AxiamException $e) {
    fwrite(STDERR, "oidcDiscover failed (expected without a live server): " . $e->getMessage() . "\n");
    exit(0);
}

$redirectUri = envOr('AXIAM_OIDC_REDIRECT_URI', 'https://app.example/auth/axiam/callback');
$request = $client->oidcBegin($configuration, $redirectUri, scope: 'openid profile');

// The caller persists these three values (e.g. in its own HTTP session, or via
// Axiam\Sdk\Oidc\MemoryOidcStateStore) between this redirect and the callback below —
// the SDK itself stores nothing (§12.3 rule 1).
$state = $request->state;
$nonce = $request->nonce;
$codeVerifier = $request->codeVerifier; // Sensitive<string> — never logged/printed raw

printf("Redirect the browser to:\n  %s\n", $request->url);
printf("Persist state=%s and nonce=%s (and the code verifier) until the callback.\n", $state, $nonce);

// --- Step 2: on the callback, after checking the returned `state` matches -----------
// (In a real application this is a SEPARATE HTTP request — the query parameters below
// stand in for what the IdP redirect would actually deliver.)
$callbackCode = getenv('AXIAM_OIDC_CALLBACK_CODE') ?: null;
if ($callbackCode !== null) {
    try {
        $tokens = $client->oidcExchange(
            code: $callbackCode,
            codeVerifier: $codeVerifier,
            redirectUri: $redirectUri,
            nonce: $nonce,
        );
        printf("Exchanged code for tokens; validated ID-token subject: %s\n", $tokens->idClaims['sub'] ?? '(no id_token)');
    } catch (AuthError $e) {
        // Covers every §12.4 ID-token failure reason code (invalid_alg, unknown_kid,
        // invalid_signature, invalid_issuer, invalid_audience, token_expired,
        // nonce_mismatch) AND an OAuthProtocolError (a subtype of AuthError) — never a
        // partially-trusted token set (§12.4 rule 7).
        fwrite(STDERR, sprintf("oidcExchange failed [%s]: %s\n", $e->getReason() ?? 'oauth2', $e->getMessage()));
    }
} else {
    echo "Set AXIAM_OIDC_CALLBACK_CODE to exercise oidcExchange() against a live server.\n";
}

// --- Service-account login, introspection, and revocation --------------------------
try {
    $serviceTokens = $client->loginClientCredentials(scope: 'reports:read');
    printf("Service-account access token acquired (expires in %ds).\n", $serviceTokens->expiresIn);

    $introspection = $client->introspect($serviceTokens->accessToken);
    printf("Introspection: active=%s\n", $introspection->active ? 'true' : 'false');

    $client->revoke($serviceTokens->accessToken);
    echo "Token revoked.\n";
} catch (OAuthProtocolError $e) {
    // error/errorDescription are also available individually: $e->error, $e->errorDescription
    fwrite(STDERR, "OAuth2 protocol error: " . $e->getMessage() . "\n");
} catch (AuthError $e) {
    fwrite(STDERR, "client-credentials flow failed (expected without a live server / oidcClientSecret): " . $e->getMessage() . "\n");
}
