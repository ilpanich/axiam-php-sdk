# axiam/axiam-sdk (PHP)

[![CI](https://github.com/ilpanich/axiam-php-sdk/actions/workflows/sdk-ci-php.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-php-sdk/actions/workflows/sdk-ci-php.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-php-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-php-sdk?branch=main)
[![Packagist Version](https://img.shields.io/packagist/v/axiam/axiam-sdk.svg)](https://packagist.org/packages/axiam/axiam-sdk)
[![PHP Version](https://img.shields.io/packagist/php-v/axiam/axiam-sdk.svg)](https://packagist.org/packages/axiam/axiam-sdk)
[![Docs](https://img.shields.io/badge/docs-phpDocumentor-blue.svg)](https://ilpanich.github.io/axiam-php-sdk/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Official PHP client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended
Identity and Authorization Management.

## Package identity

- **Packagist package:** `axiam/axiam-sdk`
- **Registry:** [packagist.org/packages/axiam/axiam-sdk](https://packagist.org/packages/axiam/axiam-sdk) _(reserved, not yet published)_
- **Source:** [github.com/ilpanich/axiam-php-sdk](https://github.com/ilpanich/axiam-php-sdk)
- **API reference:** [ilpanich.github.io/axiam-php-sdk](https://ilpanich.github.io/axiam-php-sdk/)
- **License:** Apache-2.0
- **PHP:** `>=8.1`

## Install

```bash
composer require axiam/axiam-sdk
```

## Quickstart

```php
<?php

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;

// `tenant` is a REQUIRED constructor argument — AXIAM is multi-tenant and there is no
// default tenant. There is no overload that lets you omit it. `login()`/`refresh()` also
// require ORGANIZATION context (CONTRACT.md §5.1): a tenant slug is only unique WITHIN an
// organization, so supply `orgSlug` (or the org UUID via `orgId`) — the server rejects a
// login without one (HTTP 400 "must provide org_id or org_slug").
$client = new AxiamClient(
    baseUrl: 'https://your-axiam-instance',
    tenant: 'acme',
    orgSlug: 'acme',
);

try {
    $result = $client->login('alice@acme.test', 'correct horse battery staple');
} catch (AuthError $e) {
    // typed exception hierarchy (AuthError/AuthzError/NetworkError), never a bare status code
    exit(1);
}

if ($result->mfaRequired) {
    $result = $client->verifyMfa($result->challengeToken, $totpCode);
}

// Same $client instance — the authenticated session's cookies/CSRF are shared automatically.
// `can(action, resource)` — same argument order as every other AXIAM SDK (CONTRACT.md §1).
$allowed = $client->can('read', 'documents');
```

See [`examples/login_mfa.php`](examples/login_mfa.php) and
[`examples/rest_authz.php`](examples/rest_authz.php) for complete, runnable versions of
this flow.

## Runtime requirements — read this before using gRPC or the AMQP worker (SC#3)

**The REST transport (login/MFA/refresh/logout/`checkAccess`/`can`/`batchCheck` over HTTP)
works on any PHP runtime, including standard PHP-FPM.** This is the default and requires
no special deployment.

**gRPC and the AMQP consumer are different — they require a long-running PHP runtime**
(Swoole, RoadRunner, or a plain long-lived CLI process), **not standard PHP-FPM**:

- **gRPC** (`checkAccess`/`can`/`batchCheck` over `Axiam\Sdk\Grpc\AuthzGrpcClient`) is an
  opt-in performance transport, guarded by `extension_loaded('grpc')`. On a share-nothing
  per-request runtime like PHP-FPM, there is no benefit to a persistent gRPC channel — every
  request tears the process down anyway — so the SDK **automatically falls back to the
  always-available REST transport** (`POST /api/v1/authz/check[/batch]`) whenever the `grpc`
  PECL extension is absent, or when the client is explicitly configured `restOnly: true`.
  Authorization checks **always work**; gRPC is purely a latency optimization for
  long-running workers that can reuse one channel across many requests. See
  [`examples/grpc_checkaccess.php`](examples/grpc_checkaccess.php).
- **`getUserInfo()` is gRPC-ONLY** (CONTRACT.md §1.1, contract 1.3) — the low-latency
  counterpart of the server's REST `GET /oauth2/userinfo`, invoking
  `axiam.v1.UserInfoService/GetUserInfo` on the same gRPC channel. Unlike
  `checkAccess`/`can`/`batchCheck` it has **no REST fallback**: on a runtime without the
  `grpc` extension (or with `restOnly: true`) it raises `NetworkError` rather than degrading.
  It requires a prior successful `login()` (calling it with no token raises `AuthError`
  before any wire call); a gRPC `UNAUTHENTICATED` response drives the shared single-flight
  refresh (§9) and retries once. It returns a typed `Axiam\Sdk\Auth\UserInfo`
  (`sub`, `tenantId`, `orgId`, and `?email`/`?preferredUsername` — the latter two present
  only when the token carries the `email`/`profile` scope).
- **The AMQP consumer** (`Axiam\Sdk\Amqp\Consumer`, run via
  [`bin/axiam-amqp-worker.php`](bin/axiam-amqp-worker.php)) is a standalone CLI-oriented
  blocking consume loop — **it is not a web-request path at all** and must never be invoked
  from an FPM worker.

**Process supervision is your responsibility for the AMQP worker.** `php-amqplib` (unlike
the Go/C# sibling SDKs' AMQP clients) has **no built-in automatic reconnection** — if the
broker connection drops (broker restart, network blip), the worker process exits rather
than silently retrying forever. Run it under a process supervisor that restarts it on
failure: systemd (`Restart=on-failure`), a RoadRunner worker-pool respawn, or a Docker
`restart: unless-stopped` policy. A worker with no supervision will simply stop consuming
messages after the first connection loss and never recover on its own.

## Contract conformance

This SDK conforms to [`CONTRACT.md`](CONTRACT.md) §1–§13 and §12.7, §14, §15 (including
§6.1 mTLS, contract 1.3; §12 OIDC/SSO helpers, contract 1.4; §13 webhook-signature
verification) — the binding,
cross-language behavioral contract every
AXIAM SDK implements: camelCase method names (§1) — including the gRPC-only `getUserInfo`
operation (§1.1) — the `AuthError`/`AuthzError`/`NetworkError` typed exception hierarchy (§2,
extended by the §12 `OAuthProtocolError` `AuthError` sub-type), non-browser `X-CSRF-Token`
response-header capture (§3), a shared Guzzle `CookieJar` (§4), a required `tenant`
constructor parameter with no default (§5), strict TLS with `customCa` as the only
server-verification escape hatch (§6) plus optional client-certificate mutual TLS (§6.1),
`Sensitive`-wrapped token redaction (§7), HMAC-SHA256-verified AMQP
messages (§8), single-flight refresh concurrency safety (§9), framework
middleware/subscriber integration (§10), declarative per-endpoint authorization
helpers (§11, see below), OIDC/SSO relying-party helpers (§12, see below), and
webhook-signature verification (§13, see below).

## Framework integration

### Laravel — auto-discovered, zero-config

```bash
composer require axiam/axiam-sdk
```

That's it. Laravel's own [package auto-discovery](https://laravel.com/docs/packages#package-discovery)
reads this package's `composer.json` `extra.laravel.providers` entry and registers
`Axiam\Sdk\Laravel\AxiamServiceProvider` automatically — no `config/app.php` edit, no
`bootstrap/providers.php` entry. You get the `axiam.auth` authentication middleware and
the `axiam` Gate ability (`can:axiam,<resource>,<action>` → 403 on deny) out of the box.
See [`examples/laravel_app/README.md`](examples/laravel_app/README.md) for the full
middleware + Gate example, including a runnable 401/403/200 route.

### Symfony — MANUAL registration is required

**Unlike Laravel, the Symfony bridge does NOT auto-discover itself.** Symfony has no
equivalent to Laravel's `extra.laravel.providers` mechanism without a published Symfony
Flex "recipe" (out of scope for this SDK). After `composer require axiam/axiam-sdk`, a
Symfony application must perform two manual steps:

1. Add `Axiam\Sdk\Symfony\AxiamBundle::class => ['all' => true]` to `config/bundles.php`.
2. Tag `Axiam\Sdk\Symfony\AxiamAuthSubscriber` (`kernel.event_subscriber`) and
   `Axiam\Sdk\Symfony\AxiamVoter` (`security.voter`) in `config/services.yaml`.

`AxiamBundle` itself ships no container extension — registering the bundle alone does
**not** wire the subscriber or voter; both manual steps are required. This is a genuinely
different (not lesser) developer experience than Laravel's — do not expect
`composer require` alone to do anything on Symfony. Full copy-pasteable
`config/bundles.php`/`config/services.yaml` snippets and a runnable
401/403/200 controller example are in
[`examples/symfony_app/README.md`](examples/symfony_app/README.md).

## Local token verification (CONTRACT.md §10.1)

Both framework guards — the Laravel `AxiamMiddleware` and the Symfony
`AxiamAuthSubscriber` — verify access tokens through one implementation,
`Axiam\Sdk\Auth\JwksVerifier::verify()`, which applies the **complete** §10.1 minimum
local-verification set. Every rule fails closed: a required claim that is absent,
unparseable, or of the wrong JSON type is a rejection, never a skipped check.

| # | Claim | What the verifier does |
|---|---|---|
| 1 | signature | Verified against the org-wide JWKS with `alg` pinned to `EdDSA` **before** any `kid` lookup, so `alg: none` and HS-family confusion are rejected without ever consulting a key. |
| 2 | `exp` | **Required.** No `exp`, or an `exp` that is not a JSON number, is rejected. An absent `exp` is a permanent credential, not an absent constraint. |
| 3 | `nbf` | Honoured when present; an `nbf` in the future is rejected. An absent `nbf` is valid. |
| 4 | `tenant_id` | **Required and asserted** against the **configured** tenant. An absent claim — or an empty configured tenant — is rejected. |
| 5 | `iss` | Checked **only** when `axiam.expected_issuer` / `AXIAM_EXPECTED_ISSUER` is set. Unset by default. |
| 6 | `aud` | Checked **only** when `axiam.expected_audience` / `AXIAM_EXPECTED_AUDIENCE` is set. Unset by default; both the single-string and array forms are honoured. |
| 7 | clock skew | `JwksVerifier::CLOCK_SKEW_LEEWAY_SECONDS` — a named 60-second constant applied to rules 2 and 3. Deliberately **not** operator-configurable. |

**What `firebase/php-jwt` does versus what §10.1 requires.** `JWT::decode()` validates
`nbf`/`iat`/`exp` and rejects a non-numeric `exp` — but only when the claim is *present*
(`isset($payload->exp) && …`), so a token with **no** `exp` at all passes straight
through it. Its `is_numeric()` test also accepts a quoted `"1700000000"`, which is a JSON
string rather than an RFC 7519 NumericDate. And `JWT::$leeway` is a public mutable static
that any code in the process can set to an unbounded value. This SDK therefore enforces
rules 2, 3 and 7 itself rather than inheriting the library's behaviour, and pins
`JWT::$leeway` to its own named constant for the duration of every decode.

**The `X-Tenant-ID` request header narrows; it never overrides.** The token's `tenant_id`
is asserted against the tenant the application was *configured* with. When the request
also carries `X-Tenant-ID`, that header must agree with the verified claim — it can never
select which tenant is expected, because it is attacker-controlled and doing so would
make the check vacuous.

`iss` and `aud` are conditional and default to unset; no issuer or audience is hardcoded
anywhere. Configure them when your deployment has an expectation to assert — an app
guarding a user-facing resource server should generally expect `axiam:user`:

```php
// config/axiam.php (Laravel) — or the AXIAM_EXPECTED_* environment variables.
return [
    'base_url' => env('AXIAM_BASE_URL'),
    'tenant'   => env('AXIAM_TENANT'),

    // CONDITIONAL (§10.1 rules 5 and 6). Omit either to skip that check entirely.
    'expected_issuer'   => env('AXIAM_EXPECTED_ISSUER'),
    'expected_audience' => env('AXIAM_EXPECTED_AUDIENCE'),
];
```

## Declarative authorization helpers

CONTRACT.md §11 adds a per-endpoint authorization layer on top of the §10
authentication guard above: three PHP 8 attributes in `Axiam\Sdk\Attributes` —
`#[RequireAuth]`, `#[RequireAccess(action: ..., resourceParam: ...)]`, and
`#[RequireRole(...)]` — enforced by a single shared `Axiam\Sdk\AccessEnforcer` that
BOTH framework bridges delegate to, so Laravel and Symfony applications get
byte-identical semantics.

```php
use Axiam\Sdk\Attributes\RequireAccess;

final class DocumentController
{
    // Resolves the resource UUID from the {id} route parameter, checks 'read' for
    // the REQUEST'S authenticated user (never the shared AxiamClient's own session),
    // and returns 401/400/403/503 automatically on failure.
    #[RequireAccess(action: 'read', resourceParam: 'id')]
    public function show(string $id) { /* ... */ }
}
```

- **Symfony**: tag `Axiam\Sdk\Symfony\AxiamAccessAttributeListener`
  (`kernel.event_subscriber`) in `config/services.yaml`, alongside
  `AxiamAuthSubscriber`/`AxiamVoter` — see
  [`examples/symfony_app/services.yaml`](examples/symfony_app/services.yaml) and
  [`examples/symfony_app/DocumentController.php`](examples/symfony_app/DocumentController.php).
- **Laravel**: the `axiam.access` route-middleware alias (registered automatically by
  `AxiamServiceProvider`, same as `axiam.auth`) supports the attribute style above AND
  a string-param style needing no attribute at all —
  `->middleware('axiam.access:read')` (`action`, then optional `scope`,
  `resourceParam`, defaulting to `'id'`) — see
  [`examples/laravel_app/routes.php`](examples/laravel_app/routes.php).

Semantics (identical in both bridges, CONTRACT.md §11.2): `require_access` runs
strictly AFTER authentication — a missing identity is 401, never a second token
verification. The resource id is a UUID resolved from (in order) a static literal, a
route parameter, or a resolver callback; unresolvable is 400, never a silent allow. A
denied check is 403; a transport failure fails CLOSED with 503 (never allows).
`checkAccess` is always called with the REQUEST's authenticated `user_id` as the
subject — not whatever session the shared `AxiamClient` itself might separately hold.
`#[RequireRole(...)]` is a LOCAL, no-server-round-trip check against the verified
identity's roles — coarser than `#[RequireAccess]` and not a substitute for it. No
decision is ever cached, and no token material appears in any error output.

## OIDC / SSO relying-party helpers (CONTRACT.md §12)

Nine operations, directly on `AxiamClient`, let this SDK act as an OIDC/OAuth2
**relying party** against AXIAM's own OIDC provider — "Login with AXIAM"
(authorization-code + PKCE), service-account `client_credentials`, token
introspection/revocation, and upstream-IdP federation SSO:

| Method | Wire call | What it does |
|---|---|---|
| `oidcDiscover()` | `GET /.well-known/openid-configuration` | Fetch the discovery document (cached per origin, ≥5 min TTL, single-flight). |
| `oidcBegin($configuration, $redirectUri, scope: ..., extraParams: ...)` | *(none — pure local computation)* | Build the authorization URL + a fresh `state`/`nonce`/PKCE `code_verifier`. |
| `oidcExchange($code, $codeVerifier, $redirectUri, $nonce, ...)` | `POST /oauth2/token` (`authorization_code`) | Exchange a code for a token set; validates the ID token in full (§12.4). |
| `oidcRefresh($refreshToken, ...)` | `POST /oauth2/token` (`refresh_token`) | Refresh an OIDC token set — distinct from, but §9-guard-sharing with, `refresh()`. |
| `loginClientCredentials(...)` | `POST /oauth2/token` (`client_credentials`) | Service-account machine-to-machine login. |
| `introspect($token, ...)` | `POST /oauth2/introspect` | RFC 7662 — is this token active, and what does it carry? |
| `revoke($token, ...)` | `POST /oauth2/revoke` | RFC 7009 — revoke a token (idempotent: any `200` is success). |
| `ssoStart($federationConfigId, $redirectUri, ...)` | `POST /api/v1/auth/federation/oidc/start` | Step 1 of upstream-IdP federation SSO. |
| `ssoComplete($state, $code)` | `POST /api/v1/auth/federation/oidc/callback` | Step 2 — session arrives as `Set-Cookie`, captured via the §4 cookie jar. |

```php
use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;

$client = new AxiamClient(
    baseUrl: 'https://api.axiam.example',
    tenant: 'acme',
    oidcClientId: 'my-app',
    oidcClientSecret: getenv('AXIAM_OIDC_CLIENT_SECRET') ?: null, // omit for a public client
    oidcTenantId: '11111111-1111-1111-1111-111111111111', // UUID for the /oauth2/* query param (§12.3 rule 4)
);

$configuration = $client->oidcDiscover();
$request = $client->oidcBegin($configuration, 'https://app.example/callback', scope: 'openid profile');
// Persist $request->state / $request->nonce / $request->codeVerifier YOURSELF — see below.
// ...redirect the browser to $request->url...

// On the callback, having checked the IdP's `state` matches:
try {
    $tokens = $client->oidcExchange(
        code: $callbackCode,
        codeVerifier: $request->codeVerifier,
        redirectUri: 'https://app.example/callback',
        nonce: $request->nonce,
    );
} catch (AuthError $e) {
    // $e->getReason() is one of the §12.4 codes (invalid_alg, unknown_kid,
    // invalid_signature, invalid_issuer, invalid_audience, token_expired,
    // nonce_mismatch) when this was an ID-token validation failure, or an
    // Axiam\Sdk\Core\OAuthProtocolError (an AuthError sub-type — existing
    // catch(AuthError) blocks keep working) carrying ->error/->errorDescription.
}
echo $tokens->idClaims['sub']; // the validated ID-token subject
```

**The caller owns the login state (§12.3 rule 1).** `oidcBegin()` returns `state`,
`nonce`, and a `Sensitive`-wrapped `codeVerifier`; the SDK stores **none** of them in any
implicit cache. Persist all three yourself between the redirect and the callback (your
own HTTP session, or `Axiam\Sdk\Oidc\MemoryOidcStateStore` — a single-use, 10-minute-TTL
reference `OidcStateStoreInterface` implementation the Laravel/Symfony glue below uses).
`state`/`nonce` are plain strings (not secrets, §12.3 rule 2); `codeVerifier`,
`access_token`, `refresh_token`, `id_token`, and `client_secret` are always
`Sensitive`-wrapped (§12.5) and redacted from `__toString()`/`var_dump()`/`json_encode()`.

**"Login with AXIAM" framework glue** (optional, **off by default** on both frameworks —
see [`examples/laravel_app/oidc_routes.php`](examples/laravel_app/oidc_routes.php) /
[`examples/symfony_app/oidc_services.yaml`](examples/symfony_app/oidc_services.yaml) +
[`oidc_routes.yaml`](examples/symfony_app/oidc_routes.yaml)):
- **Laravel**: `Route::axiamOidcLogin('/auth/axiam/login', '/auth/axiam/callback')` — a
  route macro registered by `AxiamServiceProvider::boot()` — wires
  `Axiam\Sdk\Laravel\OidcLoginController`/`OidcCallbackController` onto both paths in one
  call. Configure via `axiam.oidc.*` config keys or `AXIAM_OIDC_*` env vars
  (`client_id`, `client_secret`, `tenant_id`, `redirect_uri`, `scope`).
- **Symfony**: manually register `Axiam\Sdk\Symfony\OidcLoginController`/
  `OidcCallbackController` as services (see `oidc_services.yaml`) and add the two routes
  (see `oidc_routes.yaml`) — no auto-discovery, same as the rest of the Symfony bridge.
- Both bridges share ONE framework-agnostic core, `Axiam\Sdk\Oidc\OidcLoginFlow`, so
  the 400/401/503 failure mapping (malformed callback / IdP error / unknown state /
  ID-token or OAuth2 failure / AXIAM unreachable) is byte-identical between them.

## Device authorization grant (CONTRACT.md §14)

RFC 8628 — signing in a device that cannot show a browser: a TV, a CLI, a headless
commissioning tool.

```php
$tokens = $client->deviceLogin(
    onUserCode: function (DeviceAuthorization $a): void {
        // Called BEFORE the first poll. Display it however the device can — screen,
        // QR code, e-ink panel. The SDK never prints it for you.
        printf("visit %s and enter %s\n", $a->verificationUri, $a->userCode);
    },
    scope: 'openid profile',
);
```

`deviceAuthorize()` and `devicePoll()` are also public, for an application driving its own
loop. The polling rules are where implementations go wrong:

- **`slow_down` raises the interval permanently.** An SDK that backs off for one round and
  returns to the original interval will be told to slow down again, forever.
- **`access_denied` and `expired_token` stay distinct.** A human said no, versus nobody
  answered — the only information the device can act on.
- **Polling stops at `expiresIn`**, even if the server has not yet said `expired_token`.
- **A `5xx` mid-poll is not terminal.** A server restart must not lose a grant the user has
  already approved.

`deviceCode` is `Sensitive`; `userCode` deliberately is not — it exists to be read aloud,
and wrapping it would defeat the one thing it is for. `deviceAuthorize()` sends no
`client_secret` and does not refuse a client built without one.

`deviceLogin()` takes an injectable `$sleep`, so the §14.2 interval arithmetic is testable
exactly rather than in wall-clock time. Per §14.3 rule 4 it **returns** the token set;
`$adoptAsCredential` is the same opt-in flag `loginClientCredentials()` uses.

## Token exchange (CONTRACT.md §15)

RFC 8693 — a service holding a user's token exchanging it for a *narrower* one before
calling the next service.

```php
$exchanged = $client->tokenExchange(
    subjectToken: $userToken,
    scopes: ['orders:read'],
    audience: 'orders-service',
);
```

Most of what this method does is refuse to be helpful:

- **No default `$actorToken`.** Passing `null` asks for *impersonation*; the SDK will not
  quietly substitute the client's own session token and turn that into a delegation.
- **No auto-narrowing after `invalid_scope`.** The server refuses rather than silently
  narrowing precisely so the caller finds out here.
- **No refresh token, ever** — `ExchangedToken` has no such property. Re-run the exchange.
- **No adoption**, and no flag to enable it — a MUST NOT, where `loginClientCredentials()`
  adoption is a MAY.

## Logout — RP-initiated and back-channel (CONTRACT.md §12.7)

`logoutUrl()` builds the redirect; `verifyLogoutToken()` validates a token the OP **pushed**
to your back-channel endpoint.

```php
$url = $client->logoutUrl($storedIdToken);

// …and at your registered backchannel_logout_uri:
$verified = $client->verifyLogoutToken($logoutToken);
if ($verified->sid !== null) {
    endSession($verified->sid);   // that session ONLY
}
```

The verifier is where the security weight sits — the input arrives unsolicited and instructs
you to terminate a session. It checks the signature (same JWKS path and same EdDSA/`kid`
discipline as §12.4), `iss`, `aud`, that `events` carries the back-channel-logout key (**the
only thing separating a logout token from an ID token**), that `nonce` is *absent* (its
presence is how an ID token gets replayed as one), that something is named, and freshness.

It returns `sid`/`sub`/`jti` rather than a bare `bool`: you have to know *which* session to
end. **Dedup on `jti` yourself** — delivery is at-least-once, so a valid token legitimately
arrives twice; the SDK has no durable store and an in-memory guard would silently drop a
real second logout after a restart.

## Decision reason codes (CONTRACT.md §11 rule 9)

`AccessDecision::$reasonCode` distinguishes `no_grant` ("ask an admin for access") from
`denied_by_rule` ("an admin has already decided") — opposite instructions to the person on
the other end, which is why the contract forbids collapsing them into a bare `false`.

`checkAccess()`/`can()`/`batchCheck()` keep returning `bool`: those signatures predate the
field and cannot carry it. **`checkAccessDecision()` and `batchCheckDecisions()`** return the
full decision. `ReasonCode` holds the three defined values as class constants rather than an
enum, so an unrecognised code is surfaced verbatim and never changes `$allowed`.

## Webhook signature verification (CONTRACT.md §13)

AXIAM signs every webhook delivery with a Stripe-style signed timestamp. Verify it with
`AxiamWebhooks::verify()` before trusting a payload:

```php
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Webhook\AxiamWebhooks;
use Axiam\Sdk\Webhook\WebhookVerificationException;

// Read the RAW body BEFORE any framework parses it as JSON.
$rawBody = file_get_contents('php://input');

try {
    $event = AxiamWebhooks::verify(
        new Sensitive($webhookSecret),
        $_SERVER['HTTP_X_AXIAM_SIGNATURE'] ?? '',
        $rawBody,
    );
} catch (WebhookVerificationException $e) {
    http_response_code(400);
    return;
}

// $event->eventType, $event->deliveryId, $event->timestamp, $event->body
```

**The raw body is mandatory.** The MAC covers the exact bytes AXIAM sent, so
`json_encode(json_decode($body))` — which can reorder keys, change whitespace, or re-escape
`/` as `\/` — will fail verification even though the payload is semantically identical. In
Laravel use `$request->getContent()`; in Symfony, `$request->getContent()`. Never re-encode.

Behaviour: HMAC-SHA256 over `<timestamp>.<raw_body>`, compared in constant time
(`hash_equals`) on the decoded bytes; a header carrying no `v1` is always a failure; the
freshness window is two-sided and defaults to 300 seconds, so a future-dated timestamp is
rejected just like a stale one. Multiple `v1` values are accepted to support secret
rotation. Use the `X-Axiam-Delivery` header as an at-least-once dedup key — a retry replays
a valid signature inside the freshness window.

## TLS policy

Guzzle's `verify` option is **always `true`** (strict TLS, system trust roots) unless a
`customCa` path (a PEM CA-bundle **file path**, never a boolean) is supplied to
`AxiamClient`'s constructor — the **only** escape hatch. There is no `verify: false` code
path anywhere in this SDK's source, examples, or tests; CI enforces this with a dedicated
grep gate (`.github/workflows/sdk-ci-php.yml`) that fails the build if any TLS-bypass
pattern (other than the `customCa` exception) is ever introduced.

### mTLS / client certificates (CONTRACT.md §6.1)

For IoT devices and service accounts that authenticate by **mutual TLS**, supply an X.509
client identity (signed by the tenant's organization CA) via the `clientCert`/`clientKey`
constructor parameters — both **PEM strings** (`clientCert` is the certificate chain,
`clientKey` its private key, PKCS#8 or PKCS#1):

```php
use Axiam\Sdk\AxiamClient;

$client = new AxiamClient(
    baseUrl: 'https://api.axiam.example',
    tenant:  'acme',
    clientCert: file_get_contents('/secure/device.crt.pem'),
    clientKey:  file_get_contents('/secure/device.key.pem'),
);
```

The identity is applied to **both transports** of that client instance: the REST Guzzle
clients (as `cert`/`ssl_key`) and any gRPC channel (via
`\Grpc\ChannelCredentials::createSsl(rootCerts, privateKey, certChain)`). mTLS is **opt-in**;
omitting it leaves the default bearer-cookie behavior unchanged. Presenting a client
certificate is strictly **additive** — it **never** relaxes server verification, so the
strict-TLS policy above still holds. `clientCert` and `clientKey` are **all-or-nothing**:
supplying exactly one, or a non-PEM value, throws `InvalidArgumentException` at construction.
The private key is secret material (§7): it is held behind `Sensitive`, written only to a
short-lived `0600` temp file cURL reads, cleaned up when the client is destroyed, and never
appears in any log, exception, or debug output.

## Sensitive value redaction

Token-carrying values (access tokens, refresh tokens, MFA challenge tokens, and — per
CONTRACT.md §12.5 — OIDC `id_token`s, `client_secret`s, and PKCE `code_verifier`s) are
wrapped in
`Axiam\Sdk\Core\Sensitive`. Its `__toString()` and `jsonSerialize()` always return the
literal string `"[SENSITIVE]"`, and the wrapped value is stored in a private static
`WeakMap` (not an instance property) so `print_r()`/`var_export()`/`var_dump()` cannot
enumerate it either — call `->reveal()` explicitly to obtain the real value. Errors that
wrap a transport failure (`NetworkError`) redact `Set-Cookie`/`Authorization`/`Cookie`
header values from the response **before** the exception object is ever constructed, so a
raw token can never leak through a caught exception, a log line, or a JSON error body.

## Examples

- [`examples/login_mfa.php`](examples/login_mfa.php) — login → MFA → typed `LoginResult`.
- [`examples/rest_authz.php`](examples/rest_authz.php) — `checkAccess()`/`can()`/`batchCheck()` over REST.
- [`examples/grpc_checkaccess.php`](examples/grpc_checkaccess.php) — the same three methods over gRPC (long-running runtime, see above).
- [`examples/telemetry_hook.php`](examples/telemetry_hook.php) — CONTRACT.md §16–§19: the §19 hook, the §16 retry signal, the §19.2 rule 6 clamp warning, and `close()`. Runs without a reachable server — the failure path emits the same events as the success path.
- [`examples/oidc_login.php`](examples/oidc_login.php) — CONTRACT.md §12: `oidcDiscover`/`oidcBegin`/`oidcExchange`, `loginClientCredentials`, `introspect`, `revoke`.
- [`examples/laravel_app/`](examples/laravel_app/README.md) — runnable Laravel middleware + Gate example, plus [`oidc_routes.php`](examples/laravel_app/oidc_routes.php) for "Login with AXIAM".
- [`examples/symfony_app/`](examples/symfony_app/README.md) — runnable Symfony subscriber + Voter example (manual registration), plus [`oidc_services.yaml`](examples/symfony_app/oidc_services.yaml)/[`oidc_routes.yaml`](examples/symfony_app/oidc_routes.yaml) for "Login with AXIAM".
- [`bin/axiam-amqp-worker.php`](bin/axiam-amqp-worker.php) — standalone AMQP consumer worker (run under process supervision, see above).

## Testing

```bash
composer install
composer test
```

Runs the full PHPUnit suite: single-flight refresh concurrency (SC#2), `Sensitive`
redaction (CR-04), AMQP HMAC verification, JWKS/EdDSA verification, the
`extension_loaded('grpc')` REST-fallback guard, and both framework-bridge tests.

## Regenerating the gRPC stubs

The protobuf message classes under `src/Grpc/Gen/` are `protoc` output, generated from
[`proto/axiam/v1/authorization.proto`](proto/axiam/v1/authorization.proto) and
[`proto/axiam/v1/userinfo.proto`](proto/axiam/v1/userinfo.proto) and **committed to this
repository** — that is what lets `composer require axiam/axiam-sdk` work with no protobuf
toolchain on your machine, and what keeps gRPC a `suggest` rather than a hard dependency.
Unlike the other AXIAM SDKs, PHP does not use `buf` (D-03); it invokes `protoc` directly.

You only need this when `proto/` changes:

```bash
composer grpc-gen    # requires protoc on PATH; no grpc_php_plugin needed
git diff src/Grpc/Gen
```

The service clients (`src/Grpc/AuthzGrpcClient.php` and `src/Grpc/UserInfoGrpcClient.php`)
are hand-written against `\Grpc\BaseStub` and are **not** generated — do not overwrite them.
