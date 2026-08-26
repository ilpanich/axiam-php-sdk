# axiam/axiam-sdk (PHP)

[![CI](https://github.com/ilpanich/axiam-php-sdk/actions/workflows/sdk-ci-php.yml/badge.svg?branch=main)](https://github.com/ilpanich/axiam-php-sdk/actions/workflows/sdk-ci-php.yml)
[![Coverage Status](https://coveralls.io/repos/github/ilpanich/axiam-php-sdk/badge.svg?branch=main)](https://coveralls.io/github/ilpanich/axiam-php-sdk?branch=main)
[![Packagist Version](https://img.shields.io/packagist/v/axiam/axiam-sdk.svg)](https://packagist.org/packages/axiam/axiam-sdk)
[![PHP Version](https://img.shields.io/packagist/php-v/axiam/axiam-sdk.svg)](https://packagist.org/packages/axiam/axiam-sdk)
[![Docs](https://img.shields.io/badge/docs-phpDocumentor-blue.svg)](https://ilpanich.github.io/axiam-php-sdk/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Official PHP client SDK for [AXIAM](https://github.com/ilpanich/axiam) — Access eXtended
Identity and Authorization Management.

**Platform documentation:** <https://ilpanich.github.io/axiam/> — getting started, the authorization model, the OAuth2/OIDC surface, and the operations guides. This README covers the SDK; the site covers the server it talks to.

## Package identity

- **Packagist package:** `axiam/axiam-sdk`
- **Registry:** [packagist.org/packages/axiam/axiam-sdk](https://packagist.org/packages/axiam/axiam-sdk) _(reserved, not yet published)_
- **Source:** [github.com/ilpanich/axiam-php-sdk](https://github.com/ilpanich/axiam-php-sdk)
- **API reference:** [ilpanich.github.io/axiam-php-sdk](https://ilpanich.github.io/axiam-php-sdk/)
- **License:** Apache-2.0
- **PHP:** `>=8.2` — see [Supported PHP versions](#supported-php-versions)

## Install

```bash
composer require axiam/axiam-sdk
```

## Supported PHP versions

| | Version | Why this one |
|---|---|---|
| **Floor** | 8.2 | The oldest release still receiving security fixes — 8.1 reached end of life on 2025-12-31. This is the `php` constraint in `composer.json`, exposed as `SupportedVersions::MIN_PHP`. |
| **Newest** | 8.5 | The current release (2025-11), exposed as `SupportedVersions::NEWEST_TESTED_PHP`. |

8.3 and 8.4 sit between the two and are supported.

**The SDK is built against the floor, and runs on everything up to the newest.**
CI proves each separately: the gating matrix in `sdk-ci-php.yml` runs
`composer install` and the full PHPUnit suite on **8.2 and on 8.5**. Source-level
gates that cannot depend on the runtime — `composer validate`, `composer audit`,
PHPStan, the docblock-coverage gate and the TLS-bypass grep — run once, on the
floor leg.

> **8.2 reaches end of life on 2026-12-31.** The floor moves to 8.3 then;
> `tests/VersionPolicyTest.php` asserts the floor is a version that still
> receives security fixes, so this is a build failure rather than something to
> remember.

Until this change the declared floor was **untestable by construction**: the
package published `php: >=8.1`, but the require-dev framework bridges
(`illuminate/support` ^11, `symfony/*` ^7) require PHP ^8.2 themselves, so
`composer install` was unsatisfiable on 8.1 and CI died before running a single
test. The floor was advertised to every Packagist consumer and had never once
been executed.

`Axiam\Sdk\SupportedVersions` exposes both ends as readable constants — see
[`examples/version_compatibility.php`](./examples/version_compatibility.php)
for a runnable preflight. Composer enforces the lower bound at install time,
but only at install time: `--ignore-platform-reqs`, a `config.platform`
override, or a `vendor/` tree built on one runtime and deployed onto another
all get past it, and the mismatch then surfaces as a parse error on the first
request.

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

This SDK conforms to [`CONTRACT.md`](CONTRACT.md) §1–§13 and §12.7, §14, §15, §17, §19, §20,
§22, §23, §24, §25, §26, §27 (including
§6.1 mTLS, contract 1.3; §12 OIDC/SSO helpers, contract 1.4; §13 webhook-signature
verification; the §17 decision memo and §19 telemetry hooks, contract 1.8) — the binding,
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
webhook-signature verification (§13, see below), the opt-in §17 decision memo
(`decisionMemoTtlMs`) and the §19 telemetry hooks (`telemetryHook`, see
[`examples/telemetry_hook.php`](examples/telemetry_hook.php)), the §22 reactor runtime
(`reactorServe`, see below), the §23 OPAQUE login path (`loginOpaque`, see below —
**conditional on `ext-ffi` and one shared library**, which is PHP's alone among the eleven
SDKs), the §24 WebAuthn relying-party layer with its §24.6a JSON bridge (see below), the
§25 account-lifecycle and MFA-enrolment operations (see below), and §26 Pushed
Authorization Requests (see below).

§24.6b — the linked-API ceremony helper — is **deliberately absent**. PHP runs on a server,
which has no authenticator, and §24.6b rule 2 forbids emulating one in software: a
"credential" held in process memory is not a second factor. The ceremony runs in the
browser, and §24.6a's JSON bridge is the seam that carries the challenge out and the
response back.

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
    subjectTokenType: OidcClient::ACCESS_TOKEN_TYPE, // required (§15.1), no default
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

### External-IdP subject tokens (CONTRACT.md §15.7)

The same method exchanges a token minted by a **trusted external IdP** — a partner's
Entra, Okta or Keycloak — for an AXIAM token scoped to what the resolved AXIAM user may
actually do. There is no separate operation:

```php
$exchanged = $client->tokenExchange(
    subjectToken: $partnerToken,
    subjectTokenType: OidcClient::JWT_TOKEN_TYPE, // required; named, never guessed
    scopes: ['read:orders'],
    audience: 'https://orders.internal',
);
```

- **`$subjectTokenType` is yours to state, and is required** (§15.1). The SDK never decodes
  the subject token to pick it, and never overrides what you named. There is no default:
  omitting it is an `ArgumentCountError`, and a blank string is refused client-side with no
  wire call. It now sits **second**, matching §15.1's canonical order — it was last while it
  was optional, to spare positional callers, and making it required breaks them anyway.
- **No actor token.** Delegation across a trust boundary is unsupported in v1; sending one
  is `invalid_request`, which the SDK will not work around by dropping it and re-sending.
- **One refusal is distinguishable.** `invalid_grant` whose `errorDescription` is `the
  subject token's issuer is not configured for token exchange` means *fix the AXIAM trust
  configuration*. Every other `invalid_grant` means *fix your token*, and is deliberately
  generic.
- **Forward the result as-is.** It carries an `ext_exchange` claim naming the partner
  issuer; never strip it, and never read it as an authorization input. It also cannot be
  exchanged again — exchanges do not compose.

The operator guide is `docs/api/federated-token-exchange.md`.

## UMA 2.0 — Protection API and ticket grant (CONTRACT.md §20)

The resource-server side of User-Managed Access: register what you guard, ask the
authorization server what a caller would need, and redeem the resulting ticket.

```php
// A PAT is a client-credentials token carrying `uma_protection` — never a user token,
// and never this client's own session (§20.2 rule 1).
$pat = $client->loginClientCredentials(scope: OidcClient::UMA_PROTECTION_SCOPE)->accessToken;

$resource = $client->umaRegisterResource($pat, 'invoice-7', 'document', ['view']);

// The returned id IS the AXIAM resource id — no translation step.
$ticket = $client->umaRequestTicket($pat, [
    new RequestedPermission($resource->id, ['view']),
]);

header($client->umaChallengeHeader('invoices', $issuer, $ticket));
```

…and on the client side, having caught that `401`:

```php
$challenge = $client->umaParseChallenge($response->getHeaderLine('WWW-Authenticate'));
$rpt = $client->umaExchangeTicket($challenge->ticket, $usersAccessToken);
```

The rules this surface exists to enforce:

- **A ticket is never retried** — not on `5xx`, not on a timeout, not on `invalid_grant`.
  It is the one documented exception to §16's retry policy, and a security rule rather
  than a performance one: the ticket is consumed *before* the exchange is evaluated, so a
  failed exchange has already spent it and a retry is a *second redemption*. Under
  concurrency that is exactly the redemption a server whose storage engine the SDK cannot
  attest may admit twice
  ([`ilpanich/axiam#302`](https://github.com/ilpanich/axiam/issues/302)). On failure,
  request a **new** ticket.
- **`umaParseChallenge()` does not exchange what it parsed.** The `as_uri` names an
  authorization server you have not necessarily chosen to trust; auto-exchanging would send
  the requesting party's `claim_token` to whatever host answered the `401`.
- **`$claimToken` is required, never defaulted.** It is the only channel that names the
  requesting party — defaulting it to your own PAT would mint an RPT for *you*.
- **No auto-narrowing on `access_denied`.** A partial grant is refused whole; whether
  two-of-three permissions is useful is your application's judgment, not the SDK's.
- **The RPT is never adopted** as this client's credentials, and carries no refresh token.
- **`umaUpdateResource()` replaces the scope list rather than merging it**, so omitting a
  scope removes it. There is no read-modify-write.

### Emitting the challenge from the §11 enforcer

Both framework bridges delegate every §11 decision to one `AccessEnforcer`, so a
`UmaChallenger` handed to that enforcer covers Laravel and Symfony alike:

```php
$challenger = new UmaChallenger('invoices', $client->oidcDiscover()->issuer, $pat, $client);
$enforcer = new AccessEnforcer($client, $logger, $challenger);

// A denied #[RequireAccess] now answers 403 with
//   WWW-Authenticate: UMA realm="invoices", as_uri="…", ticket="…"
```

Two properties are deliberate, and both are asserted by counting Protection API requests:

- **Opt-in.** Emitting a challenge means minting a credential. An enforcer that did that on
  every denial by default would put a Protection API call — and a live ticket — behind every
  unauthorized request, which is a denial-of-service amplifier pointed at your own
  authorization server. An allow mints nothing, and neither does a 401 or a fail-closed 503:
  only a *resource denial* is answerable with a ticket.
- **A minting failure is not an escalation.** An expired PAT or an unreachable Protection API
  still yields the plain 403 — never a 503, and never an allow.

The requested scope is the AXIAM **action**, so the ticket asks for exactly the authority
that was refused and the engine's deny rules keep applying to whatever RPT comes back.

Both halves run in [`examples/uma_resource_server.php`](examples/uma_resource_server.php)
and [`examples/uma_client.php`](examples/uma_client.php).

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

## Reactors — AMQP extension actors (CONTRACT.md §22)

A **reactor** is an external process that subscribes to named hook events on the AXIAM bus
and answers back — allow, deny, or a field-allow-listed mutation — inside a timeout the
server declared. Zitadel Actions and Keycloak SPIs solve the same problem by loading
third-party code *into* the authorization server; a reactor stays outside it, reachable
only through a signed reply schema the server validates before it believes a word of it.

```php
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Reactor\AmqpLibReactorTransport;
use Axiam\Sdk\Reactor\ReactorAnswer;
use Axiam\Sdk\Reactor\ReactorConfig;
use Axiam\Sdk\Reactor\ReactorEvent;
use Axiam\Sdk\Reactor\ReactorEvents;
use Axiam\Sdk\Reactor\ReactorServer;

$config = new ReactorConfig(
    tenantId: $tenantId,
    // §8.1 + §22.12: the tenant AMQP subkey from the management API, wrapped.
    signingKey: new Sensitive($subkey),
    // The queue name is derived from it — but the SERVER declared it.
    reactorId: $reactorId,
);

$server = new ReactorServer(
    config: $config,
    // §8b: amqps:// only, optional CA bundle, no verification-skip switch anywhere.
    transport: AmqpLibReactorTransport::connect('amqps://broker.example:5671', $caPath),
    handler: function (ReactorEvent $event): ReactorAnswer {
        switch ($event->event) {
            case ReactorEvents::TOKEN_PRE_ISSUE:
                // `ext.` is the COMPLETE allow-list for this event.
                return ReactorAnswer::mutate(['ext.department' => 'eng']);
            case ReactorEvents::LOGIN_POST_AUTH:
                return fraudulent($event)
                    ? ReactorAnswer::deny('embargoed region')
                    : ReactorAnswer::allow(); // or ReactorAnswer::allowWithStepUp()
        }

        return ReactorAnswer::allow();
    },
);

$server->reactorServe(); // blocks; call $server->stop() from a signal handler
```

### Binding handlers per event (§22.14)

The `switch` above is the shape every multi-event reactor grows, and its fall-through —
`return ReactorAnswer::allow()` — answers on behalf of code that never ran. That is the
defect §22.10 rule 2 forbids the *runtime* from committing, relocated into your file where
the rule does not reach it: an operator who set `fail_closed` on the registration has it
defeated there.

`ReactorHandlers` is §22.14's declarative form, and it uses the same attribute mechanism
the §11 `#[RequireAccess]` helper already uses:

```php
use Axiam\Sdk\Attributes\OnReactorEvent;
use Axiam\Sdk\Reactor\ReactorHandlers;

final class ClaimsReactor
{
    #[OnReactorEvent(ReactorEvents::TOKEN_PRE_ISSUE)]
    public function enrich(ReactorEvent $event): ReactorAnswer
    {
        return ReactorAnswer::mutate(['ext.department' => 'eng']);
    }

    #[OnReactorEvent(ReactorEvents::LOGIN_POST_AUTH)]
    public function screen(ReactorEvent $event): ReactorAnswer
    {
        return fraudulent($event) ? ReactorAnswer::deny('embargoed region') : ReactorAnswer::allow();
    }
}

$handlers = ReactorHandlers::of(new ClaimsReactor());
$server = new ReactorServer(config: $config, transport: $transport, handler: $handlers->handler());
```

- **A misspelled event is refused when the attribute is instantiated** — `OnReactorEvent`
  accepts only §22.5 registry names, which is also how it refuses the three hot-path
  operations §22.7 excludes: they are in no registry row.
- **An unbound event abstains** — the composed handler throws `ReactorRejection`, which
  publishes **nothing**, so the registration's `failure_policy` decides (§22.8) exactly as
  it decides a timeout. Never a synthesized `allow`.
- Binding the same event twice throws rather than silently overwriting, and
  `$handlers->events()` feeds `ReactorEvents::defaultFailurePolicy()` so you can see what
  an unreachable reactor costs before you go live.

Closures work too — `(new ReactorHandlers())->bind(ReactorEvents::TOKEN_PRE_ISSUE, $fn)` —
and both spellings are governed by the same rules. It is pure sugar: `handler()` returns
exactly the callable `ReactorServer` already takes. It opens nothing, verifies nothing,
signs nothing, does not filter a patch, and a handler's own throwable reaches the runtime
unchanged so nothing is published.

`reactorServe()` verifies every delivery **before** the handler sees it — key version, MAC,
freshness, nonce, in that order — then signs the reply with the same tenant subkey. §8's
HMAC runs in **both directions** here: a reply is an instruction to change a token or refuse
a login, so an unsigned or stale one is not a weak reply, it is not a reply at all.

Five things this runtime does that are easy to get wrong, and that are asserted against the
server-generated vectors in
[`tests/Fixtures/reactor_v2_reference_vectors.json`](tests/Fixtures/reactor_v2_reference_vectors.json)
rather than documented and hoped for:

- **`hmac_signature` is serialized as `null` inside a reactor body**, not omitted the way
  §8's own two message types omit it. This is the single most likely place to produce a MAC
  that never verifies, in either direction.
- **`reason`, `patch` and `require_mfa` are omitted when absent/false.** A reply that
  serializes `"require_mfa": false` produces different canonical bytes and a different MAC.
- **A patch is sent unfiltered.** One forbidden key rejects the *whole* patch server-side,
  and this SDK will not quietly drop `sub` to rescue the rest — that would leave you
  believing a field was set when it was dropped.
- **A handler that throws publishes nothing.** No synthesized `allow`: the registration's
  `failure_policy` decides, which is what the operator configured. `login.post_auth`
  defaults to `fail_closed`.
- **It never declares an exchange, a queue or a binding.** The server declares the
  per-reactor queue from the registration, and `ReactorTransport` has no declare or bind
  method for the runtime to reach for. A reactor that could bind could bind itself to
  `*.token.pre_issue` and read another tenant's issuance events.

The event registry, its per-event mutable-field allow-lists and §22.8's strictest-wins
failure-policy composition are mirrored locally (`ReactorEvents::all()`,
`ReactorEvents::defaultFailurePolicy($events)`) because the delivery path validates against
them with no network available; `GET /api/v1/reactors/events` serves the live copy.

**Not hookable, and not offered anywhere in this SDK:** the hot-path decision operations
(the authorization check, the batch check and token introspection) are absent from the
registry by design — §22.7 writes this as a MUST NOT because a reactor round-trip is
milliseconds and the check path's budget is microseconds. An application that needs external
input on an authorization decision writes a **deny grant**, which the engine evaluates in the
hot path at hot-path cost.

`timeout_ms` reaches the handler as `$event->timeoutMs` and bounds the reply: work whose
window has already closed is abandoned rather than answered late. Telemetry (§19) is
available through the `telemetryHook` constructor argument — and worth wiring, because a
`fail_open` timeout produces `allow` *and* an audit record, so reactor health must never be
inferred from the outcome alone.

**Like the §8 consumer, a reactor is a long-running CLI process, never an FPM request**, and
`php-amqplib` has no built-in reconnection: when the broker session ends `reactorServe()`
returns and a process supervisor restarts the worker. That is a deliberate deviation from the
Go/Java runtimes' in-process reconnect loop and the same posture this SDK already documents
for the AMQP worker above. `$server->stop()` is safe from a `pcntl` signal handler: the
delivery in flight is answered before the loop returns (§18).

See [`examples/reactor/reactor.php`](examples/reactor/reactor.php).

## OPAQUE (CONTRACT.md §23) — conditional on `ext-ffi` and one shared library

`loginOpaque` proves the password to the server without the password — or anything from which it
can be cheaply recovered — ever crossing the wire. The server stores a **registration record**
sealed under a tenant-wide oblivious PRF seed, and what travels is a blinded group element and a
MAC, neither useful without both.

```php
if ($client->opaqueAvailable()) {
    $result = $client->loginOpaque('alice', $password);
} else {
    $result = $client->login('alice', $password);
}
```

It takes the same arguments as `login()` and returns the same `LoginResult`, MFA branch included,
so switching a tenant to OPAQUE needs no change to how the result is handled. A runnable
end-to-end example is [`examples/opaque_login.php`](examples/opaque_login.php).

Unlike the SRP-6a it replaces, there is no separate server-proof step and nothing has been
dropped: RFC 9807's AKE authenticates the server during the handshake, so opening `KE2` **is** the
proof that it holds the record.

### PHP went from two conditions to one

This was the SDK where §23 hurt most, and the change is worth spelling out.

The SRP client needed **two** things, and the second was the bad one:

1. `ext-gmp` or `ext-bcmath`, because PHP has no native arbitrary-precision integer and SRP is
   2048- to 4096-bit modular exponentiation.
2. A tenant configured for `pbkdf2_sha256` — because no PHP runtime offers Argon2id with a
   caller-supplied 32-byte salt. `sodium_crypto_pwhash` requires exactly 16, `password_hash()`
   generates its own. **AXIAM's default KDF was, for PHP, simply unreachable**, and the honest
   advice was to weaken the tenant's configuration for PHP's benefit.

Both are gone. The key stretching now happens inside `libaxiam_opaque_ffi`, so a `true` from
`opaqueAvailable()` means *every* tenant works — including the default one — and no tenant needs
reconfiguring on PHP's account.

What remains is having the library, which is two things that are really one:

**1. `ext-ffi`.** Not guaranteed on any runtime, and disabled outright on some shared hosts.

**2. `libaxiam_opaque_ffi`.** A Rust `cdylib` published as a per-platform asset on the
[axiam release page](https://github.com/ilpanich/axiam/releases), **not** a Composer package —
there is no cross-language registry to put it on. Put it on the system library path, or:

```bash
export AXIAM_OPAQUE_LIBRARY=/opt/axiam/libaxiam_opaque_ffi.so
```

`opaqueAvailable()` reports both as one answer, and reports rather than throwing — so an
application chooses the login path before attempting one rather than discovering the gap
mid-exchange. It also *calls into* the library rather than merely loading it: FFI resolves symbols
lazily, so a probe that only opened the file would report "present" and then fail at login against
some other library that happened to share the name.

### The protocol is not implemented here

CONTRACT.md §23.1 forbids an SDK from writing its own OPAQUE. SRP-6a was arithmetic every language
can express — which in PHP meant ~800 lines across two bignum backends, plus the `pbkdf2_sha256`
limitation on top. OPAQUE is not: it needs an oblivious PRF, `hash_to_curve`,
`expand_message_xmd`, an envelope construction and a three-message AKE, and eleven independent
implementations of that is eleven chances to be subtly and silently wrong in a way that still
interoperates until it does not.

`Axiam\Sdk\Opaque` therefore contains **no cryptography**. It is an FFI binding to the same
implementation the AXIAM server links.

### What this buys, and what it does not

OPAQUE closes holes TLS 1.3 does not:

- a TLS-terminating reverse proxy, ingress controller, CDN or service mesh sees every plaintext
  password today; under OPAQUE it sees `KE1` and `KE3`;
- an accidental request-body log, a heap dump or a crash reporter can no longer capture a
  plaintext password, because the server never has one;
- **a stolen record database is not offline-crackable on its own.** This is the substantive gain
  over SRP: cracking a record also requires the tenant's OPRF seed, which is AES-256-GCM encrypted
  at rest under a key the database does not hold.

It does **not** protect against a compromised AXIAM server, and this SDK does not claim it does.

### Tenant policy, and the errors that are not credential failures

`opaque_mode` is an organization baseline a tenant may tighten:

| mode | `login()` | `loginOpaque()` |
|---|---|---|
| `disabled` (default) | works | `NetworkError` — the endpoint answers `404` |
| `optional` | works | works |
| `required` | `AuthzError` | works |

Which exception you get is most of what this SDK owns on this path:

| condition | exception | why |
|---|---|---|
| tenant has OPAQUE disabled | `NetworkError` | a property of the tenant, not of any user — fall back to `login()` |
| `ext-ffi` or the library absent | `NetworkError` | a fact about this runtime, raised before any request is sent |
| server named a KSF this build cannot perform | `NetworkError` | a configuration problem; substituting one would surface as a wrong password |
| `/start` response missing `ke2` | `NetworkError` | malformed response |
| envelope did not open / `KE2` did not verify, `mode: "required"` or no `mode` | `AuthError` | the **whole** of the credential check |
| envelope did not open / `KE2` did not verify, `mode: "optional"` | whatever `login()` returns or raises | retried over `login()` first — see below |
| tenant refuses password login (`login()`) | `AuthzError` | the credentials were never examined |

That `AuthError` covers both halves of the mutual authentication: a wrong password, an account
that does not exist, a server that does not hold the record, and an account with no registration
record at all are indistinguishable by design. **Nothing is sent to `login/finish` in that case**
(§23.4 rule 7).

What happens next depends on the `mode` field the `login/start` response carries — the tenant's
`opaque_mode` — and on nothing else (contract 1.29):

- `"optional"` — `loginOpaque()` **retries over `login()` itself**, with the same credentials,
  and returns that call's outcome. You do not write this branch; the SDK does. It has to exist:
  every account has no registration record the moment an operator enables OPAQUE and acquires
  one only when its password is next set, so treating the failed exchange as final would lock
  out every user of a tenant for the whole of its migration.
- `"required"`, and **any response with no `mode` at all** (a server older than the field) —
  `AuthError`, and you must not retry over `login()` yourself. It would be refused anyway:
  `required` answers `403 opaque_required` for every principal in the tenant, so the retry would
  put a plaintext password on the wire for nothing. An unrecognised value is treated the same way.

`mode` is **not** downgrade protection, and do not read it as one: a hostile endpoint that wanted
the plaintext could simply answer `404`, which sends a caller to `login()` whatever it puts here.
`required` is what closes that, server-side, by refusing `/auth/login` before it examines any
credential.

`required` refuses **every** principal in the tenant, not only the enrolled ones. Splitting the
response on whether an account has a record would turn `/auth/login` into an enumeration oracle
costing one junk password per name. Operators turn it on last, after a password-reset campaign.

### Enrolment

The server cannot build a registration record, so any request that **sets** a password has to
carry one. `opaqueEnrollment()` produces the `opaque` object for `POST /api/v1/users`,
`/auth/password/change`, `/auth/reset/confirm` and `/admin/bootstrap`:

```php
$enrolment = $client->opaqueEnrollment($newPassword);
$body['opaque'] = $enrolment->toWire();
```

Note the parameters that are gone. There is no `$identity`: the SRP version required the account's
**username**, an email there produced a verifier no login could ever satisfy — and renaming a user
invalidated their verifier outright. A record binds to a credential identifier the server chooses,
so neither is true any more. There is no `$group` or `$params` either: those come from the
`register/start` response, so a caller cannot pick a cost the server will not honour.

Unlike `srpEnrollment()` this performs I/O — one `register/start` round trip. The envelope is
sealed under the server's oblivious PRF, so there is no offline computation that produces a valid
record.

### Cost

`loginOpaque()` runs the tenant's key-stretching function: Argon2id at 19 MiB and t=2 by default,
which is tens to hundreds of milliseconds of CPU plus that memory, per login attempt. That cost is
the point — it is what makes a stolen record expensive to attack even by someone holding the OPRF
seed. On a request-per-process runtime it lands squarely in the request; size `max_execution_time`
and any upstream timeout accordingly. It is not a cost `login()` has.

### Cryptographic parameters

The ciphersuite is `OPAQUE-3DH` over **ristretto255** with **SHA-512**, HKDF-SHA-512 and
HMAC-SHA-512, fixed AXIAM-wide. It is not negotiated and not read from the server: a client that
accepted a suite from the endpoint it is authenticating would be accepting a downgrade.

The key-stretching function *is* the server's to name, per exchange, and is honoured as given
rather than cached or defaulted. `argon2id` and `scrypt` are accepted; anything else — including
`pbkdf2_sha256`, which was SRP's PHP-only fallback and is not an OPAQUE KSF at all — is refused
rather than substituted. Costs outside the bands this SDK will act on (`memory_kib` 8 MiB–1 GiB,
`iterations` 1–10, `parallelism` 1–16, `log_n` 14–20, `r`/`p` 1–16) are refused too.

### Zeroization

PHP strings are immutable and the runtime copies them freely, so this SDK **cannot** clear the
password. §23.3 rule 8 requires saying so rather than implying a guarantee it cannot keep. What it
does do is never put the password in a request body, and never log it.

## WebAuthn / passkeys (`Axiam\Sdk\Webauthn`, CONTRACT.md §24)

Six wire operations, two ceremonies, and one thing this SDK deliberately does not do.

```php
// Enrolment — requires a session (§24.1), refused client-side without one.
$challenge = $client->webauthnRegisterStart();
$credential = $client->webauthnRegisterFinish(
    $challenge->stateToken,
    "Alice's laptop",
    $platformResponseJson,          // verbatim
);

// Sign-in with no username at all — the authenticator picks the account.
$signIn = $client->webauthnDiscoverableStart();
$result = $client->webauthnDiscoverableFinish($signIn->stateToken, $assertionJson);
```

**The server chooses every option and verifies every response; this SDK passes both through
byte-for-byte** (§24.0). `WebauthnChallenge::$challenge` is a plain decoded array, not a
modelled type: no defaulting, no validation-that-rejects, no re-encoding. On the way back
the `*Finish` body is assembled as **text**, splicing the caller's response string in
unmodified — decoding and re-encoding it would round every number through a float and hand
the server a byte sequence the authenticator never signed.

### The browser half, via the §24.6a JSON bridge

```php
// Your start endpoint
$challenge = $client->webauthnRegisterStart();
echo json_encode([
    // §24.6a rule 1: the wire JSON, unparsed and unreassembled.
    'requestJson' => $challenge->requestJson(),
    'stateToken' => $challenge->stateToken->reveal(),
]);
```

```javascript
// Browser
const options = PublicKeyCredential.parseCreationOptionsFromJSON(requestJson);
const credential = await navigator.credentials.create({ publicKey: options });
await fetch('/passkeys/finish', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ stateToken, response: credential.toJSON() }),  // verbatim
});
```

`requestJson()` returns the inner options object — the `publicKey` wrapper belongs to the
DOM's `CredentialCreationOptions`, and the platform JSON APIs do not want it. A mobile
client relaying Android's `registrationResponseJson` uses the same two seams.

Passing something that is not JSON, or is not a JSON object, raises `AuthError` client-side
with no wire call: the SDK will not POST a body it already knows the server cannot verify.

### The two authentication ceremonies are different flows (§24.2)

`webauthnAuthenticateStart()`/`Finish()` is a **second factor** — it continues a `login()`
that answered `mfaRequired` with `"webauthn"` among its methods, and the challenge token
names the user so the server can send an `allowCredentials` list.
`webauthnDiscoverableStart()`/`Finish()` is a **primary factor**: nothing precedes it,
`allowCredentials` is empty, and the assertion itself identifies the user. They are not one
operation with an optional token — merging them reproduces a bug the server already fixed,
which is why the token is a required argument on one and absent from the other.

One difference a reactor author will ask about: `discoverable/finish` fires the
`login.post_auth` hook event (§22.5) and `authenticate/finish` does not. The latter
continues a login already gated at its password step; the former has no such step.

### Saying something useful when a ceremony fails (§24.6b rule 5)

```php
$outcome = WebauthnFailure::classify($domExceptionName);
echo $outcome->message();
```

`AlreadyRegistered` is the exclusion list doing its job, and the only classification whose
remedy is "use a different device" rather than "try again". `Cancelled` covers **both** an
explicit refusal and a silent timeout — the spec deliberately refuses to distinguish them,
because telling a website which one happened leaks whether an authenticator was present —
so its copy does not accuse anyone of cancelling.

### Two error rows that are not the §2 defaults (§24.4)

- A **403 from `register/finish`** is the tenant's *attestation policy* rejecting this
  particular authenticator. The server's message is the only place that says which one
  would be accepted, so it is lifted into the `AuthzError`'s message rather than discarded.
  Show it.
- A **503 from `register/start`** means the policy needs FIDO metadata the server cannot
  reach. That is a configuration state, not a transient one, and it is **not retried** —
  the second documented exception to §16 after §20's.

Session cookies: as of contract 1.28 both `*Finish` authentication calls set the
`axiam_access` / `axiam_refresh` / `axiam_csrf` triple alongside the token body, so a
completed ceremony leaves the client signed in for every cookie-driven call that follows
(§24.3).

Worked end to end in [`examples/webauthn_passkeys.php`](examples/webauthn_passkeys.php).

## Account lifecycle and MFA enrolment (`Axiam\Sdk\Account`, CONTRACT.md §25)

Nine operations covering the things a user does to their own account — none of which is
administration, and all of which were previously reachable only by hand-rolling HTTP.

```php
$result = $client->login('alice@example.com', $password);

if ($result->mfaSetupRequired) {
    // The third outcome. The tenant requires MFA, this account has none, and the
    // server handed back a setup token to finish with. There is no session yet —
    // the token IS the credential.
    $enrollment = $client->mfaSetupEnroll($result->setupToken);
    renderQr($enrollment->totpUri->reveal());
    $client->mfaSetupConfirm($result->setupToken, $code);   // completes the LOGIN
}
```

`LoginResult` gained two properties with defaults rather than changing shape, so every
pre-1.28 construction still works and still reads `false`. **Handle the new outcome
anyway.** A tenant that turns on required MFA will start returning it, and a client that
only branches on `mfaRequired` reports a successful login that has no session.

`mfaSetupConfirm()` adopts credentials exactly as `login()` does, because it *is* the
completion of a login (§25.2 rule 2) — including capturing the session's first CSRF token.
`mfaEnroll()`/`mfaConfirm()` are the voluntary pair, from inside an existing session, and
they do **not** clear the §17 decision memo — the subject has not changed, and discarding a
warm memo on an unrelated profile action costs a round trip on every check that follows.

Both halves of an `MfaEnrollment` are `Sensitive`, and the second one matters: the
`otpauth://` URI *contains* the secret (§25.3). Wrapping the bare secret and then logging
the URI leaks the same bytes.

### Password reset, and the two things it will not tell you

```php
$client->requestPasswordReset(new PasswordResetRequest('alice@example.com'));
// returns void, whether or not that address has an account

$context = $client->passwordResetContext($token);
if ($context->opaque !== null) {
    // This tenant runs §23. Build a registration record from these parameters;
    // a plaintext password would be refused, and refused late (§25.4 rule 1).
}
$client->confirmPasswordReset(new PasswordResetConfirmation($token, $newPassword, $tenantId));
```

`requestPasswordReset()` returns nothing and throws nothing on an unknown address, and this
SDK exposes no way to tell the two cases apart. That is not an omission to improve on: a
client that surfaced a "no such user" state — even one inferred from timing — would turn
the endpoint into the account-enumeration oracle its uniform response exists to prevent.
Likewise a `404` from `passwordResetContext()` means unknown, expired **or**
already-consumed, and the SDK does not distinguish them either (§25.4 rule 3).

`verifyEmail()` and `resendVerification()` are unauthenticated — a user whose address is
unverified may have no session at all — and carry the tenant as a **body** field, since
§12.1 rule 2's `?tenant_id=` convention is scoped to the `/oauth2` endpoints.

Worked end to end in [`examples/account_lifecycle.php`](examples/account_lifecycle.php).

## Pushed Authorization Requests (CONTRACT.md §26, RFC 9126)

PAR moves the authorization request off the browser. Instead of putting `scope`,
`redirect_uri`, `state` and the PKCE challenge into a URL the user agent carries, the client
POSTs them straight to AXIAM over an authenticated back channel and puts an opaque
`request_uri` in the redirect.

```php
$config = $client->oidcDiscover();
if ($config->pushed_authorization_request_endpoint === null) {
    // §26 is optional; fall back to the plain oidcBegin redirect.
}

$begun = $client->oidcBegin($config, $redirectUri, 'openid profile');
$pushed = $client->oidcPar($begun, $redirectUri, $config, 'openid profile');

header('Location: ' . $pushed->url);   // exactly ?client_id=…&request_uri=…
```

Three things worth knowing:

- **The server answers `201`,** not `200` — RFC 9126 §2.2 specifies *Created*. A success
  predicate written `=== 200` treats every successful push as a failure.
- **The redirect URL carries exactly two parameters.** The server refuses a request that
  mixes a `request_uri` with inline authorization parameters rather than merging them;
  merging is where parameter confusion lives (§26.2 rule 2). Any query the discovered
  `authorization_endpoint` already carried is dropped.
- **`oidcBegin()` still owns `state`, `nonce` and the PKCE pair.** There is no second
  generator (§26.2 rule 1), and `PushedAuthorizationRequest` carries all three straight
  through to the exchange.

The push is **not retried** on a 5xx or a transport failure: it is a POST that creates
server state, so it falls outside §16.2's read-only eligibility exactly as `oidcExchange()`
does. The safe recovery is a fresh push, which costs one round trip and cannot
double-consume anything. The `requestUri` is `Sensitive` because between the push and the
redirect it is a bearer handle to a fully-formed authorization request (§26.5).

A **FAPI 2.0 client has no alternative**: `profile: "fapi2"` refuses a registration that
does not set `require_par`, so such a client cannot authorize any other way (§21.1).

Worked end to end in [`examples/par_login.php`](examples/par_login.php).

## Management API (`Axiam\Sdk\Management`, CONTRACT.md §27)

The administrative surface: **146 operations across 24 namespaces**, generated from the
vendored `management-registry.json` and `openapi.json` by `scripts/gen_management.py` and
committed, so building this package needs no Python. CI re-runs the generator with
`--check` on every PR, which is what stops the committed surface from drifting away from
the contract it claims to implement.

The namespace handles sit **directly on the client** — `$client->roles()`,
`$client->serviceAccounts()->rotateSecret($id)`, the form §27.3's PHP row shows — and the
same 24 handles are also reachable behind one accessor, `$client->management()` (§27.2
rule 4), which reads better where a call site is already dense with §1 methods. The two
forms are **equivalent**: the direct accessors forward to `management()`, so rule 4's
"where an SDK offers both, the two MUST return equivalent handles" holds structurally
rather than by two code paths agreeing, and the suite asserts it by comparing the method,
path and query each actually puts on the wire.

```php
// §27.2 — namespace handles, not 146 flat methods.
$page = $client->users()->listItems(new PageRequest(0, 50));

// Or reach the same handles behind one accessor.
$management = $client->management();
$same = $management->users()->listItems(new PageRequest(0, 50));

// §27.4 rule 4 — `total` is the SERVER's count, not count($page). Confusing the two is
// how a script silently processes the first fifty of four hundred users.
printf("%d of %d\n", count($page), $page->total);

// Every page. The walk stops on the first EMPTY page, never on a short one.
$users = $management->users();
foreach (ManagementTransport::walk(
    static fn (PageRequest $p): Page => $users->listItems($p),
) as $user) { /* ... */ }

// §27.4 rule 5 — name what you mean to change. What you leave unset is OMITTED from the
// request, not sent as null; on a sparse update those say opposite things.
$management->users()->update($id, new Models\UpdateUserRequest(status: Models\UserStatus::Locked));

// §27.4 rule 3 — `{org_id}`/`{tenant_id}` come from the client; ->inOrg()/->forTenant()
// override them for one handle and return a COPY, leaving the original pointing where it did.
$management->caCertificates()->inOrg($otherOrgId)->listItems();
```

**Errors (§27.4 rule 7).** Three statuses get a sub-type *inside* the §2 taxonomy, so a
`catch (AuthzError $e)` written before §27 existed still behaves as it did:

| status | type | parent | why |
|---|---|---|---|
| `404` | `NotFoundError` | `AuthzError` | On a multi-tenant surface the server answers `404` for another tenant's object *precisely so* a probing caller cannot enumerate it. Re-drawing that line client-side would undo the protection. |
| `409` | `ConflictError` | `AuthzError` | §2 already maps `409` there; the sub-type keeps that mapping. |
| `400`, `422` | `ValidationError` | `NetworkError` | Inherited from §2's `400` row. Carries the server's per-field complaints. |

**Secrets (§27.5).** A one-time secret is `Sensitive`: it prints and `json_encode`s as
`[SENSITIVE]`, so it cannot reach a log line by accident. The one writer that must send
one in the clear unwraps it explicitly — `ManagementTransport::encodeBody()` walks the
body and calls `reveal()`. PHP has no `json_encode` equivalent of Jackson's mixin or
System.Text.Json's converter precedence, because `JsonSerializable` is consulted on the
instance and nothing outranks it; making the unwrap explicit is better anyway, since
there is no precedence rule to remember and exactly one greppable place where a secret
is revealed.

### Declarative manifests (§27.6, §27.7)

Describe the tenant you want; let the SDK work out the difference.

```php
$manifest = ManagementManifest::builder()
    ->permission('docs.read', 'documents:read', 'Read documents')
    ->role('contractor', 'contractor', 'External', grants: [
        'docs.read'  => 'allow',
        'docs.write' => 'deny',   // AXIAM's RBAC is DENY-OVERRIDE, not most-specific-wins
    ])
    ->group('externals', 'externals', 'Contractors', roleKeys: ['contractor'])
    ->build();

$plan = $client->management()->manifest()->plan($manifest);   // writes NOTHING
if (!$plan->isConverged()) {
    $report = $client->management()->manifest()->apply($manifest);
}
```

Or as attributes, which is the idiom this SDK already uses for §11 and lets a tenant's
shape live in version control as a type:

```php
#[ManagedPermission(key: 'docs.read', action: 'documents:read')]
#[ManagedRole(key: 'contractor', name: 'contractor', grants: ['docs.read' => 'allow'])]
final class AcmeTenant {}

$manifest = ManifestAttributeReader::read(AcmeTenant::class);
```

Four properties are worth knowing before you run one against production:

- **`plan()` writes nothing.** It reads and reports. Safe on a schedule, safe in CI.
- **`apply()` stops at the first failure and does NOT roll back** (§27.7). The returned
  `ApplyReport` names what landed, what failed and what was never attempted — a partial
  apply is a state you resume from, and an automatic rollback would fire a second wave of
  writes exactly when the server is telling you something is wrong.
- **Ordering is derived, not declared.** By kind, then dependency, then key. The tie-break
  on key is what makes a plan stable across runs.
- **Omission is never deletion.** There is no `ChangeAction::Delete` at all, so an
  incomplete manifest cannot become a destructive one.

An incoherent manifest — a dangling reference, a cycle, a duplicate key — is refused
*before* the first request, because discovering it halfway through an un-rollback-able
apply is strictly worse.

See `examples/management_basics.php`, `examples/management_manifest.php`,
`examples/management_manifest_attributes.php`, and
`examples/device_mtls_provisioning.php` — the last a full operator/device split that mints
a `Device` certificate from the tenant's signing CA, binds it to a service account, writes
the one-time private key at `0600`, and then authenticates as the device over §6.1 mutual
TLS with no password anywhere.

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
- [`examples/uma_resource_server.php`](examples/uma_resource_server.php) — CONTRACT.md §20: mint a PAT, register the resource, and emit the `WWW-Authenticate: UMA` challenge from a denial.
- [`examples/uma_client.php`](examples/uma_client.php) — the other half: refusal → parse → trust decision → exchange → retry with the RPT.
- [`examples/laravel_app/`](examples/laravel_app/README.md) — runnable Laravel middleware + Gate example, plus [`oidc_routes.php`](examples/laravel_app/oidc_routes.php) for "Login with AXIAM".
- [`examples/symfony_app/`](examples/symfony_app/README.md) — runnable Symfony subscriber + Voter example (manual registration), plus [`oidc_services.yaml`](examples/symfony_app/oidc_services.yaml)/[`oidc_routes.yaml`](examples/symfony_app/oidc_routes.yaml) for "Login with AXIAM".
- [`examples/opaque_login.php`](examples/opaque_login.php) — CONTRACT.md §23: `loginOpaque`, the one way OPAQUE can be unavailable on PHP (it used to be two), and `opaqueEnrollment`.
- [`examples/reactor/reactor.php`](examples/reactor/reactor.php) — CONTRACT.md §22: a reactor answering `token.pre_issue` with an `ext.` mutation and `login.post_auth` with a veto, over signed AMQP.
- [`examples/webauthn_passkeys.php`](examples/webauthn_passkeys.php) — CONTRACT.md §24: both ceremonies, the §24.6a JSON bridge to the browser half, and the §24.6b rule 5 failure classification.
- [`examples/account_lifecycle.php`](examples/account_lifecycle.php) — CONTRACT.md §25: the third `login()` outcome, voluntary and forced TOTP enrolment, email verification, and the password-reset triple.
- [`examples/par_login.php`](examples/par_login.php) — CONTRACT.md §26: the 201 answer, the two-parameter redirect URL, and the exchange that follows.
- [`examples/management_basics.php`](examples/management_basics.php) — CONTRACT.md §27: namespace handles, one page vs. every page, sparse updates, per-handle scoping, and the three error classifications.
- [`examples/management_manifest.php`](examples/management_manifest.php) — CONTRACT.md §27.6/§27.7: plan (which writes nothing) then apply (which stops at the first failure and does not roll back), including a `deny` grant.
- [`examples/management_manifest_attributes.php`](examples/management_manifest_attributes.php) — the same manifest declared with `#[Managed*]` attributes instead of the builder.
- [`examples/device_mtls_provisioning.php`](examples/device_mtls_provisioning.php) — the operator/device split: mint a `Device` certificate from the tenant's signing CA, bind it to a service account, write the one-time private key at `0600`, then authenticate as the device over §6.1 mutual TLS.
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
