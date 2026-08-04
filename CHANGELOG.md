# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0-alpha24] - 2026-08-04

### Added

- Add AxiamWebhooks::verify signature verifier (CONTRACT §13, T-145)

### Changed

- Device (mTLS) tokens now carry aud=axiam:m2m (#22)
- Service accounts can use login_client_credentials (#21)
- Bump coverallsapp/github-action from 2.3.6 to 2.3.8

### Fixed

- SEC-085 — request guards must not substitute the client's own session (#20)
- Enforce the full CONTRACT §10.1 local-verification set

## [Unreleased]

### Security

- **BREAKING (authentication bypass fixed) — `SEC-085`.** The Laravel middleware and the
  Symfony subscriber verified the inbound request with
  `AxiamClient::verifyLocallyOrFallback()`. That method is a *client-side* helper: when
  the supplied token fails verification it refreshes **this application's own session**
  and verifies **that** token instead, returning its claims. As a request guard it meant
  a caller presenting an **expired, foreign-tenant, unsigned or outright garbage** token
  was not rejected — it was admitted and authenticated as the application's own AXIAM
  principal, typically a **service account** more privileged than the end user whose
  request it replaced. Every downstream authorization decision then ran under that
  identity.

  Both guards now call the new `AxiamClient::verifyLocally()`, which applies the full
  §10.1 set to the caller's token and has **no fallback**. `verifyLocallyOrFallback()`
  remains for the SDK's own outbound calls, where refreshing the client's own token is
  the intended recovery, and now documents that it must never be used as a guard.

  This is codified upstream as **CONTRACT.md §10.1 rule 8** ("subject of the decision"):
  a guard decides on the caller's credential and no other. Requests that were previously
  admitted under the application's identity will now correctly receive `401`.

### Fixed

- **Slug-vs-UUID tenant comparand now diagnoses itself.** AXIAM access tokens carry the
  tenant **UUID** in `tenant_id`, but this SDK's client is configured with a tenant
  **slug**. A guard handed that slug rejects 100% of traffic — fail-closed and safe, but
  it presents as "every token is invalid" with nothing pointing at the cause.
  `JwksVerifier` now emits a single `E_USER_WARNING` naming the real problem. It fires
  **once per process**, only when the configured value is not UUID-shaped while the claim
  is, and strictly *after* the rejection is decided — so it cannot be used as a log-flood
  lever and does not alter the verification outcome in any way. A genuine cross-tenant
  rejection (UUID vs UUID) stays silent.

- **BREAKING (acceptance tightened).** Align local token verification with the new
  normative CONTRACT.md §10.1 "minimum local-verification set". Three defects:
  - **`exp` is now REQUIRED.** `JwksVerifier::verify()` delegated expiry entirely to
    `firebase/php-jwt`, whose gate is `isset($payload->exp) && (…)` — so a token
    carrying **no** `exp` at all sailed straight through and was accepted as a
    *permanent credential*. That is the `SEC-080` defect verbatim: "the claim was
    missing so there was nothing to check". A quoted numeric `exp` (`"1700000000"`) was
    also accepted, because the library's guard is `is_numeric()`, which passes numeric
    strings; a JSON string is not an RFC 7519 NumericDate and is now rejected rather
    than coerced.
  - **The `X-Tenant-ID` request header could OVERRIDE the configured tenant.** Both the
    Laravel middleware and the Symfony subscriber computed
    `$tenantId = $request->headers->get('X-Tenant-ID') ?: $this->tenant` and verified
    the token against *that*. Because the header is attacker-controlled, presenting a
    token for tenant B alongside `X-Tenant-ID: B` compared the token against itself —
    a vacuous check that admitted any tenant's token to an app configured for a
    different one. §10.1 rule 4 requires the assertion be made against the **configured**
    tenant. The header now only *narrows*: when present it must agree with the verified
    claim, and it can never select which tenant is expected.
  - **Clock skew was not bounded.** `firebase/php-jwt`'s `JWT::$leeway` is a public
    mutable static any code in the process can set to an unbounded value, which §10.1
    rule 7 forbids. Verification now pins it to this SDK's own named constant for the
    duration of every decode, and applies that same constant in its own `exp`/`nbf`
    checks.

  Tokens minted by the AXIAM server are unaffected — they always carry `exp` and never
  a future `nbf`. A guard fed tokens from **another signer sharing the organization-wide
  JWKS**, or an application relying on `X-Tenant-ID` to serve multiple tenants from one
  configured client, may start rejecting what it previously accepted. That is the intent.

### Added

- Add the `axiam.expected_issuer` / `AXIAM_EXPECTED_ISSUER` and
  `axiam.expected_audience` / `AXIAM_EXPECTED_AUDIENCE` configuration (plus the
  corresponding `AxiamClient` and `JwksVerifier` constructor parameters) — the
  CONTRACT.md §10.1 rule 5/rule 6 checks. Both are **conditional and default to unset**:
  with no expectation configured no check is performed at all, and once configured a
  mismatching — or absent — claim is rejected. No issuer or audience is hardcoded
  anywhere in this SDK; an app guarding a user-facing resource server should generally
  expect `axiam:user`. `aud` honours both RFC 7519 shapes (single string, array).
- Add `JwksVerifier::CLOCK_SKEW_LEEWAY_SECONDS` — the named, bounded 60-second
  clock-skew constant applied to the `exp`/`nbf` checks (§10.1 rule 7). It is a class
  constant and is deliberately not operator-configurable.
- Add the complete §10.1 required negative-test set
  (`tests/Contract101LocalVerificationTest.php`): expired; no `exp`; non-numeric `exp`;
  numeric-*string* `exp`; null `exp`; future `nbf`; different tenant; no `tenant_id`; no
  configured tenant; `alg: none`; a real HS256-signed token bearing an EdDSA key id;
  issuer and audience mismatch and absent-claim cases; and a case proving a global
  `JWT::$leeway` cannot widen this SDK's window.
- **Webhook signature verification (CONTRACT §13, T-145).** New
  `Axiam\Sdk\Webhook\AxiamWebhooks::verify()` validates the `X-Axiam-Signature` header
  AXIAM attaches to every webhook delivery: HMAC-SHA256 over `<timestamp>.<raw_body>`,
  compared in constant time (`hash_equals`) on the decoded bytes, with a two-sided
  freshness window defaulting to 300 seconds and an injectable clock for testing.
  Multiple `v1` values are accepted so secret rotation does not drop deliveries; a header
  carrying no `v1` is always a failure rather than a silent pass. Returns a
  `WebhookEvent`, or throws `WebhookVerificationException` whose message never contains
  the secret or the expected signature. Callers MUST pass the raw request body — see the
  README for the re-serialization caveat.
- `CONTRACT.md` §13 vendored; conformance statement updated to §1–§13.

### Changed

- Re-sync the vendored `CONTRACT.md` with the new normative §10.1.

## [1.0.0-alpha23] - 2026-08-02

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha21.

## [1.0.0-alpha21] - 2026-07-30

### Added

- Add OIDC/SSO relying-party helpers (CONTRACT §12, contract 1.4)

### Changed

- Re-sync vendored CONTRACT.md to contract 1.6
- Add regression coverage for CSRF-capture-after-login fix (1ee9776)
- Re-sync vendored CONTRACT.md to contract 1.5

### Fixed

- Capture the CSRF token after login/verifyMfa (H8 SDK bench)
- Share oidcRefresh's outcome across same-kind guard contention

## [1.0.0-alpha19] - 2026-07-27

### Fixed

- `oidcRefresh()`: a concurrent caller that finds the §9 single-flight guard already
  busy with ANOTHER `oidcRefresh` call now shares that leader's outcome instead of
  re-acquiring the guard and issuing its own token-endpoint request. AXIAM refresh
  tokens are single-use with rotation, so the previous behavior could replay an
  already-consumed refresh token and fail `invalid_grant` under Fiber/event-loop
  concurrency (cross-SDK conformance review F-06). `Session::refreshGuard()` gains an
  optional `kind` parameter (`Session::REFRESH_KIND_SESSION` /
  `Session::REFRESH_KIND_OIDC`) to tell same-operation contention (share the result)
  apart from cross-operation contention (wait and retry, unchanged). Additive,
  non-breaking.

### Added

- OIDC / SSO relying-party helpers (CONTRACT §12, contract 1.4): `oidcDiscover`,
  `oidcBegin`, `oidcExchange`, `oidcRefresh`, `loginClientCredentials`, `introspect`,
  `revoke`, `ssoStart`, `ssoComplete` directly on `AxiamClient`.
  - New `Axiam\Sdk\Oidc\*` namespace: `OidcClient` (internal engine),
    `OidcConfiguration`, `AuthorizationRequest`, `OidcTokenSet`, `IntrospectionResult`,
    `SsoStartResult`, `SsoCompleteResult`, `Pkce` (RFC 7636 S256-only PKCE),
    `IdTokenValidator` (§12.4 issuer/audience/time/nonce checks),
    `OidcStateStoreInterface` + `MemoryOidcStateStore` (single-use, 10-minute TTL),
    `OidcLoginFlow` (the shared framework-agnostic "Login with AXIAM" begin/complete
    core).
  - `Axiam\Sdk\Core\OAuthProtocolError`: a new `AuthError` sub-type for RFC 6749
    `OAuth2ErrorResponse` bodies from `/oauth2/*` — existing `catch (AuthError $e)`
    blocks keep working unchanged.
  - `Axiam\Sdk\Auth\JwksVerifier::verifyIdTokenSignature()`: extends the existing §10
    JWKS verifier (never forked) with §12.4 rules 1–2 (algorithm pin + Ed25519
    signature, single re-fetch on an unknown `kid`) for ID tokens.
  - Laravel: `Route::axiamOidcLogin()` route macro + `OidcLoginController`/
    `OidcCallbackController` (optional, off by default).
  - Symfony: `OidcLoginController`/`OidcCallbackController` (optional, manually
    registered, off by default).
  - `AxiamClient` gains three new optional constructor parameters: `oidcClientId`,
    `oidcClientSecret`, `oidcTenantId`.

## [1.0.0-alpha18] - 2026-07-24

### Changed

- Update guzzlehttp/guzzle requirement from ^7.13 to ^7.13 || ^8.0 (#10)
- Bump actions/checkout from 7.0.0 to 7.0.1 (#9)
- PHP SDK 88.3% → ~96.9% + add coverage gate (Phase B) (#12)

## [1.0.0-alpha16] - 2026-07-22

### Added

- Add gRPC-only getUserInfo operation (CONTRACT §1.1, contract 1.3)

### Changed

- Import TestCase in the userinfo test's second namespace block
- Vendor CONTRACT 1.3 + userinfo.proto and regenerate gRPC message stubs

## [1.0.0-alpha15] - 2026-07-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha12.

## [1.0.0-alpha12] - 2026-07-19

### Fixed

- Supply organization context for login/refresh (CONTRACT §5.1) (#8)

## [1.0.0-alpha11] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha10.

## [1.0.0-alpha10] - 2026-07-18

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha9.

## [Unreleased]

### Added

- gRPC-only `getUserInfo()` operation (CONTRACT.md §1.1, adopting contract 1.3):
  `AxiamClient::getUserInfo()` invokes `axiam.v1.UserInfoService/GetUserInfo` — the
  low-latency counterpart of the server's REST `GET /oauth2/userinfo` — over the SDK's
  existing gRPC channel (via the `AuthzDispatcher`), carrying the same
  `authorization: Bearer` + `x-tenant-id` metadata as the gRPC `checkAccess` path. It
  returns a typed `Axiam\Sdk\Auth\UserInfo` value object (`sub`, `tenantId`, `orgId`, and
  the scope-gated optionals `?email` / `?preferredUsername`, present only when the token
  carries the `email` / `profile` scope). Unlike `checkAccess`/`can`/`batchCheck` it is
  **gRPC-only with no REST fallback** (§1.1.6): on a runtime without the `grpc` extension
  (or with `restOnly: true`) it raises `NetworkError`. It requires a prior successful
  `login()` — calling it with no token raises `AuthError` before any wire call (§1.1.3) —
  and a gRPC `UNAUTHENTICATED` response drives the shared single-flight refresh (§9) and
  retries the RPC once (§1.1.4). The new `proto/axiam/v1/userinfo.proto` message stubs are
  committed under `src/Grpc/Gen/`; the `UserInfoService` client
  (`src/Grpc/UserInfoGrpcClient.php`) is hand-written against `\Grpc\BaseStub`, mirroring
  `AuthzGrpcClient` (no `grpc_php_plugin` required).
- Client-certificate / mutual-TLS (mTLS) support (CONTRACT.md §6.1): two new optional
  `AxiamClient` constructor parameters, `clientCert` and `clientKey` (both PEM strings — the
  certificate chain and its private key). When supplied together the client presents that
  X.509 identity for mutual TLS on **both** transports — the REST Guzzle clients (`cert`/
  `ssl_key`) and any gRPC channel (`\Grpc\ChannelCredentials::createSsl(rootCerts, privateKey,
  certChain)`). The feature is opt-in and strictly additive: server verification is never
  relaxed (the strict-TLS `verify` policy is untouched). The two parameters are all-or-nothing
  and PEM-only — supplying exactly one, or a non-PEM value, throws `InvalidArgumentException`
  at construction. The private key is treated as secret material (§7): held behind `Sensitive`,
  materialized only into a `0600` temp file (removed when the client is destroyed), and never
  logged, displayed, or exposed via a getter. Conformance statement updated to note §6.1.

## [1.0.0-alpha2] - 2026-07-16

### Added

- Declarative per-endpoint authorization helpers (CONTRACT.md §11): `#[RequireAuth]`,
  `#[RequireAccess(action: ..., resourceParam: ...)]`, and `#[RequireRole(...)]` PHP 8
  attributes in `Axiam\Sdk\Attributes`, enforced by a shared `Axiam\Sdk\AccessEnforcer`
  used by both framework bridges — `Axiam\Sdk\Symfony\AxiamAccessAttributeListener`
  (a `kernel.controller` listener) and `Axiam\Sdk\Laravel\AxiamAccessMiddleware` (the
  `axiam.access` route-middleware alias, supporting both the attribute style and a
  string-param style, e.g. `->middleware('axiam.access:read')`). The resource UUID is
  resolved from a static literal, a route parameter, or a resolver callback; the check
  is always made for the request's authenticated user (`subject_id`), never the shared
  `AxiamClient`'s own session; a transport failure fails closed with `503`. Conformance
  statement updated to CONTRACT.md §1–§11.
- `AxiamClient::checkAccess()` (and the underlying `AuthzDispatcher`/`AuthzRestClient`)
  gained an additive, optional `subjectId` parameter so a caller can evaluate a check
  on behalf of a specific subject rather than the client's own session identity —
  existing call sites are unaffected (the parameter defaults to `null`, preserving prior
  behavior exactly).

## [1.0.0-alpha] - 2026-07-15

First alpha release of the official PHP client SDK for AXIAM. This is an early,
pre-production preview published to Packagist for evaluation and feedback — the
public API may still change before the beta and stable releases.

### Added

- REST client covering the AXIAM API surface (authentication, authorization
  checks, tenant/user/role/resource management).
- Strict TLS by default with no certificate-verification bypass surface.
- PSR-compliant, PHPStan level 6 clean, with a 100%-documented public API.
- Usage examples for the common authentication and authorization flows.

[1.0.0-alpha]: https://github.com/ilpanich/axiam-php-sdk/releases/tag/v1.0.0-alpha
