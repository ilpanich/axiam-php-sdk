# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- OPAQUE (RFC 9807) login and enrolment (CONTRACT §23): `loginOpaque()`,
  `opaqueEnrollment()` and `opaqueAvailable()` on `AxiamClient`, plus the new
  `Axiam\Sdk\Opaque` namespace.
- `examples/opaque_login.php`.
- `ext-ffi` in `suggest`. It binds `libaxiam_opaque_ffi`; a consumer whose tenant
  does not use OPAQUE needs neither.

### Removed

- **BREAKING** — SRP-6a. `loginSrp()`, `srpEnrollment()`, `srpAvailable()`, the
  whole `Axiam\Sdk\Srp` namespace (both bignum backends), `srp-test-vectors.json`
  and `examples/srp_login.php` are all gone. AXIAM's server-side SRP endpoints are
  removed in the same release, so keeping the client would leave methods that only
  ever return 404.
- `ext-gmp` and `ext-bcmath` from `suggest`. They were there for SRP's modular
  exponentiation and nothing else in this SDK uses them.

### Changed

- **BREAKING** — the OPAQUE protocol is NOT implemented in this SDK. CONTRACT
  §23.1 forbids it, so the client half is an FFI binding to
  `libaxiam_opaque_ffi` — the same implementation the AXIAM server links,
  published as a per-platform asset on the axiam release page rather than as a
  Composer package. Put it on the system library path or set
  `AXIAM_OPAQUE_LIBRARY`.
- **PHP is now conditional on one thing rather than two, and the one that went
  away was the bad one.** The SRP client needed a bignum extension *and* a tenant
  configured for `pbkdf2_sha256`, because no PHP runtime offers Argon2id with a
  caller-supplied 32-byte salt — AXIAM's default KDF was, for PHP, unreachable,
  and the advice was to weaken the tenant's configuration for PHP's benefit. The
  key stretching now happens inside the shared library, so a `true` from
  `opaqueAvailable()` means every tenant works, default included.
- **BREAKING** — `opaqueEnrollment()` performs I/O, where `srpEnrollment()` did
  not: OPAQUE's envelope is sealed under the server's oblivious PRF, so there is
  no offline computation that produces a valid record. It also drops the
  `$identity`, `$group` and `$params` arguments — a record binds to a credential
  identifier the server chooses, and the key-stretching parameters are the
  server's. As a consequence, **renaming a user no longer invalidates their
  credential**.
- Failure taxonomy for the OPAQUE path: a tenant with OPAQUE disabled, an absent
  `ext-ffi` or library, and a key-stretching function this build cannot perform
  are all `NetworkError` (a caller can fall back, or an operator can act);
  everything else is `AuthError` and must NOT be retried over `login()`
  (§23.4 rule 7).

## [1.0.0-alpha31] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha30.

## [1.0.0-alpha30] - 2026-08-20

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha29.

## [1.0.0-alpha29] - 2026-08-20

### Added

- SRP-6a login client, conditional on a bignum extension (CONTRACT §23) (#41)

## [1.0.0-alpha28] - 2026-08-19

### Changed

- Re-vendor openapi.json at 1.0.0-alpha27 (#40)

## [1.0.0-alpha27] - 2026-08-17

### Added

- §22.14 declarative reactor handler binding — ReactorHandlers

### Changed

- Re-vendor CONTRACT.md 1.23 (§8b rules 7 and 8)
- Re-vendor openapi.json for the SCIM provisioning-token endpoints
- Re-vendor CONTRACT.md 1.22 from the server repo

## [1.0.0-alpha25] - 2026-08-16

### Added

- Ship the §22 reactor runtime — reactorServe (R2.5)
- Extend §10.1 rule 9 for DPoP and implement §21.7.2 (#33)
- SubjectTokenType is required, and moves second (contract 1.13)
- §15.7 — external-IdP subject tokens at the exchange (X4)
- §20.3 — emit a UMA challenge from the §11 enforcer (#27)
- §20 UMA 2.0 — Protection API and ticket grant (#26)
- §16 retry, §17 memo, §18 close(), §19 telemetry + config_clamped (D5) (#24)
- Device grant, token exchange, logout helpers; contract re-sync (D6) (#23)

### Changed

- Add a codegen drift gate for the committed gRPC stubs (D-03)
- Re-vendor CONTRACT.md 1.19, openapi.json and proto/ from main (R5.8) (#35)
- R5.7 — §9 refresh-result sharing under concurrency (F-06), AuthError parameter order (F-18), §12.3 rule 3 invariant (F-14) (#34)
- Contract 1.15 — §10.1 rule 9, sender-constrained access tokens (#32)
- Retire the "measured residual" justification (contract 1.14)
- Re-sync to contract 1.14 (#302 closed)

### Fixed

- §15.7 — Sensitive exposes via reveal(), not expose()
- Route checkAccess/can/batchCheck through the instrumented path (F3) (#25)

## [Unreleased]

### Added

- **CONTRACT.md §22 — Reactors, the AMQP extension actors (contract 1.18/1.19; remediation
  R2.5).**

  New `Axiam\Sdk\Reactor\ReactorServer::reactorServe()` — §22.10's `reactor_serve`, spelled
  `reactorServe` by that subsection's per-language table. It consumes the **server-declared**
  queue, verifies every delivery, dispatches to a handler, signs and publishes the reply, and
  returns cleanly on shutdown.

  §8's HMAC now runs in **both directions** on one exchange — the server signs the event, the
  reactor signs the reply with the same tenant subkey — with one canonicalization difference
  that costs a day if it is not stated: `hmac_signature` is serialized as **`null`** inside a
  reactor body rather than omitted as it is in §8's own two message types. The §22.13 vectors
  ship beside the §8 vectors under the same master key, tenant and derived subkey;
  `tests/Fixtures/reactor_v2_reference_vectors.json` is vendored and both directions are
  asserted byte-for-byte against `canonical_signed_json`, including the omission of
  `reason`/`patch` when absent and of `require_mfa` when false.

  Three PHP-specific canonicalization traps are handled once, in `ReactorProtocol`, and
  tested rather than commented: `json_encode()` escapes slashes and non-ASCII where
  `serde_json` escapes neither; a body decoded into an associative array turns an empty
  `payload` object into `[]`, so reactor bodies are decoded into `stdClass`; and a patch is
  key-sorted with `SORT_STRING` and written through an object, because the server's
  `BTreeMap` emits byte-ordered keys while a PHP array emits insertion order and would
  serialize numeric-looking keys as a JSON array.

  Three rules are structural rather than documented. `ReactorAnswer::allow()` and
  `allowWithStepUp()` take no patch, so `allow` + `patch` cannot be spelled. `ReactorTransport`
  has no declare or bind method, so §22.1's "actors consume, they never declare topology" has
  no seam to leak through — a reactor that could bind could bind itself to another tenant's
  routing key. And a handler that throws publishes **nothing**: no synthesized `allow`,
  because that would override the operator's `fail_closed` from inside the library.

  A mutation is sent **unfiltered** (§22.4 rule 1) — one forbidden key rejects the whole patch
  server-side, and dropping the offender would leave the author believing a field was set when
  it was dropped.

  §22.7's hot-path exclusion is enforced with a test rather than a comment: the three hot-path
  decision operations appear in no constant, no list and no doc example under `src/Reactor/`
  or `examples/reactor/`, asserted by a source scan.

  Also new: `ReactorEvents::all()` and `ReactorEvents::defaultFailurePolicy()` (the §22.5
  registry and §22.8's strictest-wins composition, which an SDK MUST NOT reduce to "take the
  first event's default"), `ReactorEvents::queueName()`/`routingKey()`,
  `AmqpLibReactorTransport::connect()` (§8b: `amqps://` only, optional CA bundle, no
  verification-skip switch), and a `ReactorTelemetryEvent` (§19) whose fields are all fixed
  readonly scalars so no variant can carry a secret. The tenant AMQP subkey is typed
  `Sensitive` at the constructor rather than by convention (§22.12). New example:
  `examples/reactor/reactor.php`.

  **One documented deviation from the Go/Java runtimes, and it is pre-existing SDK policy
  rather than a §22 decision:** there is no in-process reconnect loop. `php-amqplib` has no
  built-in reconnection, so as with this SDK's §8 consumer the serve loop returns when the
  broker session ends and a process supervisor restarts the worker. §22.10's four normative
  rules on the helper are all implemented; reconnect appears only in that subsection's
  descriptive prose.

  Not breaking: nothing existing moved, and `Axiam\Sdk\Amqp\Consumer` is untouched.

### Changed

- Re-vendor `openapi.json` at 1.0.0-alpha27 — the copy was pinned at alpha26 and
  failing the cross-repo artifact-drift gate
- **`AuthError::__construct()` parameter order corrected — `$reason` moves from second to
  last (conformance-review F-18, remediation R5.7).**

  New signature: `__construct(string $message, ?\Throwable $previous = null, ?string
  $reason = null)`. Previously `$reason` sat second, ahead of `$previous`.

  **This is a source-level break, and calling it non-breaking would be wrong.** Any code
  that wrote `new AuthError($message, 'token_expired')` positionally must now write
  `new AuthError($message, reason: 'token_expired')`; from `1.0.0-alpha19` up to this
  release that positional form was the documented one. It is being changed rather than
  kept because the alternative is worse and permanent: before §12, `AuthError` had no
  constructor of its own and inherited `RuntimeException`'s, so second-position meant the
  cause for the class's whole prior life, and `new AuthError($msg, $previous)` — the shape
  this SDK's own `NetworkError` still uses — silently became a `TypeError`. Fixing the
  order now, at `1.0.0-alpha*`, costs one mechanical edit per call site; leaving it costs
  a permanently surprising constructor. Six call sites inside this SDK were updated
  (`JwksVerifier`, `IdTokenValidator`); `AuthErrorParameterOrderTest` locks the order so a
  future additive parameter is appended rather than inserted.

  `getReason()`, `getPrevious()`, `getMessage()`, the class hierarchy, and
  `OAuthProtocolError` are all unchanged, so every `catch (AuthError $e)` block and every
  reader of these accessors is unaffected.

- **The §12.3 rule 3 invariant is now named at the transport seam** (conformance-review
  F-14, remediation R5.7). A 401 from `/oauth2/*` stays out of the §9 refresh guard
  because no 401→refresh interceptor sits on the transport §12 uses — an invariant kept
  by *absence*, which nothing in the type system re-checks. `AxiamClient`'s OIDC seam now
  spells out the two edits that would silently break it (pushing `RefreshMiddleware` onto
  `$plainStack`; handing `OidcEngine` the `$authzHttp` client) and points at the two
  regression tests that guard it. Those tests previously inferred "no refresh happened"
  from a `MockHandler` "queue is empty" error; they now assert zero
  `/api/v1/auth/refresh` calls against the transaction log directly. No behaviour change.

### Fixed

- **`oidcRefresh()`: a waiting caller no longer destroys the in-flight refresh it is
  waiting for (CONTRACT.md §9 rules 1/2, conformance-review F-06, remediation R5.7).**

  1.0.0-alpha19 taught `Session::refreshGuard()` to tell same-operation contention apart
  from cross-operation contention, so a second concurrent `oidcRefresh` stopped issuing
  its own token request. It then awaited the leader's outcome with
  `PromiseInterface::wait()` — which is not a wait at all. Guzzle's `wait()` *drives* a
  promise: it takes the underlying wait function, nulls it, and runs it. The leader had
  already consumed it, so the waiter's `wait()` found a pending promise with no wait
  function and **rejected the leader's promise** ("Cannot wait on a promise that has no
  internal wait function"). Every caller in the burst failed, and because the rejection
  ran the guard's clear-on-both-paths bookkeeping, the slot was freed while the leader's
  request was still on the wire — so the next caller started a second
  `POST /oauth2/token` with a refresh token the leader had already spent. Single-use
  rotation makes that a replay, not a retry.

  Waiters now use the new `RefreshGuard::join()`, which *observes* the shared promise
  (register a callback, drain Guzzle's task queue, yield to the scheduler) instead of
  driving it, and re-raises the leader's failure as `AuthError` for every waiter. Only
  the leader — the `ran === true` caller — calls `wait()`. Bounded per §9 rule 5:
  exhausting the wait raises `AuthError` rather than returning a stale token set.

  Reachable only on a concurrent runtime (Fibers, Swoole, RoadRunner); vanilla
  synchronous PHP has no second caller. Additive and non-breaking — no public signature
  changed.

- **§9's per-operation burst test now exists for `oidcRefresh`** (`OidcRefreshBurstTest`):
  five concurrent callers, each in its own `Fiber`, against a transport that suspends the
  caller mid-request, asserting exactly **one** `/oauth2/token` wire call and that all
  five receive that one call's access token — plus the failure half of rule 2 (one failed
  call, five `AuthError`s, still one wire call). It fails against the previous release.

### Added

- **CONTRACT.md §10.1 rule 9 extended for DPoP, and §21.7.2 proof verification
  implemented (contract 1.16/1.17).**

  `JwksVerifier::verifyTokenBinding()` applies the full ten-row rule against a
  certificate thumbprint, a verified DPoP key thumbprint, or **both**. A `cnf`
  naming both methods is a **conjunction** — satisfying only the more convenient
  one is not compliance — and a `cnf` naming nothing this SDK can check (including
  an *empty* one, which is how proto3 delivers an empty `CnfClaim`) is refused
  rather than read as unbound. `verifyCertificateBinding()` remains for
  certificate-only transports and now **refuses** a DPoP-bound or both-bound token
  rather than ignoring the half it cannot check.

  New `DpopVerifier` implements all ten §21.7.2 checks and returns the proof key's
  RFC 7638 thumbprint, so a value passed to `PresentedProofs` could only have come
  from a proof that verified. `InMemoryJtiStore` covers check 8; the `JtiStore`
  argument is required, not optional, because there is no safe default that skips
  replay tracking. **On PHP-FPM the in-memory store prevents no replay at all** —
  it does not survive the response — so its docblock points at Redis or a unique
  index instead.

  PS256 arrives via `firebase/php-jwt` delegating to `phpseclib`, since PHP's own
  `openssl_verify()` has no PSS padding; phpseclib is already in the dependency
  graph, and a PS256 proof fails closed if it is ever absent.

  Not a breaking change: an unbound token is still accepted with no certificate and
  no proof, asserted directly by the first test in the new group.

- **CONTRACT.md §10.1 rule 9 — sender-constrained (certificate-bound) access tokens**
  (contract 1.15, RFC 8705 §3 / RFC 7800). A token carrying `cnf` is **not** a bearer
  token; accepting one without proving the caller holds the named key converts it back
  into one.
  - `JwksVerifier::verifyCertificateBinding(array $claims, ?string $presentedThumbprint): bool`
    — the rule. Returns `bool` rather than throwing, matching `verify()`: this class never
    throws on attacker input.
  - `JwksVerifier::certificateThumbprintS256(string $der): string` — RFC 8705 §3.1
    `x5t#S256`: base64url, **unpadded**, SHA-256 over the DER certificate.

  **Not a breaking change, and it does not make certificates mandatory.** An *unbound*
  token is still accepted with or without a certificate.

  `verify()` deliberately does **not** apply rule 9: it has no transport to ask for a peer
  certificate. Under PHP-FPM behind an mTLS terminator the thumbprint typically comes from
  `$_SERVER['SSL_CLIENT_CERT']` — and only where that variable is set by a proxy **you**
  control, never from a caller-settable request header.

  A `cnf` naming an unimplemented method is **rejected**, never read as "unconstrained".

- **CONTRACT.md §21** — the FAPI 2.0 posture as an SDK sees it. Only rule 9 is normative
  for this SDK.

### Changed

- **Re-sync vendored `CONTRACT.md` / `openapi.json` to contract 1.15.**


### Changed

- **Re-sync vendored `CONTRACT.md` to contract 1.14** — documentation only, no code change.
  §20.2 rule 6 (a permission ticket MUST NOT be retried) cited a "measured residual
  (ilpanich/axiam#302) … roughly 1 in 640" as its second reason. That residual is closed: the
  server now decides the ticket race with a transaction its storage engine arbitrates plus a
  redemption nonce read back after the commit. **The rule is unchanged, and this SDK's
  behaviour is unchanged** — `uma_exchange_ticket` stays excluded from every automatic retry
  path. What changed is the reasoning: the first reason (a spent ticket makes the retry
  useless) always stood alone, and the second now rests on what an SDK can actually know —
  it is talking to a server whose storage engine it cannot attest, and the guarantee is
  conditional on that engine being persistent.
- **BREAKING (contract 1.13): `tokenExchange`'s `$subjectTokenType` is now required, and moves
  from last to second** in the signature.

  It shipped optional and last — last precisely so existing positional callers were unaffected.
  That satisfied §15.7's "never inspect the subject token" while leaving the rule it serves
  unenforced: an optional parameter with a default *is* a default the SDK applies whenever the
  caller says nothing. §15.1 now makes it required.

  **Making it required breaks positional callers anyway, so it may as well sit where the
  contract puts it** — second, next to the `$subjectToken` it describes, matching the other ten
  SDKs. The reason for the old placement expired with the default.

  PHP refuses a call that omits it (`ArgumentCountError`, before any SDK code runs). The case
  the signature cannot catch is a **blank** string — the shape a config-driven caller produces
  — so that is refused client-side with no wire call, naming both constants. Both are asserted.

  **Migration** — pass it second, or by name:

  ```php
  $exchanged = $client->tokenExchange(
      subjectToken: $userToken,
      subjectTokenType: OidcClient::ACCESS_TOKEN_TYPE, // <- add this
      scopes: ['orders:read'],
  );
  ```

  This closes a gap rather than opening one: `subject_token_type` has always been required *on
  the wire*, and the SDK was covering for that with a constant which stopped being the only
  legal value when X4 landed.

### Added

- **§15.7 external-IdP subject tokens (X4).** `tokenExchange()` can now exchange a token minted
  by a trusted external IdP — a partner's Entra, Okta or Keycloak — for an AXIAM token scoped to
  what the resolved AXIAM user may actually do. No new operation: the same method, plus a
  `$subjectTokenType` parameter and the new `OidcClient::JWT_TOKEN_TYPE` constant alongside the
  existing `ACCESS_TOKEN_TYPE`.

  **The type is the caller's to name, never the SDK's to guess.** §15.7 forbids inspecting the
  subject token to pick it, because which kind of token you hold is something only you know and
  a wrong guess is the difference between a request that is refused and one that is silently
  reinterpreted. A JWT-shaped subject token does **not** change what is sent, which is asserted
  by a test. (This shipped optional and last in the signature; contract 1.13 made it required
  and moved it second — see *Changed* above.)

  Also asserted: an `$actorToken` alongside an external subject token surfaces
  `invalid_request` with no retry and no request rewriting; a refused refresh or ID token type
  is never retried as a different type; the one normative description — `the subject token's
  issuer is not configured for token exchange`, meaning *fix the AXIAM trust config* rather than
  *fix your token* — reaches the caller intact; and nothing re-exchanges an exchanged token,
  which both server paths refuse because exchanges do not compose.

  `CONTRACT.md` and `openapi.json` re-synced from `ilpanich/axiam@main` (contract 1.10 → 1.12
  plus §15.7), which also brings contract 1.11's lifted §12.6 deferral, contract 1.12's
  `/oauth2/*` error rows dispatching on the `error` field at any status, and the
  `TokenExchangeTrust` schemas behind the X4 provider configuration.

- **§20.3 challenge emission from the §11 enforcer.** `AccessEnforcer`'s new third
  constructor argument takes a `UmaChallenger` (realm, `as_uri`, PAT, client); with one, a
  `#[RequireAccess]` denial mints a permission ticket for the action that was refused and
  returns it as `WWW-Authenticate: UMA` alongside the unchanged 403 body. Because both
  framework bridges delegate every §11 decision to that one enforcer, configuring it once
  covers Laravel and Symfony alike.

  It is **opt-in** because emitting a challenge means minting a credential: an enforcer that
  did it by default would turn every unauthorized request into a Protection API call, which
  is a denial-of-service amplifier pointed at your own authorization server. An allow mints
  nothing. And a **minting failure is not an escalation** — an expired PAT or an unreachable
  Protection API still yields the plain 403, never a 503 and never an allow. Both are
  asserted by counting Protection API requests. The requested scope is the AXIAM *action*,
  so the ticket asks for exactly the authority just refused and the engine's deny rules keep
  applying to whatever RPT comes back.

  Paired with the new `examples/uma_resource_server.php` and `examples/uma_client.php`,
  which run both halves — including the trust decision §20.3 keeps in the caller's hands
  rather than auto-exchanging against whatever host a 403 named.

- **§20 UMA 2.0 — Protection API and ticket grant.** Nine methods on `AxiamClient`:
  `umaRegisterResource`, `umaReadResource`, `umaUpdateResource`, `umaDeleteResource`,
  `umaListResources`, `umaRequestTicket`, `umaExchangeTicket`, and the two local
  challenge helpers `umaParseChallenge` / `umaChallengeHeader`. New value objects
  `ResourceSet`, `RequestedPermission`, `RptPermission`, `RequestingPartyToken` and
  `UmaChallenge` under `Axiam\Sdk\Oidc`.

  The load-bearing rules, all asserted in `tests/OidcUmaTest.php`:

  - **`umaExchangeTicket` is never retried** (§20.2 rule 6) — not on `5xx`, not on a
    timeout, not on `invalid_grant`. This is the one documented exception to §16, and a
    security rule rather than a performance one: the ticket is consumed *before* the
    exchange is evaluated, so a retry is a second redemption — the concurrency case whose
    measured residual `ilpanich/axiam#302` records.
  - **`umaParseChallenge` performs no exchange** (§20.3). The `as_uri` names an
    authorization server the caller has not chosen to trust.
  - **The RPT is never adopted** as this client's credentials (§20.2 rule 4), and carries
    no refresh token (rule 5) — `RequestingPartyToken` has nowhere to put one.
  - **`umaUpdateResource` replaces the scope list rather than merging it** (§20.2 rule 8);
    there is no read-modify-write, so omitting a scope removes it.

- **§16 bounded read-only retry policy** (`src/Core/RetryPolicy.php`), wired into
  `checkAccessDecision`: 3 attempts, 200 ms base, 5 s cap, **full jitter** over `[0, backoff]`,
  `Retry-After` honored as a floor. This SDK had no §16 policy before — `OidcClient`'s
  `for ($attempt...)` loop coordinates concurrent refreshes and is a different mechanism — so
  §11.2 rule 5's requirement had gone unmet since it was written.
- **§18 `AxiamClient::close()`** — idempotent, clears the memo, and use-after-close throws
  `NetworkError` rather than silently reconnecting. It does **not** log out and never reaches
  the network: the server-side session outlives the client object.
- **§19 telemetry hooks** — `telemetryHook:` on the constructor, plus the closed event
  hierarchy (`RequestStartEvent`, `RequestEndEvent`, `RetryEvent`, `RefreshEvent`,
  `ConfigClampedEvent`). A throwing hook cannot fail the operation that fired it, and no event
  payload can carry a token. One request pair per *attempt*.
- **§17 decision memo — opt-in, off by default** — `decisionMemoTtlMs:`, clamped to 5 s.
  Allows and denies memoized identically, failures never memoized, cleared on any credential
  change. **Reads-your-own-writes is not guaranteed.**
- **§19.2 rule 6 `ConfigClampedEvent`** — the clamped memo TTL is now reported at construction
  rather than applied silently. Nothing is emitted for a value already within its limit.
- `retryEnabled:` (§16.6), default `true`.
- `NetworkError::$retryAfterMs`, a parsed duration rather than the raw header text, so the
  sanitization discipline that class enforces is untouched. Both RFC 7231 forms parse.

### Changed

- Re-vendored `CONTRACT.md` at **1.10** and `openapi.json` (the server's `/uma2/*` surface).
- `login`, `verifyMfa`, `refresh` and `logout` clear the decision memo (§17.1 rule 9) and
  reject after close (§18.1 rule 4).
- `AuthMiddleware` gained `CREDENTIAL_OVERRIDE_OPTION`, a per-request Guzzle option naming a
  bearer credential that is not the session's. The middleware overwrites `Authorization`
  unconditionally — it has to, so a request retried after a single-flight refresh is
  re-decorated with the fresh token — which left no way for a caller to say "use *this*
  credential". The Protection API needs exactly that, because §20.2 rule 1 forbids falling
  back to the session token when a PAT was asked for.


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
