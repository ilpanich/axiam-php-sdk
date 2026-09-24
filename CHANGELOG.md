# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Contract 1.51.** `CONTRACT.md`, `openapi.json` and `management-registry.json`
  re-vendored from `ilpanich/axiam` `56fbe44` (`CONTRACT.md` sha256 starts
  `0ac7fd75f83c…`); `proto/` was already identical. The §27 surface regenerated to 195
  files (192 before).

- **§5.2 rule 1 — the acting tenant.** `new AxiamClient(..., actingTenant: $uuid)` at
  construction, and `$client->actingTenant($uuid)` / `$client->clearActingTenant()` on
  an existing client, send `X-Axiam-Tenant` on every `/api/v1` request while set — never
  on `X-Tenant-ID`'s behalf, and never on gRPC (the acting tenant is REST-only; the
  server's gRPC interceptor reads no such metadata). A non-UUID value is refused
  client-side (`NetworkError`), with zero wire calls. Gated on `organizationLevel`/
  `reachableTenantIds` once a login result reports them (login, verify-MFA, OPAQUE's
  finish, and the MFA/WebAuthn setup completions all set it; WebAuthn AUTHENTICATION,
  SSO/federation and a client-credentials/device-grant credential adoption reset it to
  unknown); a client holding no such result has nothing to gate on, and the server's
  `403` is the answer. The §17 decision memo key gained a fifth component, the acting
  tenant, so a memoized decision for one tenant can never answer a check against
  another. **Design difference from the reference implementation, recorded (C-12):**
  mutates the client and returns it (`self`) rather than returning a new handle over a
  shared session — PHP's request lifecycle has no concurrent tasks sharing one client
  the way a long-lived Rust/Go/Python process does.

- **§6.1 rules 6-10 — `authenticateDevice()`.** `POST /api/v1/auth/device`, no request
  body, reachable only on a client built with `clientCert`/`clientKey` (`AuthError`,
  zero wire calls, otherwise). Returns `Auth\DeviceToken { accessToken: Sensitive,
  tokenType, expiresIn }` and adopts it as this client's credential — the shared cookie
  jar is cleared first, so a cookie left from an earlier `login()`/`verifyMfa()` session
  on the same client object cannot silently outrank the device's own credential. Every
  refusal is `401` → `AuthError`; a `429` is `NetworkError`, never `AuthError`, and the
  call is never retried. Never enters the §9 single-flight refresh guard — there is no
  refresh token to spend. See `examples/device_mtls_provisioning.php`.

- **§1.1.1/§10.3 — `validateToken()`/`introspectToken()`.** gRPC wrappers over
  `axiam.v1.TokenService/ValidateToken` and `/IntrospectToken` — the operations §10.3
  has required an SDK validating over gRPC to read `cnf` from since contract 1.17, and
  no PHP method wrapped until now. Return `Auth\TokenValidation`/`Auth\TokenIntrospection`,
  each with `status(): TokenStatus` (`Inactive`/`Bearer`/`SenderConstrained`/
  `Unverifiable`) and `verifyPossession(PresentedProofs)`, which apply §10.1 rule 9
  through the SAME `JwksVerifier::verifyTokenBinding()` primitive local verification
  uses — the two transports cannot disagree about whether a token is a bearer token.
  gRPC-only; no REST substitution (`POST /oauth2/introspect` is a different operation).
  `AxiamException|null` gRPC-only guard, zero-wire-call precondition with no caller
  token, and the §9 refresh-retry-once, all mirror `getUserInfo()` exactly.

- **§13 row 17 — the manifest reconciles role permission grants and group role
  bindings.** `apply()` now grants every permission a role's manifest declaration names
  and does not already have, and assigns every role a group's manifest declaration
  names and does not already carry — additively (never revoking/unassigning something
  the manifest simply does not mention), for every role/group the manifest declares at
  least one grant/role for, whether or not that role/group's own fields needed a
  `Create`/`Update`.

- **§13 row 17 — the manifest sends a nested resource's `parent_id`.**
  `resource($key, $name, $type, parentKey: '…')` now resolves the parent to its real
  server id and sends it on `Create`. Previously the manifest ordered a child after its
  parent but never told the server about the relationship, so a nested manifest was
  created flat.

- **§27.6.1 addition 2 — resource-scoped role bindings.** `RoleBinding::at($role,
  $resource)` / `::atOnly($role, $resource)` join the plain role-key shape in a group's
  or service account's `roleKeys`. `inherit` reaches the wire only as `false`. A
  binding's natural key is `(subject, role)`: a server assignment with a different
  resource or `inherit` is an `Update`, performed as unassign-then-assign, carrying the
  server assignment's `tenant_scope` across unchanged; a failed re-assignment restores
  the previous binding and the failure is `BindingRebindFailed { restored, restoreError
  }` on `ApplyReport::$failure` (**C-12 question 7**: PHP's answer matches the
  reference — the previous binding is put back, and BOTH outcomes are reported, never
  just the first). A subject binding one role twice — plain and scoped alike — or a
  *global* role bound with `inherit: false`, is refused while the manifest is *built*,
  before a client exists to send anything (**C-12 question 6**: PHP refuses, matching
  the reference; §27.6.1 only lets an SDK do so, it does not require it). Previously
  declined; the decision is reversed — see `claude_dev/dogfooding-findings-fix-plan.md`
  §13 row 17 and the orchestrator's C-6 review.

- **§27.6.1 addition 3 — `service_accounts` in the manifest.**
  `->serviceAccount($key, $name, description: …, roleKeys: […])`, reconciled by `name`
  — which the server does not keep unique, so `plan()`/`apply()` refuse, before any
  write, when more than one existing account matches. `description` is the only field
  an `Update` reconciles. A `Create`'s one-time `client_secret` lands on
  `ApplyReport::createdServiceAccounts()`, kept even when a *later* step of the same
  `apply()` fails; `apply()` never calls `rotateSecret()`. Service accounts and their
  bindings are reconciled last (§27.6 rule 5). Previously declined; the decision is
  reversed — see above.

### Breaking

- **§10.1 rule 9 — `JwksVerifier::verify()` / `AxiamClient::verifyLocally()` now refuse
  a sender-constrained token they have no evidence for**, instead of admitting it as an
  ordinary bearer credential. `verifyLocally()` is the ONLY verification entry point the
  Laravel/Symfony framework bridges (and every downstream request guard) call, and it
  has no transport to ask for a peer certificate or a verified DPoP proof — so before
  this fix, a certificate- or DPoP-bound token (every device token from §6.1, or any
  DPoP-bound token) reached it with its `cnf` claim intact and unchecked, and was
  admitted as though it carried no confirmation at all. This is the same defect found
  independently in the Rust, TypeScript, Go, Python and C# ports. An application whose
  request guard was unknowingly accepting bound tokens as bearer tokens will now see
  those callers rejected (`verifyLocally()` returns `null`) until it switches to the new
  `AxiamClient::verifyWithProofs($token, $tenant, PresentedProofs)` / `JwksVerifier::
  verifyWithProofs()` and supplies the evidence its OWN connection established (never a
  request header — §10.1 rule 9 detail 2). An unbound token is unaffected.

### Fixed

- **§27.6 declarative manifest, two pre-existing defects (§13 row 17).** `applyRole()`'s
  docblock claimed it "reconciles its permission grants"; it never granted anything, and
  `applyGroup()` had the identical gap for group role bindings — a `apply()` of a role
  with grants reported success and granted nothing. A resource declared with a
  `parentKey` was created flat: `CreateResourceRequest.parentId` has always existed and
  was never sent. Both fixed; see Added above.

- **`scripts/gen_management.py` — two generator defects the contract 1.51 re-vendor
  exposed**, the same pair independently found and fixed in `ilpanich/axiam-rust-sdk`
  (C-1): `SubjectAltName` is an externally tagged `oneOf`
  (`{"dns": "…"}` / `{"ip": "…"}`); the generator recognised neither that shape nor any
  `oneOf` without a discriminant field, and fell through to an empty class serializing
  as `[]` (PHP's `json_encode([])`, not `{}`) — a request the server refuses. A required
  `inherit` on the three role-side assignment listings, decoded with `ModelDecode::need()`,
  would throw against a server older than contract 1.51 that never sends the field,
  failing the whole listing — including the one `roles.list_groups`/`list_users`/
  `list_service_accounts` a manifest reads to plan every binding. Both fixed in the
  generator (`externally_tagged()`/`emit_external_union()`;
  `DEFAULT_TRUE_WHEN_ABSENT`), pinned in `tests/Management/Contract151ModelsTest.php`.
  `CertificateType` already decoded an unrecognised value (including the new `"Server"`)
  without failing the response — no change needed, only a test.

## [1.0.0-beta16] - 2026-09-19

### Added

- MCP resource-server helpers (CONTRACT.md §28, contract 1.48)

- MCP resource-server helpers — RFC 9728 protected-resource metadata and the RFC 6750
  bearer challenge (CONTRACT.md §28, contract 1.48)

- **The resource-server half of the Model Context Protocol authorization handshake, on
  both framework surfaces.** `Axiam\Sdk\Mcp\Mcp::protectedResourceMetadata()` and
  `::bearerChallenge()`, plus a `resourceMetadataUrl` constructor option on
  `Laravel\AxiamMiddleware`, `Symfony\AxiamAuthSubscriber` and `AccessEnforcer`. AXIAM
  is the authorization server and implements none of this; your MCP server is the
  resource server, and this is its side.

  ```php
  $metadata = Mcp::protectedResourceMetadata(
      resource: 'https://mcp.example.com/mcp',
      authorizationServers: ['https://axiam.example.com'],
      scopesSupported: ['mcp:read', 'mcp:tools'],
  );
  $client = new AxiamClient($baseUrl, $tenant, expectedAudience: $metadata->document['resource']);
  $middleware = new AxiamMiddleware($client, $tenant, $metadata->metadataUrl);
  Route::serveProtectedResourceMetadata($metadata, $middleware);
  ```

  Laravel gets a `Route::serveProtectedResourceMetadata()` macro (registered by
  `AxiamServiceProvider`, alongside the existing `Route::axiamOidcLogin()` one); Symfony
  gets an invokable `Symfony\ProtectedResourceMetadataController` the integrator wires
  into their own routing configuration, since Symfony's routing table is declarative
  config this SDK cannot hook at runtime.

  **No operation performs network I/O**, so §16's retry policy and §9's single-flight
  refresh do not apply and nothing here touches the shared `AxiamClient`'s own session —
  both are pure local computation, like `UmaChallenge::parse()`. The *client* half of
  the handshake is deliberately not shipped: a helper that read a 401 and acted on it
  would send a credential to whatever host the 401 asked it to.

- **Opt-in and off by default, and the regression proves it.** With
  `resourceMetadataUrl` unset every guard behaves byte-for-byte as it did before: no
  `WWW-Authenticate` on any response, no status changed, no body changed, and no path
  exempted. The two framework test files (`tests/Mcp/McpLaravelTest.php`,
  `tests/Mcp/McpSymfonyTest.php`) assert the header's *absence* explicitly rather than
  asserting the status, because a 401 that grew a header is still a 401 — an
  implementation that emitted a bare challenge unconditionally would pass every other
  test in the suite.

- **`expectedAudience` is now mandatory when `resourceMetadataUrl` is set**, and
  `AxiamMiddleware`, `AxiamAuthSubscriber` and `AccessEnforcer` each refuse the
  configuration at construction, naming both options (a `ValidationError`, §2's
  taxonomy — §28 adds no new type). A resource server that publishes "tokens for me
  carry this `aud`" and then does not check `aud` has published a claim it does not
  honour, and a token minted for a *different* MCP server opens it. That is the
  confusion RFC 8707 exists to prevent, so it is impossible to configure rather than
  merely discouraged. `AxiamClient` gains a public `expectedAudience()` accessor so a
  guard can read back its own §10.1 row 6 configuration without a second,
  independently-set option for §28.

  This changes nothing for an existing deployment: `resourceMetadataUrl` is new, so
  there is no configuration that was valid before and is refused now.

- **The document's path is derived from the resource, not chosen**, and exactly one
  route is registered per call — RFC 9728 §3.1's insertion between the authority and
  the path, with a trailing slash carried through rather than trimmed. It is served
  `200 application/json` with `Cache-Control: public, max-age=3600` and
  `Access-Control-Allow-Origin: *` (never `Access-Control-Allow-Credentials`), and
  **without authentication**: `AxiamMiddleware`/`AxiamAuthSubscriber` exempt that one
  path themselves, from the `resourceMetadataUrl` they were configured with, checked
  before either guard ever tries to extract a credential.

- **One class of 403 gains a header, and only one.** `AccessEnforcer::enforceAccess()`
  now reaches the server through the transport-agnostic `AxiamClient::checkAccessDecision()`
  / `AuthzDispatcher::checkAccessDecision()` (REST and gRPC both — new, additive; the
  existing bare-`bool` `checkAccess()` is unchanged and delegates to it) so a `#[RequireAccess]`
  call that named a `scope` whose decision came back `allowed: false` with
  `reasonCode: "no_grant"` now carries `error="insufficient_scope", scope="…"`. The
  JSON body does not change — it is still `authorization_denied`, and
  `insufficient_scope` appears only in the header. A `denied_by_rule` decision, an
  absent or unrecognised `reasonCode`, a denial with no `scope` argument, a
  `require_role` failure and a CSRF refusal all carry no header: `no_grant` means *ask
  for more*, which is what a challenge invites a client to do, and `denied_by_rule`
  means *an administrator has already decided*. Where a route also carries a §20.3 UMA
  challenge (a `UmaChallenger` configured on the same `AccessEnforcer`), the UMA
  challenge wins and exactly one `WWW-Authenticate` value is ever emitted.

- **The challenge never says why.** Expired, not yet valid, wrong tenant, wrong
  audience, bad signature, a revoked `sid` — all of them are `invalid_token`,
  indistinguishably, and the guard adds no `error_description`, no header and no body
  field that tells them apart. A request that carried *no* credential gets a challenge
  with no `error` parameter at all, which is a different answer and deliberately so.
  `Mcp::bearerChallenge()` **refuses rather than escapes** any value outside RFC 6750's
  character sets, raising `ValidationError` rather than emitting `\"`.

- **Validation refuses; it never repairs.** `Mcp::protectedResourceMetadata()` applies
  every §28.2 rule at construction — absolute URI with no query and no fragment,
  `https` except on `127.0.0.1`/`[::1]`/`localhost`, at least one issuer with no
  duplicates and no query, `NQCHAR` scope tokens in the caller's order,
  `bearer_methods_supported` exactly `["header"]` — and raises `ValidationError` (§2's
  taxonomy, unchanged; §28 adds no error type) rather than normalising, trimming,
  lowercasing or re-encoding anything to make it pass. An empty `scopesSupported` and
  an absent `resourceDocumentation` omit their members rather than emitting `null`.
  Nothing in the document may come from a request, and there is no option that would
  let it.

- **gRPC and AMQP: no transport-appropriate equivalent exists on this SDK.**
  CONTRACT.md §28.5 rule 8 makes exposing `bearerChallenge` to a gRPC resource-server
  guard's error mapping optional and forbids an AMQP equivalent outright. This SDK's
  `Axiam\Sdk\Grpc` namespace is a **client** for AXIAM's own gRPC services
  (`checkAccess`, `getUserInfo`) — the opposite direction from §28 — and
  `Axiam\Sdk\Amqp` is §8's HMAC-signed message bus, not a bearer-token guard. Neither
  is the §10 guard §28 extends, so neither gains this option; §10 (and therefore all of
  §28) stays a REST-only surface on this SDK. Recorded here rather than silently
  skipped.

- **Tests**: §28.9's five required tests, on the fixture §28.9 names, across three
  files — `tests/Mcp/McpContractTest.php` for the two framework-independent ones
  (document shape and validation negatives; challenge quoting and its refusals) and
  `tests/Mcp/McpLaravelTest.php` / `tests/Mcp/McpSymfonyTest.php` for the three that
  need a guard (401 with the challenge; 403 `insufficient_scope`; a token whose `aud`
  is not the resource), plus the off-by-default regression on each surface — driving
  a real `AxiamClient` through its `transportHandler` test seam, never a mock (the
  class is `final`), the same idiom every other REST test in this suite uses.

- **Contract**: the vendored `CONTRACT.md`, `openapi.json` and `management-registry.json`
  are re-synced to **1.48** (§28, plus the RFC 8707 `openapi.json` additions T21.3
  recorded unnumbered for this task to fold in, and 1.47's `token_endpoint_auth_methods_supported`
  `none` addition — documentation/spec only, no SDK operation changes). `proto/` is
  byte-identical to the previously-vendored copy. The re-synced `openapi.json`/
  `management-registry.json` moved the §27 management surface's own digest, so
  `scripts/gen_management.py` was re-run and its generated output re-committed
  alongside — mechanical, no §27 behaviour change. **Superseded in part by F-28-01
  below**: re-syncing from a phase branch is what contract 1.49 now forbids, and
  the artefacts are re-synced once, from `main`, after Phase 21 lands.

### Changed

- F-28-01 — re-sync CONTRACT.md 1.49, openapi.json and management-registry.json from axiam main @ e4c62180e

- Record F-28-01 and the D-02 adjudication (T21.9 T9d)

- **F-28-01 — the vendored contract artefacts are re-synced from a merged `main`
  (contract 1.49).** This repository's copies had been re-synced above from a
  **phase branch**, which kept moving afterwards (CONTRACT.md §28.11 row R-1). They
  are now re-synced once, from **`ilpanich/axiam` `main` @ `e4c62180e`**, as contract
  1.49 requires:

  | Artefact | Blob |
  |---|---|
  | `CONTRACT.md` (1.49) | `2493348c3285` |
  | `openapi.json` | `b75e30eaa359` |
  | `management-registry.json` | `4619f441aac0` |

  `proto/` already matched and is unchanged. The §27 management surface is
  regenerated in the same commit (`python3 scripts/gen_management.py`). The operation
  set does not move — it was already 162 operations across 24 namespaces, including
  `oauth2Clients` `createRegistrationToken` / `listRegistrationTokens`, from the
  phase-branch registry — and only the registry's recorded spec digest changes. What
  does change is one model: the new `CimdPolicy` (T21.5 client ID metadata
  documents), carried as an optional `cimd` member on `OidcPolicy`,
  `SetOrgSettings` and `TenantSettingsOverride`, with `fromArray`/`toArray`
  round-tripping it. `ManagementSurfaceGeneratedTest` and
  `ManagementModelRoundTripGeneratedTest` are regenerated with it. No hand-written
  operation changes signature or behaviour. The README's conformance statement now
  names contract 1.49.

- **Two findings the T21.9 T9d review recorded about this port rather than
  changed.** **D-02 stands
  as conformant.** `AccessEnforcer::enforceAuth()` receives the identity a §10 guard
  already resolved, never the request, so it cannot tell "no credential" from
  "credential presented and rejected" and its standalone `#[RequireAuth]` 401 carries
  no challenge. Contract 1.49's §28.5 rule 4 now provides for exactly this shape — the
  C++ port's bare `require_auth()` is in the same position — and notes that the 401 is
  reachable only where the §10 guard did not run, whose own 401 already carried the
  correct vector. **And `checkAccessDecision()` was verified not to add a second
  network call**: the bare-bool `checkAccess()` delegates to it, `AccessEnforcer`
  calls it once, and a caller using only `checkAccess()` sees exactly the behaviour it
  saw before (CONTRACT.md §28.11 row R-11).

- **Breaking, security fix — `CreateRegistrationTokenResponse::$initialAccessToken` is now
  `\Axiam\Sdk\Core\Sensitive`, was `string`** (CONTRACT.md §27.5, contract 1.50,
  ilpanich/axiam#480). The RFC 7591 §1.2 initial access token is returned exactly once and
  is never retrievable afterwards, but it was missing from the registry's curated
  `(schema, field)` table, so the generator emitted a bare `string` and the credential
  appeared in every `print_r()`, `var_dump()` and log rendering of the model — the leak
  §7 rule 1 and §27.5 exist to prevent. `management-registry.json` now publishes
  `sensitive_response_fields: ["initial_access_token"]` for
  `oauth2_clients.create_registration_token`, making it the **fifteenth** §27.5 operation,
  and `scripts/gen_management.py` wraps the property like the fourteen before it.

  Migration — read the token through the explicit reveal, at the one point of use:

  ```php
  $created = $client->management()->oauth2Clients()->createRegistrationToken($body);
  // before: $token = $created->initialAccessToken;
  $token = $created->initialAccessToken->reveal();
  ```

  There is deliberately **no** plain-`string` accessor kept alongside it: the plain
  accessor is precisely the leak (contract 1.50). `Sensitive` implements
  `JsonSerializable`, so the wire form is unchanged — `openapi.json` and `proto/` did not
  move, only the SDK-side type.

  Re-synced from a merged `ilpanich/axiam` `main` @ `da94e1d04`: `CONTRACT.md`
  (blob `28c163e32d25`) and `management-registry.json` (blob `aab87fd79910`).

### Fixed

- 1.50 — initialAccessToken becomes Sensitive (#480)

## [1.0.0-beta15] - 2026-09-15

### Added

- Re-vendored `CONTRACT.md` (1.45), `openapi.json`, `management-registry.json`
  and `proto/` from `axiam` at `3d5b279`, and regenerated the §27 management
  surface (`scripts/gen_management.py`): **159 → 160 operations**.

- **`certificates.signCsr(SignCertificateCsrRequest)` — `POST
  /api/v1/certificates/sign-csr` (contract 1.45).** Issue a leaf certificate
  from a caller-supplied CSR instead of a server-generated key pair: the
  request carries `csrPem`, `issuerCaId`, `certType`, `validityDays` and
  optional `metadata`, and answers the **existing** `Certificate` model — never
  `GeneratedCertificate` — because a CSR the caller supplied the key of has no
  private key for AXIAM to return. `subject` and `keyAlgorithm` are read off
  the CSR server-side rather than accepted from the request, so the stored row
  and the issued certificate cannot disagree. A model round-trip test asserts
  `Certificate` carries no private-key field and no `Sensitive`-wrapped field
  at all, reflectively rather than by reading a docblock.

- **`webauthnSetupRegisterStart(Sensitive|string $setupToken)` /
  `webauthnSetupRegisterFinish($setupToken, $stateToken, $credentialName,
  $response)` — the WebAuthn twin of `mfaSetupEnroll`/`mfaSetupConfirm`
  (CONTRACT.md §24.1, §24.7, §25.1, §25.2, contract 1.45).** Enrol a passkey or
  security key as the **first** factor of a forced login enrolment — reached
  from `LoginResult::$mfaSetupRequired` exactly where the TOTP pair is — so a
  user of an MFA-enforcing tenant is no longer required to own a TOTP app to
  get in.

  This pair takes **no session, and none is ever attached**: unlike
  `webauthnRegisterStart`/`Finish`, calling it never requires being signed in,
  and — new machinery this adds to `AxiamClient` — the wire call carries
  neither the session's `Authorization` header nor any cookie the shared jar
  already holds, even when the client happens to be authenticated as someone
  else at the time. `Axiam\Sdk\Rest\AuthMiddleware` gained a
  `NO_SESSION_CREDENTIALS_OPTION` per-request flag for exactly this, and the
  request itself rides a scratch `CookieJar` so a `Set-Cookie` on `finish`'s
  `200` is still captured and merged into the client's own jar afterward —
  suppressing what is sent without losing what is meant to be adopted.

  `webauthnSetupRegisterFinish` adopts credentials **exactly as
  `mfaSetupConfirm` does** (§25.2 rule 2): both are the completion of the
  login `login()` interrupted, both answer `LoginSuccessResponse`, and both
  now share one `loginResultFromSuccessBody()` implementation (factored out of
  `handleLoginResponse`'s own `200` branch) rather than two call sites
  agreeing to parse the body the same way. A `403` surfaces the tenant's
  attestation-policy message verbatim (§24.4 rule 1, shared with
  `webauthnRegisterFinish` via a new `attestationPolicyError()` helper); a
  `503` from `start` is never retried, as this SDK's plain transport never
  retries anything on that path. `setup_token` is wrapped `Sensitive` (§25.3),
  `state_token` as everywhere else in §24 (§24.5).

  Nine new tests in `tests/WebauthnTest.php` cover the adoption, the
  no-session-credential guarantee (asserted on the transport, with a session
  deliberately configured first), the wire shape, the three status rows, and
  that `setup_token` is never parsed or rendered.

### Changed

- Re-vendor CONTRACT.md at 1.46

- F-1 (PHP): certificates.signCsr and the WebAuthn setup/register pair (contract 1.45) (#68)

## [1.0.0-beta14] - 2026-09-13

### Added

- **CONTRACT.md §10.4 — an optional session-revocation feed poller (contract
  1.44).** The new `Axiam\Sdk\Auth\RevocationFeed`, passed as the sixth
  constructor argument to `JwksVerifier`, plus `RevocationFeed::entryFor()` and
  the three bounds the contract names (`MIN_POLL_INTERVAL_SECONDS`,
  `DEFAULT_POLL_INTERVAL_SECONDS`, `MAX_ENTRIES`).

  Local verification proves a token was issued and has not expired, never that
  the session behind it still exists — so a logout or a role removal does not
  reach a token already in a caller's hands until it expires, up to fifteen
  minutes. A deployment that publishes `GET /oauth2/revocations` lets a guard
  close that to **one poll interval**, for one cacheable fetch per interval
  rather than the round trip per request gRPC introspection costs.

  Nothing changes unless you pass one: the parameter is optional and defaults to
  `null`, so every existing call site keeps working unchanged. It never fetches
  on the request path after the first call — `verify()` reads a cached set. And
  it never fails closed: an unreachable feed, a non-`200`, an unparseable body
  or an unknown `alg` all behave exactly as no feed at all, and specifically
  **not** as an empty list, which would assert that nothing has been revoked. A
  token with no `sid` is never matched against it, and there is no fallback to
  `jti`.

- Two tests pinning CONTRACT.md §16 against the server's new answer for a
  contended write — `503` with `Retry-After: 1` (AXIAM T-262). No behaviour
  changed: §16.3 already retried an eligible read and already honoured
  `Retry-After` as a floor, and a non-idempotent call already made exactly one
  attempt. Both halves are asserted through the public surface with a wire
  count, because a retry policy nobody exercises that way is the failure §16.7
  exists for.

### Changed

- Re-vendor CONTRACT.md: fill this SDK's §10.4.1 and §21.10 rows

- R-6, R-8, R-4: §10.4 revocation feed, §21.3.1 vector C, T-262 retry tests

- **A malformed `mtls_endpoint_aliases` entry now throws instead of falling back
  to the top-level endpoint** (CONTRACT.md §21.3.1 vector C, contract 1.43).

  Falling back looks like the safe answer and is the dangerous one: the caller
  asked to authenticate with a certificate, the operator published something
  unusable, and sending the certificate to the front-channel host authenticates
  nothing while appearing to work.

  "Malformed" means not an absolute URL, or a scheme weaker than the top-level
  endpoint the alias replaces — comparing like with like, so an `http` alias for
  an `http` endpoint (a development deployment) is still accepted.

  The refusal is an `AuthError`, not a `NetworkError`: nothing failed in
  transport, and §16.3 retries `NetworkError` and only `NetworkError`, so the
  other choice would have retried a permanent misconfiguration three times and
  reported it as a transient one. It is per endpoint, so one malformed alias
  leaves every other endpoint working, and a client built without `clientCert`
  never reads the member at all.

- Re-vendored `CONTRACT.md` (1.44), `openapi.json` and
  `management-registry.json` from `axiam`, and regenerated the §27 management
  surface. The surface gains `SessionResponse`, whose T-254 replay fields were
  published server-side at 1.0.0-beta13.

## [1.0.0-beta13] - 2026-09-12

### Added

- Accept a caller-supplied dpop_jkt on pushed authorization requests

- Model the two contract 1.42 discovery capability lists

- Prefer RFC 8705 §5 mtls_endpoint_aliases on mTLS calls

- **`dpop_jkt` on pushed authorization requests (SDK contract 1.42, RFC 9449
  §10.1).** `oidcPar()` takes an optional sixth argument, `dpopJkt` — the
  base64url JWK SHA-256 thumbprint of the key the client will prove possession
  of at the token endpoint — and emits it in the `POST /oauth2/par` form. It
  binds the authorization code to that key at issue time rather than only at
  redemption, closing the window in which a stolen code can be redeemed by a
  different key. Omitted from the form entirely when null or empty (§12.1
  forbids transmitting an absent optional field as an empty value).

  The **caller** computes the thumbprint: CONTRACT.md §21.9 records this SDK as
  verifying DPoP proofs but not generating them, so there is no client key here
  to derive one from, and no proof generator was added. The value is forwarded
  verbatim.

  `request_uri`, also added to the server's `PushedAuthorizationRequest` schema
  in 1.42, is deliberately **not** exposed. RFC 9126 §2.1 makes it the one
  authorization parameter a client MUST NOT push; upstream models it so the
  server can refuse it, and a client able to send it is a client able to chain
  one pushed request into another — the attack §26.2 rule 2 exists to prevent.

- **`code_challenge_methods_supported` and
  `token_endpoint_auth_signing_alg_values_supported` on `OidcConfiguration`
  (SDK contract 1.42, CONTRACT.md §21.5).** Both are read from the discovery
  document as `list<string>|null`, **optional even though `openapi.json` marks
  them required**. RFC 8414 §2 defines no default for either, so an absent
  `code_challenge_methods_supported` is not an implied `["S256"]`; modelling
  them required would reject every document from a non-AXIAM OP that this SDK
  parses today. `null` means absent, and an advertised `[]` survives as `[]`.

  The other three members contract 1.41 added to `OidcDiscoveryDocument` —
  `acr_values_supported`, `claims_parameter_supported`,
  `request_parameter_supported` — are **not** modelled, because this type
  models a curated subset and never modelled them (it does not model
  `dpop_signing_alg_values_supported` either). Widening it further would be new
  surface, not a re-sync.

  The new constructor parameters are optional with defaults, so existing
  `new OidcConfiguration(...)` call sites still work.

- **RFC 8705 §5 `mtls_endpoint_aliases` (SDK contract 1.40, CONTRACT.md §21.3
  rule 2).** `OidcConfiguration` gains an optional `mtls_endpoint_aliases`
  property (the new `Axiam\Sdk\Oidc\MtlsEndpointAliases`), and the §12 helpers
  now prefer an alias over the top-level entry of the same name on any call made
  over mutual TLS — that is, from a client built with `clientCert`. Six
  operations reach the token endpoint (`oidcExchange`, `oidcRefresh`,
  `loginClientCredentials`, `devicePoll`, `tokenExchange`,
  `umaExchangeTicket`), plus `introspect`, `revoke`, `deviceAuthorize` and
  `oidcPar`.

  A null property means "this deployment terminates mutual TLS on the issuer's
  own host", never "mTLS is unsupported": a client without it keeps using the
  conventional endpoints instead of failing. Every property of
  `MtlsEndpointAliases` is nullable, so an endpoint a partial object does not
  name falls back rather than failing the whole document. No alias is
  synthesised for `authorization_endpoint`, `end_session_endpoint` or
  `jwks_uri`, which are front-channel or public. `issuer` does not move, and
  §12.4 rule 3 still compares a token's `iss` against it by exact string —
  including for a token minted at an alias endpoint.

  The new constructor parameter is optional with a default, so existing
  `new OidcConfiguration(...)` call sites still work.

### Changed

- Record the 1.40 -> 1.42 re-sync in CHANGELOG and README

- Pin replace-don't-append for a discovery-advertised tenant_id

- Re-vendor CONTRACT/openapi/registry at SDK contract 1.42

- Re-vendored `CONTRACT.md`, `openapi.json` and `management-registry.json` from
  `ilpanich/axiam` at **SDK contract 1.42** — two revisions, 1.40 → 1.42, since
  the previously vendored copy was 1.40 and not 1.41. The registry goes from
  **155 to 158 operations across 24 namespaces**: three additions in the
  `privacy` namespace (`privacy.listConsents`, `privacy.grantScopeConsent`,
  `privacy.withdrawScopeConsent`, behind `/api/v1/account/consents` and
  `/api/v1/account/consents/oidc-scopes[/{client_id}]`). `openapi.json` also
  gained the `MtlsEndpointAliases` schema (1.40) and, in 1.41–1.42, the
  `Address`, `AuthnRequestParamsMode`, `ConsentView`, `GrantScopeConsent`,
  `OidcPolicy` and `UserInfoPostForm` schemas.

  Everything in the §27 surface is regenerated by `scripts/gen_management.py`,
  not hand-written: four new generated models (`AuthnRequestParamsMode`,
  `ConsentView`, `GrantScopeConsent`, `OidcPolicy`), `authnRequestParams` and
  `browserSso` on the three OAuth2-client models, `oidc` on `SecuritySettings`,
  `defaultLocale` and `sensitiveScopesEnabled` on `SetOrgSettings` and
  `TenantSettingsOverride`, and `client_secret_basic` on the
  `ClientAuthMethod` enum.

  `proto/` is byte-identical upstream, so the committed gRPC stubs are
  untouched. Additive throughout: no public API was removed or renamed.

- `scripts/gen_management.py` now interpolates the operation and namespace
  counts from the vendored registry into the doc-comments it emits, instead of
  carrying them as literals. Six prose strings still said "147" three
  re-vendors after the registry had reached 155 — a comment nobody could see
  was wrong without counting by hand. The corresponding sentence in the
  hand-written `ManagementSemanticsTest` no longer names a number at all.

- `README.md`: the stated contract version (1.38 → 1.42) and the management
  operation count (147 → 158), both stale.

### Fixed

- **Regression tests for contract 1.42's tenant-scoped discovery endpoints.**
  As of 1.42 the server appends `?tenant_id=<uuid>` to the token, revocation,
  introspection, device-authorization, PAR and end-session URLs it advertises
  in discovery, whenever the discovery request named a tenant or the deployment
  sets `oauth2_default_tenant_id`. An SDK that *appends* its own would now put
  `?tenant_id=A&tenant_id=B` on the wire.

  **This SDK was already correct and no behaviour changed**:
  `OidcClient::withQuery()` merges the resolved `tenant_id` over the endpoint's
  existing query rather than appending, so exactly one survives and the
  resolved value wins. Three tests now pin that down — on the token, revocation
  and PAR endpoints — asserting one `tenant_id`, the resolved value, and that
  an unrelated query parameter, the port and the path all survive (RFC 6749
  §3.1/§3.2 require a client to retain the endpoint's own query component).

## [1.0.0-beta12] - 2026-09-06

### Changed

- Make the §27 drift-check gate the release

## [1.0.0-beta11] - 2026-09-04

### Fixed

- Regenerate the §27 surface for the WebAuthn policy fields

- Regenerated the §27 management surface from the vendored
  `management-registry.json` / `openapi.json`. The v1.0.0-beta09 re-vendor
  carried the WebAuthn user-verification policy — `SecuritySettings.webauthn`,
  and `webauthn_user_verification` on the organization and tenant settings
  requests — without regenerating the code emitted from it. This SDK's
  drift-check runs on pull requests only, so beta09 and beta10 both published a
  surface in which the new policy could be neither read nor set.
  `python3 scripts/gen_management.py --check` is green again.

## [1.0.0-beta10] - 2026-09-03

### Changed

- Maintenance release — no notable changes since v1.0.0-beta09.

## [1.0.0-beta09] - 2026-09-02

### Changed

- Maintenance release — no notable changes since v1.0.0-beta08.

## [1.0.0-beta08] - 2026-09-02

### Added

- Contract 1.38 — the four public "Sign in with X" operations (#62)

- **Contract 1.38: the four public "Sign in with X" operations.** `ssoProviders`,
  `ssoStartOauth2`, `ssoCompleteOauth2` and `ssoCompleteHandoff`, under the exact
  CONTRACT.md §12.2 PHP names, on `OidcClient` with the delegating methods on
  `AxiamClient` the other nine already have. New classes `FederationProvider`
  (carrying the three `PROTOCOL_*` discriminants) and `FederationProviderList`
  (carrying the `HANDOFF_QUERY_PARAM`/`HANDOFF_CODE_TTL_SECONDS` constants),
  matching the §12.1 SDK-type table. Upstream: ilpanich/axiam#398.

  Four rules an implementation can satisfy by accident and break by accident, so
  each is stated in the code and carries a test:

  - **An empty provider list is a success** (§12.1 note 9). An unknown
    organization, a known one with nothing configured, and a request naming no
    workspace at all all answer `200 []`. `ssoProviders()` returns each as an
    ordinary result and never throws: the endpoint is shaped so it cannot
    enumerate organization or tenant slugs, and distinguishing the three
    client-side would rebuild that oracle. It is therefore also the one federation
    operation that does *not* throw when no workspace resolves — a client-side
    refusal would be that same two-valued answer by another route.
  - **`protocol` selects the start operation** (§12.1 note 10), never
    `providerKind`. It is the wire string rather than an enum, so a value added
    server-side cannot become a parse failure for the whole list.
  - **PKCE on the OAuth2 variant is server-side** (§12.1 note 11). Nothing here
    computes a verifier or sends a challenge, and a test asserts the absence rather
    than leaving it to be noticed.
  - **A `400` from a start call is a configuration refusal** (§12.1 rule 12a, new
    at 1.38): the deployment rejecting a `$redirectUri` whose origin is neither its
    own issuer nor listed in `AXIAM__AUTH__SSO_SPA_ORIGINS`. It surfaces as
    `NetworkError` — §2's `400` row, the taxonomy's configuration/programming-error
    member, distinct from the `AuthError` a `401` gets — and is not retried.

  A handoff `401` is terminal: `ssoCompleteHandoff()` makes exactly one wire call,
  so it cannot become a retry by accident.

- `OidcLoginProvidersTest` — 20 tests. The wire-shape half reads the vendored
  `openapi.json` and asserts method, path, media type, the success schema names,
  that the `ssoProviders` identifiers are declared `in: query`, and that neither
  OAuth2 start schema carries PKCE material; the SDK half asserts what actually
  reaches the wire matches. The rule half covers note 9 (all three empty-list
  cases, plus that a workspace-less request is still *sent*), note 10 (all three
  dispatch branches, with a `Saml` fixture whose `provider_kind` is `google` so a
  kind-based dispatch fails the recorded-path assertion), note 12 (terminal `401`,
  exactly one request) and rule 12a (a `400` from either start operation is
  `NetworkError` and unretried; a `401` from the same endpoint stays `AuthError`).

### Changed

- Re-vendored `CONTRACT.md` (1.29 → 1.38), `openapi.json` and
  `management-registry.json` byte-for-byte from `ilpanich/axiam@1c457f6`.
  `proto/axiam/v1/` and `opaque-test-vectors.json` did not change upstream and were
  re-verified as already identical rather than re-copied.
  `management-registry.json` moves only its `spec_digest`: `operation_count` stays
  at 155, so no §27 operation was added or removed.

- Regenerated the §27 management surface (`python3 scripts/gen_management.py`), as
  §27.8 requires whenever the vendored artifacts move. `openapi.json` gains ten
  fields on the federation-config schemas (`allow_tenant_inheritance`,
  `allowed_issuer_tenants`, the two Apple identifiers, the OAuth2 endpoint trio,
  `provider_kind`/`provider_slug`, `button_icon`, `scopes`/`effective_scopes`,
  `has_bundled_mark`, `mints_client_secret`, `pkce_required`), so the three
  federation-config models and the three generated tests move with it. The
  operation surface itself is unchanged.

- The README's contract-conformance statement names **contract 1.38** and §12's
  thirteen operations, and its §12 section documents the four new ones, the
  protocol-dispatch table, the faithful `FederationProvider` shape, and the
  rule-12a taxonomy mapping.

## [1.0.0-beta07] - 2026-08-30

### Changed

- Re-vendor AXIAM contract 1.36

- **Documented contract 1.36, which this SDK already vendors.** `CONTRACT.md`,
  `openapi.json` and `management-registry.json` were re-vendored from the
  `sdks/` sources in [`ilpanich/axiam`](https://github.com/ilpanich/axiam)
  (ilpanich/axiam#396) as part of the 1.0.0-beta06 release, whose note recorded
  only "no notable changes". That understated it — the contract moved in that
  release — and v1.0.0-beta06 is tagged, so the correction is recorded here
  rather than by editing a released section. No SDK code changed with the
  artifacts; the three entries below are why not.

- **§5.2.2 rule 4 is new, and is an errata rather than a wire change.** The
  server now scopes every *self-service* endpoint to `principal_tenant_id`
  rather than to the acting tenant — `GET`/`PUT /users/{own id}`, that user's
  `mfa-methods`, `POST /users/{own id}/reset-mfa`, `POST /auth/mfa/enroll` and
  `/confirm`, `POST /auth/webauthn/register/start` and `/finish`, `POST
  /users/me/resend-verification`, the §25 account export and erasure for the
  caller's own id, and `GET /oauth2/userinfo`. Each of those answered `404` for
  an organization-level caller that had switched to another tenant and now
  succeeds. No request or response field is added, so nothing here is a wire
  change.

  The rule also forbids the obvious workaround: an SDK MUST NOT clear or rewrite
  the acting-tenant header for those calls, because that header is what makes
  the **administrative** form of the same endpoints reach the tenant the caller
  asked for — stripping it would break reading another tenant's user in order to
  fix reading your own. This SDK was audited for such a workaround and has none:
  `X-Tenant-ID` is set in one place, `Rest/AuthMiddleware.php`, unconditionally
  for every outgoing request; no endpoint is special-cased.

- **Issue #395 is settled: the acting-tenant header is `X-Axiam-Tenant`**, and
  §5.2, §5.2.2 and §5.2.3 now name it. The note under 1.0.0-beta05 below
  recorded the contract and the server disagreeing on it; they no longer do, and
  the name this SDK documents was already the server's. §5 rule 2's
  *unconditional* `X-Tenant-ID` is deliberately **not** renamed, and the
  contract now carries a note saying why it must not be: it names the client's
  *constructor* tenant, so folding it into `X-Axiam-Tenant` would override the
  acting tenant on every request an organization-level principal made after a
  switch. Every existing §5 rule 2 send is left exactly as it was.

- **`openapi.json` gained `/api/v1/auth/me`, `/api/v1/auth/password/change` and
  `/api/v1/admin/bootstrap`.** All three were always served and always normative
  in `CONTRACT.md`; they were missing from the generated document only because
  their handlers were never listed in its `paths(…)`. `management-registry.json`
  keeps `operation_count` at **155** — bootstrap is excluded on the §27.0
  boundary — so §27 code generation is unaffected and the generated surface is
  unchanged.

## [1.0.0-beta06] - 2026-08-30

### Changed

- Maintenance release — no notable changes since v1.0.0-beta05.

## [1.0.0-beta05] - 2026-08-30

### Added

- Contract 1.35 (carrying 1.34) — principal tenant, tenant_scope, service-account RBAC

- **Contract 1.35, which carries contract 1.34 with it.** Nothing had been fanned
  out since 1.33, so this re-vendors `CONTRACT.md`, `openapi.json` and
  `management-registry.json` across both revisions. The registry still holds 155
  operations across 24 namespaces — 1.35 changed only its `spec_digest` — so the
  eight §27 operations below arrived with 1.34 and are new here regardless.

- **§27: service accounts as RBAC principals** (contract 1.34) — eight generated
  operations across `RolesApi`, `GroupsApi` and `ServiceAccountsApi`, with the
  `RoleServiceAccountAssignment` and `AddServiceAccountMemberRequest` models they
  need. `RolesApi::unassignFromServiceAccount()` takes the same optional
  `$resourceId` query parameter as the user and group unassign calls: omitting it
  removes the *global* grant specifically, not every grant of that role.

- **§5.2.2: the acting tenant and the principal tenant are different things**
  (contract 1.34). `LoginResult` gains `actingTenantId`, `principalTenantId`,
  `principalTenantSlug`, `orgId` and (from §5.2.3) `reachableTenantIds`. Absent
  means *equal* — a server older than 1.34 omits them and cannot switch the acting
  tenant either, so `principalTenantId` falls back to `actingTenantId` rather than
  to `null`. Read `orgId` from the session instead of resolving a slug through
  `GET /api/v1/organizations`, which is `super-admin`-only and returns only the
  caller's own organization.

  The pre-existing `LoginResult::$tenantId` is left alone: it carries the session's
  tenant *slug*, not an id, and renaming or repurposing it would be a breaking
  change unrelated to this contract.

- **§5.2.3: tenant-scoped role assignments** (contract 1.35). `tenantScope` appears
  on the three assignment request bodies and on the assignment objects the read
  paths return. Omitted means unrestricted, which is what every assignment written
  before the field existed already meant.

  `reachableTenantIds` pairs with it on the login result: a narrowed
  organization-level principal still reports `organizationLevel = true`, so an
  application gating a tenant switcher on that flag alone offers tenants the server
  refuses at the header.

### Fixed

- Construct the refusal through NetworkError::fromMessage()

- **A registration record for your own password was sealed against the wrong
  tenant.** CONTRACT.md §5.2.2 rule 2: the caller's credentials live in the tenant
  the *account* lives in, not whichever tenant the client is currently pointed at,
  and a record sealed against the acting tenant is refused with "the OPAQUE session
  was issued for a different tenant".

  `AxiamClient::opaqueEnrollment()` had one behaviour for a method documented for
  three callers — user creation, change-password and reset completion — and only the
  first of those wants the acting tenant. It keeps that behaviour; the new
  `AxiamClient::opaqueEnrollmentForSelf()` seals against the principal tenant
  captured at login (dropping the `tenant_slug` that would otherwise out-vote the id
  server-side) and is what a self-service password change must call. It throws a
  `NetworkError` before any login has completed, because there is nothing to seal
  against then and guessing the acting tenant is the bug itself.

  The two collapse to the same request for every ordinary principal, so this only
  bit an organization-level account that had switched tenant.

- **`tenant_scope: []` no longer reaches the wire** (§5.2.3 rule 1, refused with
  `400`). PHP's generated `toArray()` guards optional fields with `!== null`, which
  an empty array passes — and an empty array is exactly what building the field from
  a filtered collection produces for "no tenants named". `scripts/gen_management.py`
  now emits `!== null && !== []` for `tenantScope` specifically.

  The allowlist is one field wide on purpose: elsewhere `[]` is meaningful — a
  replacement body clearing a list — and `Contract135Test` pins that
  `UpdateWebhookRequest(events: [])` still sends `"events": []`.

### Note on `X-Tenant-ID` vs `X-Axiam-Tenant`

CONTRACT.md §5.2.2 and §5.2.3 name the acting-tenant header `X-Tenant-ID`, but the
AXIAM server reads **`X-Axiam-Tenant`** (`ACTIVE_TENANT_HEADER` in
`crates/axiam-api-rest/src/extractors/auth.rs`), as do its own tests, the admin UI,
and the `openapi.json` vendored alongside that contract. The server never reads
`X-Tenant-ID` at all.

Documentation updated here names `X-Axiam-Tenant`, because a tenant switch sent
under the other name is not refused — it is ignored, and the request quietly acts on
the principal's own tenant instead. The discrepancy has been reported upstream; this
SDK's existing `X-Tenant-ID` sends are left as they are, being out of scope for a
contract re-vendor.

## [1.0.0-beta04] - 2026-08-28

### Changed

- Re-vendor contract 1.33, record why Packagist needs no attestation

- **CONTRACT 1.32 — signing in an organization-level principal (§5.2.1).**
  `CONTRACT.md`, `openapi.json` and `management-registry.json` re-vendored from the
  AXIAM server, where the same bug class had made an organization-level
  administrator unable to sign in at all (ilpanich/axiam#388).

  Naming no tenant now resolves the organization's own reserved scope on
  `/auth/login`, `/auth/opaque/login/start`, `/auth/opaque/register/start` and
  `/auth/webauthn/authenticate/discoverable/start`. That reserved tenant's slug is
  `organization`, so this SDK reaches it through the ordinary constructor:

  ```php
  new AxiamClient($baseUrl, 'organization', orgSlug: 'globex')
  ```

  Prefer that over omitting the tenant: §5 rule 2 still requires one on the
  `X-Tenant-ID` header of every request after the login.

### Fixed

- Reject a blank tenant or orgSlug instead of sending it as ""

- **The constructor now rejects a blank `$tenant` (whitespace included) and a blank
  `$orgSlug`** (CONTRACT.md §5, §5.1, §5.2.1 rule 2). `$tenant === ''` caught the
  empty string but not a slug of spaces, and `$orgSlug` was unchecked. A **null**
  `$orgSlug` stays accepted — that is the organization identifier being optional,
  not blank.

  An SDK MUST NOT send an empty-string slug. Nothing can carry one, so the server
  resolves nothing — and on `/auth/opaque/login/start` it fails on the workspace
  *before* the tenant's OPAQUE mode is read, so the `404` of §23.4 rule 10 never
  arrives, this SDK has no fallback to take, and sign-in fails even against a
  tenant with OPAQUE **disabled**.

## [1.0.0-beta02] - 2026-08-28

### Added

- Contract 1.31 — list search, the truthful resend, organization scope

- **CONTRACT.md contract 1.31 — list search, the truthful resend, and organization scope.**
  The vendored `CONTRACT.md`, `openapi.json` and `management-registry.json` are re-synced
  from `axiam@main`, and four behaviours follow from them.

  **`PageRequest` gained a third component, `search` (§27.4 rule 4).** All twenty
  paginated operations accept an optional free-text term, matched case-insensitively by
  the **server** against the identifying fields of whatever is being listed — a name or
  username, plus the record id, so a UUID pasted out of a log line finds its row.
  `Page::$total` then counts *matches*, not rows.

  It rides on the page request rather than becoming a third argument on twenty generated
  methods, and that is what makes `PageRequest::next()` — and so
  `ManagementTransport::walk()` — carry it across the whole walk. A per-method argument
  has nowhere to live between one request and the next, so a walk built on one would
  return the matches followed by the unfiltered tail, which reads as a server bug from
  the caller's side. `null`, `""` and `"   "` are the same request: no `search` parameter
  at all. The term is trimmed but never truncated — the server's length cap stays the
  server's, because a client-side truncation the server would not have made is a silently
  different query the caller cannot see.

- **`AxiamClient::resendOwnVerification()` (§25.1, §25.7).** `POST
  /api/v1/users/me/resend-verification`, session-authenticated, taking **no address** —
  the server reads it off the caller's own record, and the signature deliberately offers
  no way to name a different one.

  It does not replace `resendVerification()`, and neither is routed to the other. The
  unauthenticated one takes an address from an anonymous caller, so it must answer
  identically whether the address exists, is already verified, or is rate-limited:
  anything else is an oracle for which addresses have accounts. This one is asked by a
  caller already signed in to the account it is asking about, so it tells the truth — a
  `409` for "already verified" and a `429` for the daily limit both raise, and this SDK
  does **not** fall back to the public endpoint on either (§25.7 rule 2). That fallback
  would turn both failures back into a silent success and restore the exact bug this
  operation exists to fix, with an extra round trip. Returning normally means the mail was
  *enqueued*, not delivered.

- **`LoginResult::$organizationLevel` (§5.2).** A completed login now reports whether the
  account it signed in is an organization-level principal — one whose record lives in its
  organization's reserved tenant, so its global grants apply in every tenant there and it
  can act on a different one by sending a different `X-Tenant-ID`, with no re-login.

  An ordinary tenant principal is a principal of exactly one tenant; the same header
  change produces a `403` for it. The flag is what an admin UI checks *before* offering a
  tenant selector, rather than discovering the answer from a failed request. It is derived
  from the response and never asserted: not a constructor argument, never sent, and
  `false` when absent — which is what a server older than contract 1.31 answers, and the
  safe direction in every case. Added with a default rather than changing the shape of
  `LoginResult`, so every existing construction still compiles.

- **Three §27.11 model additions**, regenerated: `Tenant::$kind` (`TenantKind`, the new
  `standard` | `organization` enum), `MtlsTrustAnchorResponse::$trustedAnchors`
  (`?int` — `null` is *not* zero: "the listener trusts no CAs" and "there was no listener
  to ask" are different operational states), and `Certificate::$boundServiceAccountId`.

  That last one is a **projection**, not a property of the certificate: the server
  resolves it for a whole page in one query, so `certificates()->listItems()` populates it
  and `certificates()->get($id)` leaves it `null`, with no second request to fill it in
  (§27.11 rule 4). `scripts/gen_management.py` learned to read the registry's
  `response.projected_fields` and fold such a field onto its base model as optional — the
  server expresses a projection as an `allOf` of the named base and an anonymous object,
  and a generator that reads only for a `$ref` sees a response with no element name at
  all.

- **CONTRACT.md §27 — the management API.** `$client->management()` exposes 146
  administrative operations across 24 namespace handles, plus the §27.6 declarative
  manifest layer. The models and handles are generated by `scripts/gen_management.py`
  from the vendored `management-registry.json` and `openapi.json`; the output is
  committed, and a new CI job re-runs the generator with `--check` on every pull request
  so the committed surface cannot drift from the contract it implements.

  All 146 operations go through one `ManagementTransport` built on the SDK's existing
  request path, so §3 CSRF, the §4 cookie jar, the §5 tenant header, §6 TLS, §16 retry
  and §19 telemetry apply by construction rather than per operation (§27.8).

  The declarative layer has two faces: `ManagementManifest::builder()` and the
  `#[ManagedResource]` / `#[ManagedPermission]` / `#[ManagedRole]` / `#[ManagedGroup]`
  attributes, matching what this SDK already does for §11. `plan()` writes nothing;
  `apply()` stops at the first failure and does not roll back, returning a report that
  names what landed, what failed, and what was never attempted.

- `AxiamClient::resolvedOrgId()` and `AxiamClient::resolvedTenantId()`. §27 has routes
  where `{org_id}`/`{tenant_id}` name the entity being administered rather than the
  calling context — the tenant signing CAs — and those take the identifier as an ordinary
  argument. Without these accessors a caller had no way to pass the same one the implicit
  routes use. `resolvedTenantId()` returns the tenant **UUID**, never the `$tenant` slug
  §5's header takes; the two are not interchangeable in a path segment.

### Changed

- Re-vendor openapi.json and management-registry.json from axiam main (#57)

- Re-vendor the contract artifacts, and drop committed Python bytecode (#55)

- Put the §27 namespace handles directly on the client, per §27.2/§27.3

- Add §27 examples, CI drift-check, docs, and ratchet the coverage floor

- Cover the §27 surface: model round-trips, core edges, manifest branches

- Add the §27.6 declarative layer and the §27.9 required tests

- Add the CONTRACT.md §27 management surface: generator, core, models

- Re-vendor CONTRACT.md, openapi.json and the §27 registry

- **Generated enums are now open (§27.11 rule 1).** `fromWire()` maps a value this SDK's
  copy of the spec does not list to that enum's new `Unknown` case instead of throwing an
  `AxiamException`.

  Throwing failed the **whole** response, so one field of one record on a page took down
  every record on it — including the ones the caller did ask for. That is the failure
  §27.11 rule 1 exists to prevent, and it is why this is a fix rather than a loosening.

  It still never reads an unrecognised value as one of the **known** cases: reading a new
  `"suspended"` as whichever case was declared first turns a new server state into a wrong
  one, and on this surface these values gate access. `Unknown` is a case of its own, and
  its wire spelling is the empty string — which no server value is, so carrying an
  unrecognised value back into an update is refused by the server rather than written as a
  spelling it never used. **A `match` over one of these enums now needs an `Unknown` arm**;
  an exhaustive `match` without one raises `\UnhandledMatchError` on a value only a newer
  server can send.

- **The §27 namespace handles now sit directly on the client** — `$client->roles()`,
  `$client->serviceAccounts()->rotateSecret($id)` — which is the form §27.3's PHP row
  specifies. `$client->management()` still reaches the same 24 handles behind one accessor;
  §27.2 rule 4 makes that the *additional* form ("SHOULD **additionally** be reachable
  behind one accessor"), so shipping only it had the two the wrong way round: the optional
  form present and the one the naming map specifies absent.

  Each direct accessor forwards to `management()`, so rule 4's "where an SDK offers both,
  the two MUST return equivalent handles" holds structurally rather than by two code paths
  agreeing to stay in step. `ManagementClientAccessorsTest` asserts it by comparing the
  method, path and query each form actually puts on the wire — a forwarding accessor that
  built its own handle with a default scope would return the right type and address the
  wrong organization, which is the failure the rule exists to prevent.

- `AuthzError` and `NetworkError` are no longer `final`, and `NetworkError`'s constructor
  is `protected` rather than `private`, so §27.4 rule 7 can classify three statuses
  *inside* the §2 taxonomy: `NotFoundError` (404) and `ConflictError` (409) extend
  `AuthzError`; `ValidationError` (400/422) extends `NetworkError`. A `catch (AuthzError)`
  written before §27 existed still catches the first two, which is the property the rule
  asks for. **The redact-before-wrap invariant is untouched**: the constructor a subclass
  can reach takes a string and a `Throwable`, never a `ResponseInterface`, so
  `NetworkError::fromResponse()` remains the only path from a response into the type.

- `RetryPolicy::execute()` accepts an optional `retryable` predicate. It defaults to the
  previous behaviour. §27 uses it for two reasons: §27.4 rule 8 retries only `GET`, and
  `ValidationError` sitting under `NetworkError` would otherwise let a body the server has
  already rejected be re-sent three times.

- The coverage floor moves 94% → 95%. The comment beside it claimed 96.92% had been
  achieved, which had gone stale as the repository grew; measured on the commit itself,
  the real figure before this change was 94.45%. §27 raises it to 95.93%.

## [1.0.0-alpha44] - 2026-08-25

### Changed

- Re-vendor openapi.json at alpha43 for tenant signing CAs (axiam#379)

- **Re-vendor `openapi.json` at 1.0.0-alpha43** for AXIAM server PR #379, which
  adds **tenant signing CAs**: an intermediate CA created beneath one of the
  organization's CAs and scoped to a single tenant, so a tenant's user, service
  and device certificates chain through a CA that can be revoked, rotated or
  handed to a different operator without redistributing the anchor the rest of
  the estate trusts. `CONTRACT.md` and `proto/` were untouched by that PR and are
  already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto any `/api/v1/organizations/{org_id}/...` CA route — and this SDK
  models none of the schemas below, so nothing here gains, loses, or changes a
  symbol. The spec is vendored so what this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - **`POST /api/v1/organizations/{org_id}/tenants/{tenant_id}/signing-cas`**
    (`generate_intermediate`) — create a tenant signing CA under an organization
    CA, with AXIAM generating the key. Returns `GeneratedCaCertificate`; the
    private key comes back exactly once, and not at all under `vault_pki`, where
    it was born inside Vault and no API exports it.
  - **`GET .../signing-cas`** (`list_intermediates`) — a paginated list of one
    tenant's signing CAs.
  - **`POST .../signing-cas/sign-csr`** (`sign_intermediate_csr`) — the BYOK
    counterpart: sign a PKCS#10 CSR produced elsewhere, so the private key never
    reaches AXIAM at all. The response carries no `private_key_pem` because there
    is none to carry.
  - **`CaCertificate` gains two nullable fields** — `tenant_id`, the tenant a CA
    signs for, and `parent_ca_id`, the CA in the organization that signed it.
    Both are absent for an organization-level CA, which is the trust anchor and
    the only kind that existed before this change.
  - **Four new schemas**: `CreateIntermediateCa`, `CreateIntermediateCaRequest`,
    `SignIntermediateCsr` and `SignIntermediateCsrRequest`.

  The spec version moves from **1.0.0-alpha40** to **1.0.0-alpha43**; the
  intervening alpha41 and alpha42 releases changed nothing in it but that string.

## [1.0.0-alpha43] - 2026-08-24

### Added

- Raise the PHP floor to 8.2 and run the newest release (#50)

- **PHP 8.5 is now a CI-run runtime.** The gating matrix runs `composer install`
  and the full PHPUnit suite on the floor **and** on the newest release, rather
  than on a single version.

- **`Axiam\Sdk\SupportedVersions`** — `MIN_PHP` and `NEWEST_TESTED_PHP` as
  readable constants. Composer enforces the lower bound at install time, but
  only at install time: `--ignore-platform-reqs`, a `config.platform` override,
  or a `vendor/` tree built on one runtime and deployed onto another all get
  past it, and the mismatch then surfaces as a parse error on the first
  request. Nothing exposed the upper end at all.

- **`tests/VersionPolicyTest.php`** — a conformance test for the support policy.
  It binds `composer.json`'s `require.php`, the CI matrix and both
  `SupportedVersions` constants together, and checks the declared floor against
  a table of PHP end-of-life dates, so a floor going out of support fails the
  build on the date it happens rather than whenever somebody next looks.

- **`examples/version_compatibility.php`** — a runnable preflight reporting the
  running runtime against the declared range, and the presence of the optional
  `ext-ffi` and `ext-grpc` extensions alongside it.

- **A "Supported PHP versions" section in the README.**

### Changed

- **BREAKING (declared support): `require.php` raised `>=8.1` → `>=8.2`.**

  The old floor was **untestable by construction**, and CI said so in a comment
  rather than in a failure: the require-dev framework bridges
  (`illuminate/support` ^11, `symfony/*` ^7) require PHP ^8.2 themselves, so
  `composer install` was unsatisfiable on 8.1 and the job died before running a
  single test. The package advertised 8.1 to every Packagist consumer and had
  never once executed it.

  PHP 8.1 reached end of life on 2025-12-31, so this drops nothing anybody
  should still be running. All four runtime dependencies (guzzle, php-amqplib,
  php-jwt, psr/log) resolved on 8.1 and no source change was needed — this
  corrects a declaration, not an implementation.

- **The gating CI matrix is floor + newest (`8.2`, `8.5`)** rather than a single
  pinned runtime. Source-level gates that cannot depend on the runtime —
  `composer validate`, `composer audit`, PHPStan, the docblock-coverage gate and
  the TLS-bypass grep — run once, on the floor leg.

## [1.0.0-alpha41] - 2026-08-24

### Added

- Honour login/start `mode` on a failed KE2 (§23.4 rule 7)

### Changed

- Re-vendor openapi.json for the vault_pki CA custodian (axiam#368)
- Re-vendor CONTRACT.md at 1.29 and openapi.json at alpha40

## [1.0.0-alpha40] - 2026-08-23

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha39.

## [1.0.0-alpha39] - 2026-08-23

### Changed

- Re-vendor CONTRACT.md for the §14.1 anchor repair
- Claim §17 and §19, both shipped since contract 1.8
- Re-vendor openapi.json at 1.0.0-alpha38

## [1.0.0-alpha38] - 2026-08-22

### Changed

- Re-vendor CONTRACT.md at 1.28
- Add WebAuthn, account lifecycle and PAR (CONTRACT §24–§26)

## [1.0.0-alpha37] - 2026-08-21

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha34.

## [1.0.0-alpha34] - 2026-08-21

### Added

- Replace SRP-6a with OPAQUE (RFC 9807), CONTRACT §23

- CONTRACT.md §24 — WebAuthn / passkeys relying-party layer (`Axiam\Sdk\Webauthn`):
  the six wire operations, the two distinct authentication ceremonies, and
  §24.6a's JSON bridge. `WebauthnChallenge::requestJson()` is the string a PHP
  relying party sends down to the browser, and the browser's response JSON goes
  straight back into the matching `*Finish` — spliced into the request body as
  text so the authenticator's signed bytes reach the wire unmodified.
  `WebauthnFailure::classify()` maps a relayed `DOMException` name to the five
  §24.6b rule 5 outcomes.

  §24.6b's linked-API helper is deliberately absent: PHP runs on a server, which
  has no authenticator, and rule 2 forbids emulating one in software.

- CONTRACT.md §25 — account lifecycle and MFA enrolment (`Axiam\Sdk\Account`):
  voluntary and forced TOTP enrolment, email verification, and the
  password-reset triple including the `reset/context` call a tenant with §23
  enabled requires before a new password can be built.

- CONTRACT.md §26 — Pushed Authorization Requests, RFC 9126 (`oidcPar`,
  `PushedAuthorizationRequest`). Required for a FAPI 2.0 client, which cannot
  authorize any other way (§21.1).

- `examples/webauthn_passkeys.php`, `examples/account_lifecycle.php` and
  `examples/par_login.php`.

- OPAQUE (RFC 9807) login and enrolment (CONTRACT §23): `loginOpaque()`,
  `opaqueEnrollment()` and `opaqueAvailable()` on `AxiamClient`, plus the new
  `Axiam\Sdk\Opaque` namespace.

- `examples/opaque_login.php`.

- `ext-ffi` in `suggest`. It binds `libaxiam_opaque_ffi`; a consumer whose tenant
  does not use OPAQUE needs neither.

### Changed

- Link to the AXIAM platform documentation site

- Re-vendor openapi.json at alpha32 (#43)

- Give every new public member a docblock

- Give the fake login response the user.id a 200 requires

- **Re-vendor `openapi.json`** for AXIAM server PR #368, which adds a third CA
  key custodian, `vault_pki`, having HashiCorp Vault's PKI secrets engine
  generate the CA key inside Vault and sign on AXIAM's behalf. The spec version
  is unchanged at **1.0.0-alpha40**; `CONTRACT.md` and `proto/` are untouched by
  that PR and are already current.

  This is a specification re-sync with **no SDK surface change**. CA-certificate
  administration is not part of the SDK contract — `CONTRACT.md` §1 maps no
  method onto `/api/v1/organizations/{org_id}/ca-certificates`, and this SDK
  models none of the five schemas below — so nothing here gains, loses, or
  changes a symbol. It is vendored so the spec this SDK is written against keeps
  describing the server it talks to.

  What moved in the spec:

  - `CaCertificate` gains a nullable `chain_pem`: the issuers above
    `public_cert_pem`, concatenated PEM, nearest issuer first and the root last.
    Absent for a CA that is its own root, which is every CA AXIAM generated
    before this. Present for a `vault_pki` CA, where it is the only copy of the
    root certificate anything outside Vault will ever see.
  - `CaCertificate.public_cert_pem` is now documented as the certificate that
    *signs*, which under `vault_pki` custody is the intermediate rather than the
    root beneath which it was created. The field itself is unchanged.
  - `GeneratedCaCertificate.private_key_pem` is **no longer required**. Under
    `vault_pki` custody the key is born inside Vault and no API exports it, so
    there is nothing to return. The field is omitted rather than sent as `null`,
    which keeps a client that has always read it working unchanged against every
    custodian that does produce a key.
  - `GeneratedCertificate` gains a nullable `chain_pem`, present only when the
    signer returned one — the `vault_pki` case, where the root's certificate
    exists nowhere a client could fetch it from.
  - `CreateCaCertificate` and `CreateCaCertificateRequest` gain the optional
    `issue_from_root`, `intermediate_subject` and `intermediate_validity_days`.
    All three are `vault_pki`-only and ignored by every other custodian.
    `issue_from_root` defaults to off: a root that signs only one intermediate
    can have that intermediate revoked and replaced without redistributing the
    trust anchor, and a root that signs leaves directly cannot.

- **§23.4 rule 7, contract 1.29 — a failed `KE2` is no longer always final.**
  `login/start` now answers with an optional `mode` field carrying the tenant's
  `opaque_mode` (`"optional"` or `"required"`; a disabled tenant still answers
  `404`), and it is the only thing that decides what `loginOpaque()` does when
  the envelope does not open. `KE3` is still never sent. Under `"optional"` the
  call now retries over `login()` with the same credentials and returns that
  call's outcome — its success, or its error. Under `"required"`, and for a
  response carrying no `mode` at all (a server older than the field), the
  failure is an `AuthError` with no retry, exactly as before. An unrecognised
  value fails closed.

  Without the `optional` branch, enabling `optional` was indistinguishable from
  enabling `required` with nobody enrolled: every account has no registration
  record the moment an operator turns OPAQUE on and acquires one only when its
  password is next set, so treating the failed exchange as final locked out
  every user of a tenant mid-migration.

  `mode` is **not** downgrade protection and the new `Axiam\Sdk\Opaque\OpaqueMode`
  says so — a hostile server that wanted the plaintext could answer `404` and
  get the fallback whatever it put here. `required` is what closes that,
  server-side, by refusing `/auth/login` before examining any credential.

- Re-vendored `CONTRACT.md` at contract **1.29** and `openapi.json` at
  **1.0.0-alpha40**.

- Re-vendor `CONTRACT.md`. Repairs §14.1's link to the `device_login` heading,
  which dropped a hyphen the em dash leaves behind and so rendered as a link
  that went nowhere; the same heading's other two links were already correct.
  Link target only — no normative change and no contract-version bump.

- **Conformance statement now names §17 and §19.** The opt-in decision memo
  (`decisionMemoTtlMs`) and the telemetry hooks (`telemetryHook`) both landed with
  contract 1.8, are exercised by the D5 conformance suite, and ship a worked
  `examples/telemetry_hook.php`; the headline statement had never been widened to
  say so.

- Re-vendor `openapi.json` at **1.0.0-alpha38**. The server registered the four
  GDPR data-subject endpoints (`POST /api/v1/account/export`,
  `GET /api/v1/account/export/{token}`, `POST /api/v1/account/delete`,
  `GET /api/v1/auth/account/delete/cancel`), taking the document to 181
  operations across 121 paths. Purely additive, and no SDK surface changes with
  it: nothing in this repo is generated from the spec, so the cross-repo
  artifact-drift gate was the only thing reporting `STALE`.

- `LoginResult` gained `$mfaSetupRequired` and `$setupToken` for §25.2 rule 1's
  third login outcome. Both default, so every existing construction still works
  and reads `false`. Callers that branch only on `$mfaRequired` should still add
  the new branch — a tenant that turns on required MFA will start returning it,
  and ignoring it reports a successful login that has no session.

- `login()` now reads the response body before mapping a non-2xx status, so the
  §25.2 rule 1 discriminant is reachable. An ordinary `403` still maps through
  `ErrorMapper` exactly as before.

- `OidcConfiguration` gained `$pushed_authorization_request_endpoint`, defaulted
  to `null` and parsed from discovery.

- Re-vendored `CONTRACT.md` and `openapi.json` at contract 1.28.

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
  everything else is `AuthError` (§23.4 rule 7 — see the contract 1.29 entry
  above for the one `mode` under which the SDK itself retries over `login()`).

- Re-vendor `openapi.json` at **1.0.0-alpha32**, matching the server. The
  content was already byte-identical in every path and schema; only
  `info.version` differed, which is what the cross-repo artifact-drift gate
  reports as `STALE`.

### Removed

- **BREAKING** — SRP-6a. `loginSrp()`, `srpEnrollment()`, `srpAvailable()`, the
  whole `Axiam\Sdk\Srp` namespace (both bignum backends), `srp-test-vectors.json`
  and `examples/srp_login.php` are all gone. AXIAM's server-side SRP endpoints are
  removed in the same release, so keeping the client would leave methods that only
  ever return 404.

- `ext-gmp` and `ext-bcmath` from `suggest`. They were there for SRP's modular
  exponentiation and nothing else in this SDK uses them.

### Fixed

- Let the PHPStan ignore match axiam_opaque_ksf_argon2id

- Make PHPStan level 6 pass on the FFI binding

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

- Add a codegen drift gate for the committed gRPC stubs (D-03)
- Re-vendor CONTRACT.md 1.19, openapi.json and proto/ from main (R5.8) (#35)
- R5.7 — §9 refresh-result sharing under concurrency (F-06), AuthError parameter order (F-18), §12.3 rule 3 invariant (F-14) (#34)
- Contract 1.15 — §10.1 rule 9, sender-constrained access tokens (#32)
- Retire the "measured residual" justification (contract 1.14)
- Re-sync to contract 1.14 (#302 closed)
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
- **Re-sync vendored `CONTRACT.md` / `openapi.json` to contract 1.15.**
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
- Re-vendored `CONTRACT.md` at **1.10** and `openapi.json` (the server's `/uma2/*` surface).
- `login`, `verifyMfa`, `refresh` and `logout` clear the decision memo (§17.1 rule 9) and
  reject after close (§18.1 rule 4).
- `AuthMiddleware` gained `CREDENTIAL_OVERRIDE_OPTION`, a per-request Guzzle option naming a
  bearer credential that is not the session's. The middleware overwrites `Authorization`
  unconditionally — it has to, so a request retried after a single-flight refresh is
  re-decorated with the fresh token — which left no way for a caller to say "use *this*
  credential". The Protection API needs exactly that, because §20.2 rule 1 forbids falling
  back to the session token when a PAT was asked for.

### Fixed

- §15.7 — Sensitive exposes via reveal(), not expose()
- Route checkAccess/can/batchCheck through the instrumented path (F3) (#25)
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

## [1.0.0-alpha24] - 2026-08-04

### Added

- Add AxiamWebhooks::verify signature verifier (CONTRACT §13, T-145)
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

- Device (mTLS) tokens now carry aud=axiam:m2m (#22)
- Service accounts can use login_client_credentials (#21)
- Bump coverallsapp/github-action from 2.3.6 to 2.3.8
- Re-sync the vendored `CONTRACT.md` with the new normative §10.1.

### Fixed

- SEC-085 — request guards must not substitute the client's own session (#20)
- Enforce the full CONTRACT §10.1 local-verification set
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

### Changed

- Maintenance release — no notable changes since v1.0.0-alpha9.

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
