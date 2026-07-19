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

This SDK conforms to [`CONTRACT.md`](CONTRACT.md) §1–§11 (including §6.1 mTLS) — the binding,
cross-language behavioral contract every AXIAM SDK implements: camelCase method names
(§1), the `AuthError`/`AuthzError`/`NetworkError` typed exception hierarchy (§2), non-browser
`X-CSRF-Token` response-header capture (§3), a shared Guzzle `CookieJar` (§4), a required
`tenant` constructor parameter with no default (§5), strict TLS with `customCa` as the only
server-verification escape hatch (§6) plus optional client-certificate mutual TLS (§6.1),
`Sensitive`-wrapped token redaction (§7), HMAC-SHA256-verified AMQP
messages (§8), single-flight refresh concurrency safety (§9), framework
middleware/subscriber integration (§10), and declarative per-endpoint authorization
helpers (§11, see below).

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

Token-carrying values (access tokens, refresh tokens, MFA challenge tokens) are wrapped in
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
- [`examples/laravel_app/`](examples/laravel_app/README.md) — runnable Laravel middleware + Gate example.
- [`examples/symfony_app/`](examples/symfony_app/README.md) — runnable Symfony subscriber + Voter example (manual registration).
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
[`proto/axiam/v1/authorization.proto`](proto/axiam/v1/authorization.proto) and **committed
to this repository** — that is what lets `composer require axiam/axiam-sdk` work with no
protobuf toolchain on your machine, and what keeps gRPC a `suggest` rather than a hard
dependency. Unlike the other AXIAM SDKs, PHP does not use `buf` (D-03); it invokes `protoc`
directly.

You only need this when `proto/` changes:

```bash
composer grpc-gen    # requires protoc on PATH; no grpc_php_plugin needed
git diff src/Grpc/Gen
```

The service client (`src/Grpc/AuthzGrpcClient.php`) is hand-written against
`\Grpc\BaseStub` and is **not** generated — do not overwrite it.
