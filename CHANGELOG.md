# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
