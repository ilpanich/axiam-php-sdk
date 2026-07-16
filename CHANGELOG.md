# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
