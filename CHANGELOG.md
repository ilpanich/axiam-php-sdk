# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
