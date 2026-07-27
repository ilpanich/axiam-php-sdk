<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

/**
 * An RFC 6749 protocol error returned by an `/oauth2/*` endpoint as an
 * `OAuth2ErrorResponse` body — `invalid_grant`, `invalid_client`, `invalid_request`,
 * `unsupported_grant_type`, … (CONTRACT.md §2, §12.3 rule 3).
 *
 * A language-idiomatic **sub-type of {@see AuthError}** (contract 1.4, addendum item 17):
 * it does NOT replace `AuthError` as a fourth peer error type, so an existing
 * `catch (AuthError $e)` block already written against this SDK's §1–§11 surface keeps
 * working unchanged after §12 is added — it simply also catches an `OAuthProtocolError`.
 *
 * `getMessage()` is always exactly `"<error>: <error_description>"`, built from the two
 * `OAuth2ErrorResponse` fields, which are also exposed individually as public readonly
 * properties (CONTRACT.md §2's error-construction rule).
 */
final class OAuthProtocolError extends AuthError
{
    /**
     * @param string $error RFC 6749 error code (e.g. `invalid_grant`, `invalid_client`).
     * @param string $errorDescription The server's human-readable description of {@see self::$error}.
     */
    public function __construct(
        public readonly string $error,
        public readonly string $errorDescription,
    ) {
        parent::__construct(sprintf('%s: %s', $error, $errorDescription));
    }
}
