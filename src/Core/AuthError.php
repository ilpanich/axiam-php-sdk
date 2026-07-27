<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

/**
 * Authentication failure: wrong credentials, expired session, MFA failure, or a 401
 * on refresh (CONTRACT.md §2). Always constructed via {@see ErrorMapper} so REST and
 * gRPC transports cannot drift on the error taxonomy.
 *
 * NOT `final` (CONTRACT.md §12, contract 1.4): {@see OAuthProtocolError} is a
 * language-idiomatic sub-type of this class, added additively for the §12 OIDC/SSO
 * relying-party helpers — every existing `catch (AuthError $e)` block keeps working
 * unchanged. `$reason` is an optional, stable, machine-readable code — used by the §12.4
 * ID-token validation checklist (`invalid_alg`, `unknown_kid`, `invalid_signature`,
 * `invalid_issuer`, `invalid_audience`, `token_expired`, `nonce_mismatch`) — carried on
 * the SAME `AuthError` type rather than a second error class (contract 1.4 judgment call:
 * ride the existing taxonomy, don't multiply it). It is `null` for every pre-existing
 * `AuthError` use in this SDK.
 */
class AuthError extends AxiamException
{
    public function __construct(
        string $message,
        private readonly ?string $reason = null,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, previous: $previous);
    }

    /**
     * A stable, machine-readable failure code, when this `AuthError` was raised for one
     * of the §12.4 ID-token validation rules. `null` for every other `AuthError` in this
     * SDK (wrong credentials, expired session, MFA failure, 401 on refresh, …).
     */
    public function getReason(): ?string
    {
        return $this->reason;
    }
}
