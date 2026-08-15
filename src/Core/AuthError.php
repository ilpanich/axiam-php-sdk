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
 *
 * **`$reason` is LAST on purpose (conformance-review F-18).** When §12 first added it, it
 * went in second — ahead of `$previous` — which silently changed what the second
 * positional argument means for every caller that already constructed this class
 * directly. `$previous` is back in the position PHP's own exception convention (and this
 * SDK's {@see NetworkError}) puts it, and new parameters are appended, never inserted.
 * Pass `$reason` by name (`reason:`), which is what every call site in this SDK does.
 */
class AuthError extends AxiamException
{
    /**
     * @param string          $message  Human-readable failure description (CONTRACT.md §2:
     *                                  never carries a token, credential, or claim value).
     * @param \Throwable|null $previous Cause, for `getPrevious()` chaining.
     * @param string|null     $reason   Stable machine-readable §12.4 code — pass by name.
     */
    public function __construct(
        string $message,
        ?\Throwable $previous = null,
        private readonly ?string $reason = null,
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
