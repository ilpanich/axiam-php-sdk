<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\Sensitive;

/**
 * The result of `oidcBegin` — everything the caller needs to start an
 * authorization-code + PKCE login (CONTRACT.md §12.1).
 *
 * **The caller owns this state** (§12.3 rule 1). The SDK stores nothing: it keeps no
 * copy of `$state`, `$nonce` or `$codeVerifier` in any implicit cache or process-global
 * state. Persist all three in your own HTTP session (or in an
 * {@see OidcStateStoreInterface}), redirect the browser to {@see self::$url}, and pass
 * `$nonce` + `$codeVerifier` back into `oidcExchange` when the authorization code arrives.
 */
final class AuthorizationRequest
{
    /**
     * @param string    $url          The fully-built authorization URL to redirect the browser to.
     * @param string    $state        CSPRNG CSRF value (≥128 bits, base64url unpadded) to compare against the `state` the IdP returns. Not a secret (§12.3 rule 2).
     * @param string    $nonce        CSPRNG replay-protection value (≥128 bits) that must equal the ID token's `nonce` claim. Not a secret (§12.3 rule 2).
     * @param Sensitive $codeVerifier The PKCE verifier, secret for its whole lifetime (§12.5). Pass it back into `oidcExchange`.
     */
    public function __construct(
        public readonly string $url,
        public readonly string $state,
        public readonly string $nonce,
        public readonly Sensitive $codeVerifier,
    ) {
    }
}
