<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\Sensitive;

/**
 * The result of `AxiamClient::oidcPar()` (CONTRACT.md §26.1).
 *
 * The server answered **201** — RFC 9126 §2.2 specifies Created, and a success predicate
 * written `=== 200` would treat every successful push as a failure.
 *
 * `$state`, `$nonce` and `$codeVerifier` are carried straight through from the
 * {@see AuthorizationRequest} that was pushed: §26.2 rule 1 forbids a second generator, and
 * rule 6 wants exactly one verifier so there is no second place for the two to disagree.
 */
final readonly class PushedAuthorizationRequest
{
    /**
     * @param string    $url          Where to redirect the user agent. Carries **exactly**
     *   `client_id` and `request_uri` — the server refuses a request that mixes a
     *   `request_uri` with inline authorization parameters rather than merging them, because
     *   merging is where parameter confusion lives (§26.2 rule 2).
     * @param Sensitive $requestUri   The opaque, single-use handle. {@see Sensitive} per §26.5:
     *   between the push and the redirect it is a bearer handle to a fully-formed authorization
     *   request, and a log line is the wrong place for it to sit for the length of that window.
     * @param int       $expiresIn    The handle's lifetime in seconds; not advisory (§26.2 rule 3).
     * @param string    $state        The value to compare against the `state` the IdP returns.
     * @param string    $nonce        The value that must equal the ID token's `nonce` claim.
     * @param Sensitive $codeVerifier The PKCE verifier to pass into `oidcExchange()`.
     */
    public function __construct(
        public string $url,
        public Sensitive $requestUri,
        public int $expiresIn,
        public string $state,
        public string $nonce,
        public Sensitive $codeVerifier,
    ) {
    }
}
