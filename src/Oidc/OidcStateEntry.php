<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\Sensitive;

/**
 * The tuple an {@see OidcStateStoreInterface} holds for one in-flight login.
 *
 * `$codeVerifier` stays {@see Sensitive} while stored (§12.5: the verifier is secret for
 * its whole lifetime, "including … in any `OidcStateStore` entry"), so a store
 * implementation that needs to persist the value at rest (e.g. a Redis-backed store)
 * must call `->reveal()` explicitly and is then responsible for protecting it.
 */
final class OidcStateEntry
{
    /**
     * @param string    $state        The `state` value this entry is keyed by. Not a secret (§12.3 rule 2).
     * @param string    $nonce        The `nonce` to check the ID token's `nonce` claim against. Not a secret (§12.3 rule 2).
     * @param Sensitive $codeVerifier The PKCE verifier for the matching authorization request (§12.5 secret).
     * @param string    $redirectUri  The `redirect_uri` that was sent on the authorization request and must be replayed on exchange.
     * @param string|null $returnTo   Optional application-owned data, e.g. the page the user was heading to before login.
     *        The login glue only stores a value that is a same-origin relative path (§12.8 rule 3) and checks it
     *        again before redirecting, because a store may be the integrator's own and an entry may be older glue's.
     * @param string|null $bindingDigest Lower-case hex SHA-256 of the browser-binding cookie value the login set
     *        (§12.8 rule 1, contract 1.68; C7). OPTIONAL so a store written against contract 1.67 still works and an
     *        entry without it can still be read — the callback then REFUSES it. A caller-supplied store MUST persist
     *        this member and return it unchanged: one that rebuilds entries from a fixed field list and drops it
     *        refuses every sign-in, loudly, which is the safe failure. Not secret, but never logged.
     */
    public function __construct(
        public readonly string $state,
        public readonly string $nonce,
        public readonly Sensitive $codeVerifier,
        public readonly string $redirectUri,
        public readonly ?string $returnTo = null,
        public readonly ?string $bindingDigest = null,
    ) {
    }
}
