<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * Optional server-side store for in-flight `oidcBegin` state (CONTRACT.md §12.3 rule 1).
 *
 * The nine §12 operations never touch a store on their own: `oidcBegin` and
 * `oidcExchange` are stateless by contract, and a caller normally keeps
 * `state`/`nonce`/`code_verifier` in its own HTTP session. This interface exists for the
 * Laravel/Symfony "Login with AXIAM" glue ({@see \Axiam\Sdk\Oidc\OidcLoginFlow}), where a
 * login and its callback are two separate HTTP requests with nothing but a `state` value
 * linking them. It MUST be opt-in — the core `oidcBegin`/`oidcExchange` operations remain
 * fully usable without one.
 *
 * Implement this to back the login/callback handlers with your own storage (Redis, a
 * database, an encrypted cookie). Two invariants are normative:
 *
 * 1. **Single-use.** {@see self::consume()} MUST return the entry *and delete it
 *    atomically*, so a replayed callback cannot reuse a `state`.
 * 2. **Expiry.** An entry older than 10 minutes MUST NOT be returned.
 */
interface OidcStateStoreInterface
{
    /** Persist `$entry`, keyed by its `state`, starting its TTL now. */
    public function save(OidcStateEntry $entry): void;

    /**
     * Atomically fetch **and remove** the entry for `$state`. Returns `null` when the
     * state is unknown, already consumed, or expired — three cases a caller MUST treat
     * identically (as a failed login), because distinguishing them leaks whether a
     * `state` ever existed.
     */
    public function consume(string $state): ?OidcStateEntry;
}
