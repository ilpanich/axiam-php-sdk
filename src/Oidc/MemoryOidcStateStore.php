<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * In-memory reference implementation of {@see OidcStateStoreInterface} (CONTRACT.md
 * §12.3 rule 1).
 *
 * Per-instance (never process/static-global), single-use, 10-minute TTL. Expired
 * entries are dropped lazily on {@see self::consume()} and swept opportunistically on
 * {@see self::save()} — never a background timer/thread, since a library must not keep
 * a long-running worker (Swoole/RoadRunner) process alive on its own.
 *
 * Suitable for a single-process app and for tests. A multi-instance deployment needs a
 * shared store (Redis, database) — implement {@see OidcStateStoreInterface} yourself for
 * that; nothing in this SDK assumes this class.
 *
 * @example
 * ```php
 * $store = new MemoryOidcStateStore();
 * $store->save(new OidcStateEntry($state, $nonce, $codeVerifier, $redirectUri));
 * $entry = $store->consume($state);   // returns the entry
 * $again = $store->consume($state);   // null — single-use
 * ```
 */
final class MemoryOidcStateStore implements OidcStateStoreInterface
{
    /**
     * The contract-mandated TTL for stored login state: 10 minutes, matching the
     * server's `federation_login_state` row lifetime (§12.3 rule 1).
     */
    public const TTL_SECONDS = 600;

    /** @var array<string,array{entry: OidcStateEntry, expiresAt: int}> */
    private array $entries = [];

    private readonly int $ttlSeconds;

    /**
     * @param int $ttlSeconds Entry lifetime in seconds. Defaults to {@see self::TTL_SECONDS}
     *                        (10 minutes) and is **clamped to it**: a shorter TTL is
     *                        honoured (useful in tests), a longer one is reduced, because
     *                        §12.3 rule 1 fixes 10 minutes as the maximum.
     */
    public function __construct(int $ttlSeconds = self::TTL_SECONDS)
    {
        $this->ttlSeconds = min($ttlSeconds, self::TTL_SECONDS);
    }

    /** Number of unexpired entries currently held. Intended for tests and metrics. */
    public function size(): int
    {
        $this->sweep();

        return count($this->entries);
    }

    /** Persist `$entry` under its own `state`, expiring `$ttlSeconds` from now. */
    public function save(OidcStateEntry $entry): void
    {
        $this->sweep();
        $this->entries[$entry->state] = ['entry' => $entry, 'expiresAt' => time() + $this->ttlSeconds];
    }

    /**
     * Atomically return and delete the entry for `$state`. Deletion happens before the
     * expiry check, so even an expired hit is removed rather than left to accumulate,
     * and a second call can never return the same entry twice — PHP's single-threaded,
     * non-preemptive request model makes this get-then-delete pair genuinely atomic; a
     * store backed by real concurrency (e.g. Redis) must use an atomic primitive such as
     * `GETDEL`.
     */
    public function consume(string $state): ?OidcStateEntry
    {
        $held = $this->entries[$state] ?? null;
        if ($held === null) {
            return null;
        }
        unset($this->entries[$state]);
        if ($held['expiresAt'] <= time()) {
            return null;
        }

        return $held['entry'];
    }

    /** Drop every expired entry. Lazy housekeeping — no background timer. */
    private function sweep(): void
    {
        $now = time();
        foreach ($this->entries as $state => $held) {
            if ($held['expiresAt'] <= $now) {
                unset($this->entries[$state]);
            }
        }
    }
}
