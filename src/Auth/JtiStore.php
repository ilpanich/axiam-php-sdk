<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

/**
 * CONTRACT.md §21.7.2 check 8 — single-use `jti` tracking for DPoP proofs.
 *
 * One method, and its contract is the whole point: {@see self::claim()} must be
 * atomic. A `contains?`-then-`add` pair read as two calls is a race that two
 * concurrent replays of the same proof can both win.
 *
 * `iat` freshness bounds the replay window; this guard is what makes the window
 * unusable.
 */
interface JtiStore
{
    /**
     * Record `$jti` as used until `$expiresAtUnix`.
     *
     * @param string $jti           The proof's `jti` claim.
     * @param int    $expiresAtUnix When the entry may be forgotten (UNIX seconds).
     *
     * @return bool `true` if this is the first sighting, `false` if it is a replay.
     */
    public function claim(string $jti, int $expiresAtUnix): bool;
}
