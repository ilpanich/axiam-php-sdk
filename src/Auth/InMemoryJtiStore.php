<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

/**
 * A {@see JtiStore} for a single PHP process.
 *
 * **Per-process, and on a classic PHP-FPM runtime that means per-request** — the
 * array does not survive the response, so this store prevents no replay at all
 * under FPM. It is useful on a long-running runtime (Swoole, RoadRunner, a CLI
 * worker), and even there it is per-worker: four workers give an attacker four
 * chances to replay a proof inside its freshness window.
 *
 * Any deployment that actually needs replay protection wants a shared store
 * (Redis `SET key NX EX`, a unique index on a database table) behind the same
 * {@see JtiStore} interface.
 */
final class InMemoryJtiStore implements JtiStore
{
    /** @var array<string,int> jti => expiry, as UNIX seconds. */
    private array $seen = [];

    /**
     * Record `$jti` as used until `$expiresAtUnix`.
     *
     * @param string $jti           The proof's `jti` claim.
     * @param int    $expiresAtUnix When the entry may be forgotten (UNIX seconds).
     *
     * @return bool `true` if this is the first sighting, `false` if it is a replay.
     */
    public function claim(string $jti, int $expiresAtUnix): bool
    {
        $now = time();

        // Prune inline. Entries only ever live for the freshness window, so this
        // stays small without a background sweeper.
        if (count($this->seen) > 128) {
            $this->seen = array_filter($this->seen, static fn (int $exp): bool => $exp > $now);
        }

        if (isset($this->seen[$jti]) && $this->seen[$jti] > $now) {
            return false;
        }

        $this->seen[$jti] = $expiresAtUnix;

        return true;
    }
}
