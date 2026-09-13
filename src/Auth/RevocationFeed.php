<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

use GuzzleHttp\ClientInterface;

/**
 * The optional session-revocation feed poller (CONTRACT.md §10.4, contract 1.44 — AXIAM
 * threats T-39 and T-143).
 *
 * WHAT THIS NARROWS, AND WHAT IT IS NOT
 *
 * An AXIAM access token is self-contained and valid for up to fifteen minutes, and this
 * SDK verifies it locally. A logout, a role removal or an account disable therefore does
 * not reach a token already in a caller's hands until it expires — §10.2 records that, and
 * the documented answer has been "route the decision through gRPC introspection instead",
 * which is correct and costs a round trip PER REQUEST.
 *
 * A deployment may publish `GET /oauth2/revocations`: the base64url-unpadded SHA-256 of
 * every session id revoked within the last access-token lifetime. A guard that polls it
 * rejects a revoked session within ONE POLL INTERVAL instead of one token lifetime, for one
 * cacheable fetch per interval.
 *
 * It is NOT a control, and every rule below follows from that:
 *
 * - DEFAULT OFF. Nothing polls unless a caller constructs one and passes it.
 * - NEVER ON THE REQUEST PATH. {@see isRevoked()} answers from the cached set and, at most,
 *   refreshes a set the NEXT caller sees.
 * - NEVER FAIL CLOSED. An unreachable feed, a non-200, a body that does not parse, an `alg`
 *   this build does not know — every one of them behaves exactly as no feed at all. Not as
 *   an empty list: an empty list asserts that nothing has been revoked, which is a guard
 *   that silently honours no revocations while appearing to honour them.
 * - IT ONLY EVER REJECTS. Every §10.1 rule runs first and still decides. The feed can turn
 *   an accept into a reject and never the reverse.
 * - A TOKEN WITH NO `sid` IS NEVER MATCHED. There is no session behind a
 *   client-credentials token, an RPT or a token exchange, and hashing `jti` instead would
 *   match nothing while looking like it worked.
 */
final class RevocationFeed
{
    /** The published feed's path, appended to a deployment's base URL. */
    public const FEED_PATH = '/oauth2/revocations';

    /**
     * The only digest the feed publishes, and the only one this poller accepts.
     *
     * A document naming anything else is treated as unusable — exactly as an unreachable
     * feed is — rather than as a list of entries that happen not to match. Silently
     * matching nothing is how a guard ends up reporting that it honours revocations while
     * honouring none.
     */
    private const SUPPORTED_ALG = 'SHA-256';

    /**
     * The shortest interval a caller may configure (§10.4 rule 2), in seconds.
     *
     * Bounded because the feed is one deployment-wide document and a fleet of guards
     * polling it at a hundred milliseconds is a load source rather than a security
     * improvement. The floor is applied by CLAMPING, not by refusing: a caller who asked
     * for something faster gets the fastest thing on offer.
     */
    public const MIN_POLL_INTERVAL_SECONDS = 15;

    /** The interval §10.4 recommends, and the one a feed uses unless told otherwise. */
    public const DEFAULT_POLL_INTERVAL_SECONDS = 30;

    /**
     * The largest number of entries kept in the cache (§10.4 rule 2).
     *
     * The server bounds the document by its own revocation rate over one token lifetime, so
     * this is defence against a server that stops doing so — a cache with no ceiling is an
     * allocation an unauthenticated endpoint controls. Overflow drops the WHOLE set rather
     * than truncating it: a truncated set is a guard that admits some revoked sessions and
     * reports none, which is worse than a guard that admits all of them and says the feed
     * is unusable.
     */
    public const MAX_ENTRIES = 100000;

    /**
     * Caps what is read off the wire before the entry count can be known, since the count
     * is only knowable after decoding. 64 bytes of entry plus JSON framing over
     * MAX_ENTRIES, rounded up.
     */
    private const MAX_BODY_BYTES = 8 << 20;

    private readonly string $feedUrl;

    private readonly int $pollIntervalSeconds;

    /**
     * Null means "never successfully fetched", which is NOT the same as an empty set, and
     * is why this is compared against null rather than by count.
     *
     * @var array<string,true>|null
     */
    private ?array $entries = null;

    private ?float $lastAttempt = null;

    /**
     * A testing seam only; null means the real clock. Not reachable from configuration.
     *
     * @var (callable():float)|null
     */
    private $clock = null;

    /**
     * @param ClientInterface $http    used only to fetch the feed document; the same
     *                                 Guzzle client type {@see JwksVerifier} takes
     * @param string          $baseUrl the AXIAM server base URL; the feed
     *                                 path is resolved against it. A deployment that does
     *                                 not publish the feed is not an error here — that is
     *                                 discovered on the first poll, and behaves as no feed
     *                                 at all from then on
     * @param int|null        $pollIntervalSeconds how long a fetched set is served before a
     *                                 refetch is attempted; clamped UP to
     *                                 MIN_POLL_INTERVAL_SECONDS rather than refused
     */
    public function __construct(
        private readonly ClientInterface $http,
        string $baseUrl,
        ?int $pollIntervalSeconds = null,
    ) {
        $this->feedUrl = rtrim($baseUrl, '/') . self::FEED_PATH;
        $interval = $pollIntervalSeconds ?? self::DEFAULT_POLL_INTERVAL_SECONDS;
        $this->pollIntervalSeconds = max($interval, self::MIN_POLL_INTERVAL_SECONDS);
    }

    /** The feed document's URL, for diagnostics. */
    public function feedUrl(): string
    {
        return $this->feedUrl;
    }

    /** The interval actually in effect, after the MIN_POLL_INTERVAL_SECONDS clamp. */
    public function pollIntervalSeconds(): int
    {
        return $this->pollIntervalSeconds;
    }

    /**
     * Overrides the clock. Testing seam only.
     *
     * @param (callable():float)|null $clock
     *
     * @internal
     */
    public function setClock(?callable $clock): void
    {
        $this->clock = $clock;
    }

    /**
     * The feed entry for a `sid`, as the server computes it.
     *
     * Base64url without padding over the claim's EXACT string — never a
     * parsed-and-re-rendered UUID, or the answer would depend on this class's UUID parser
     * rather than on the feed.
     */
    public static function entryFor(string $sid): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $sid, true)), '+/', '-_'), '=');
    }

    /**
     * Reports whether this session has been revoked, as far as this poller knows.
     *
     * False whenever the answer is not a confident yes — a feed never fetched, unreachable,
     * malformed, or simply not listing this session. The caller admits the request in all
     * of those cases, which is §10.4 rule 3 and is the whole reason the feature is safe to
     * turn on.
     *
     * @param string|null $sid the `sid` claim, or null/empty for a token that carries none
     *                         — which is never matched (§10.4 rule 6)
     */
    public function isRevoked(?string $sid): bool
    {
        if ($sid === null || $sid === '') {
            return false;
        }

        $this->refreshIfStale();

        if ($this->entries === null) {
            return false;
        }

        return isset($this->entries[self::entryFor($sid)]);
    }

    /**
     * Fetches now, whatever the interval says. For tests, and for a caller that wants the
     * first poll to have happened before it starts serving.
     */
    public function refresh(): void
    {
        $fetched = $this->fetch();
        $this->lastAttempt = $this->now();
        if ($fetched !== null) {
            $this->entries = $fetched;
        }
        // On failure the previous set is deliberately left in place: a blip must not
        // un-revoke a session the guard already knows about.
    }

    private function now(): float
    {
        return $this->clock !== null ? ($this->clock)() : microtime(true);
    }

    /**
     * Refetches if the poll interval has elapsed since the last ATTEMPT.
     *
     * Attempt, not success: a feed that is down must not be retried on every request, which
     * would put the request path back on the network — the cost §10.4 exists to avoid.
     */
    private function refreshIfStale(): void
    {
        if ($this->lastAttempt !== null
            && ($this->now() - $this->lastAttempt) < (float) $this->pollIntervalSeconds
        ) {
            return;
        }

        $this->refresh();
    }

    /**
     * Performs one fetch. Null for every kind of failure, which the caller treats
     * identically — see the class docblock on why "unusable" must not collapse into
     * "empty".
     *
     * @return array<string,true>|null
     */
    private function fetch(): ?array
    {
        try {
            $response = $this->http->request('GET', $this->feedUrl);
        } catch (\Throwable) {
            return null;
        }

        if ($response->getStatusCode() !== 200) {
            return null;
        }

        $body = (string) $response->getBody();
        if (strlen($body) > self::MAX_BODY_BYTES) {
            return null;
        }

        try {
            $document = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        if (!is_array($document)) {
            return null;
        }

        $alg = $document['alg'] ?? null;
        if (!is_string($alg) || $alg !== self::SUPPORTED_ALG) {
            return null;
        }

        $revoked = $document['revoked'] ?? null;
        if (!is_array($revoked)) {
            return null;
        }

        if (count($revoked) > self::MAX_ENTRIES) {
            // The WHOLE set, not a truncation — see MAX_ENTRIES.
            return null;
        }

        $entries = [];
        foreach ($revoked as $entry) {
            if (!is_string($entry)) {
                return null;
            }
            if ($entry !== '') {
                $entries[$entry] = true;
            }
        }

        return $entries;
    }
}
