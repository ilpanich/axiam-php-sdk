<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

use Axiam\Sdk\Rest\AccessDecision;

/**
 * Client-side decision memo — CONTRACT.md §17.
 *
 * **Disabled by default.** §11.2 rule 6's ban on caching allow/deny decisions is
 * still the default behaviour; this is the single opt-in exception that section
 * carves out, and a caller has to switch it on having read the cost.
 *
 * ## What it costs
 *
 * The staleness bound is the TTL, **in both directions**. A grant revoked on the
 * server can still read as allowed for up to the TTL, and a grant just added can
 * still read as denied for up to the TTL. That second direction is the one that
 * surprises people: **reads-your-own-writes is not guaranteed.** An admin UI that
 * grants a role and immediately re-checks is the case that breaks, and it breaks
 * silently.
 *
 * This mirrors the server's own bound rather than inventing a second staleness
 * story — `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` (default 5s) makes the same
 * trade server-side. One deliberate difference: the server's setting is an
 * unclamped integer, so an operator can configure a multi-hour staleness window.
 * {@see DecisionMemo::MAX_TTL_MS} clamps this one at 5s, because the client has no
 * reason to repeat that.
 *
 * No lock: PHP's shared-nothing request model means one client instance is not
 * shared across concurrent requests the way a Go or Java client is, so the
 * cross-thread hazard the other SDKs guard against does not arise here. This memo
 * lives and dies with the request that built the client.
 */
final class DecisionMemo
{
    /**
     * The §17.1 rule 2 ceiling, in milliseconds. A configured TTL above this is
     * clamped, not rejected: a caller who asked for a minute wants caching, and
     * silently giving them the maximum safe value beats failing construction.
     */
    public const MAX_TTL_MS = 5000.0;

    /**
     * Entry cap before FIFO eviction (§17.1 rule 8). The memo is a latency
     * optimisation, so dropping an entry is always correct — but it must drop
     * rather than grow without bound.
     */
    public const MAX_ENTRIES = 1024;

    /**
     * Joins the key components. U+001F (unit separator) cannot appear in an action,
     * a UUID or a scope, so no combination of caller-supplied values can forge a
     * collision.
     */
    private const SEP = "\x1F";

    /**
     * Marks an absent optional, which is why an absent scope can never collide with
     * a present one — a memo that let them collide would answer a narrower question
     * with a broader answer.
     */
    private const ABSENT = "\x00";

    private readonly float $ttlMs;

    /** @var array<string, array{decision: AccessDecision, storedAt: float}> */
    private array $entries = [];

    /** @var callable(): float */
    private $clock;

    /**
     * @param float                    $ttlMs Requested TTL in milliseconds; `0.0` or less
     *                                        disables the memo, and anything above
     *                                        {@see DecisionMemo::MAX_TTL_MS} is clamped to it.
     * @param (callable(): float)|null $clock Injected millisecond clock, so the TTL can
     *                                        be tested without waiting.
     */
    public function __construct(float $ttlMs = 0.0, ?callable $clock = null)
    {
        $this->ttlMs = $ttlMs <= 0.0 ? 0.0 : min($ttlMs, self::MAX_TTL_MS);
        $this->clock = $clock ?? static fn (): float => hrtime(true) / 1_000_000.0;
    }

    /**
     * Whether this memo does anything. `false` for the default configuration.
     */
    public function enabled(): bool
    {
        return $this->ttlMs > 0.0;
    }

    /**
     * The TTL after clamping, in milliseconds.
     */
    public function effectiveTtlMs(): float
    {
        return $this->ttlMs;
    }

    /**
     * Builds the §17.1 rule 3 key: all four components, absent distinguished from
     * present.
     */
    public static function key(
        ?string $subjectId,
        string $resourceId,
        string $action,
        ?string $scope,
    ): string {
        return implode(self::SEP, [
            $subjectId ?? self::ABSENT,
            $resourceId,
            $action,
            $scope ?? self::ABSENT,
        ]);
    }

    /**
     * A live decision for `$key`, if one is memoized and unexpired.
     */
    public function get(string $key): ?AccessDecision
    {
        if (!$this->enabled()) {
            return null;
        }

        $entry = $this->entries[$key] ?? null;
        if ($entry === null) {
            return null;
        }

        if (($this->clock)() - $entry['storedAt'] >= $this->ttlMs) {
            unset($this->entries[$key]);

            return null;
        }

        // Returned whole, including the reason code: §17.1 rule 5 forbids returning
        // `allowed` while dropping the code, which would make the field
        // intermittently absent — worse than never having had it.
        return $entry['decision'];
    }

    /**
     * Memoizes a decision the server actually returned.
     *
     * Callers must only reach here on success. §17.1 rule 7 forbids negative-caching
     * a failure: memoizing a transport error as a deny would turn a blip into a
     * TTL-long outage, and memoizing it as an allow is unthinkable.
     */
    public function put(string $key, AccessDecision $decision): void
    {
        if (!$this->enabled()) {
            return;
        }

        // Unset first so re-inserting moves the key to the end of PHP's insertion
        // order, which is what makes the eviction below FIFO.
        unset($this->entries[$key]);
        $this->entries[$key] = ['decision' => $decision, 'storedAt' => ($this->clock)()];

        while (\count($this->entries) > self::MAX_ENTRIES) {
            $oldest = array_key_first($this->entries);
            if ($oldest === null) {
                break;
            }
            unset($this->entries[$oldest]);
        }
    }

    /**
     * Drops every entry (§17.1 rule 9).
     *
     * Called on login, verifyMfa, refresh and logout. Entries are keyed by subject,
     * not by session, so a re-authentication as a *different* principal would
     * otherwise read the previous principal's decisions.
     */
    public function clear(): void
    {
        $this->entries = [];
    }

    /**
     * Emits a {@see ConfigClampedEvent} if the requested TTL was clamped
     * (CONTRACT.md §19.2 rule 6).
     *
     * This is the clamp that matters most to get right: an operator who set a
     * 60-second TTL believes their staleness bound is 60 seconds. It is five, and
     * without this event nothing anywhere says so.
     *
     * Nothing is emitted when the requested value was already inside the limit, or
     * when the memo is disabled — an event that fires when nothing happened trains
     * its reader to ignore it.
     */
    public function reportClamp(float $requestedMs, TelemetryDispatcher $telemetry): void
    {
        if (!$telemetry->installed() || $requestedMs <= 0.0 || $requestedMs === $this->ttlMs) {
            return;
        }

        $telemetry->emit(new ConfigClampedEvent(
            'decisionMemoTtlMs',
            (string) $requestedMs,
            (string) $this->ttlMs,
            '§17.1 rule 2',
        ));
    }

    /**
     * Entry count, for tests.
     */
    public function count(): int
    {
        return \count($this->entries);
    }
}
