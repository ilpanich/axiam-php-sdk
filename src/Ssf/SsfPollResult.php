<?php

declare(strict_types=1);

namespace Axiam\Sdk\Ssf;

/**
 * What {@see SsfReceiver::poll()} returns: the verified SETs and the refused ones, apart — and
 * the ones it could not judge.
 *
 * A SET is **unjudged** when a failure that is not a verdict on it — a JWKS or configuration
 * fetch that fails, a replay store that cannot answer — stopped `poll()` before it reached a
 * verdict (CONTRACT.md §32.7, §34.2 P1 and P3). An unjudged SET is in neither `events` nor
 * `refused`, its `jti` was not recorded, and you neither acknowledge it nor report it in
 * `setErrs`: the transmitter offers it again, and a later poll judges it.
 */
final class SsfPollResult
{
    /**
     * @param list<SecurityEvent> $events        The SETs that verified, in the transmitter's order.
     *                                           Every `jti` the replay store recorded is here.
     * @param bool                $moreAvailable Whether the transmitter holds more.
     * @param list<RefusedSet>    $refused       The SETs that did not verify.
     * @param list<string>        $unjudged      The `jti`s (the poll map keys) of the SETs that
     *                                           were not judged, in the transmitter's order;
     *                                           empty when every SET was.
     * @param \Throwable|null     $unjudgedCause The failure that left them unjudged — a
     *                                           {@see \Axiam\Sdk\Core\NetworkError} for a key
     *                                           fetch, or the replay store's own exception —
     *                                           `null` when `$unjudged` is empty.
     */
    public function __construct(
        public readonly array $events,
        public readonly bool $moreAvailable,
        public readonly array $refused,
        public readonly array $unjudged = [],
        public readonly ?\Throwable $unjudgedCause = null,
    ) {
    }
}
