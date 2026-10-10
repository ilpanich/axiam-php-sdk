<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

/**
 * Emitted when `ssf.poll` returns normally leaving at least one SET unjudged (CONTRACT.md
 * §19.1, contract 1.60; §34.2 P1).
 *
 * An unjudged SET raises nothing: `poll()` returns what it judged and the transmitter offers the
 * rest again. Without this event a JWKS or replay-store outage would be invisible to the caller
 * for as long as some SET of each batch still verifies. It carries a count and a category —
 * never a `jti`, never a SET.
 */
final class SsfUnjudgedEvent extends TelemetryEvent
{
    /** A JWKS or SSF configuration fetch failed (or failed less than a minute ago). */
    public const CATEGORY_KEY_FETCH = 'key_fetch';

    /** The replay store could not answer. */
    public const CATEGORY_REPLAY_STORE = 'replay_store';

    /**
     * @param string $operation The operation name, `ssf.poll`.
     * @param int    $unjudged  How many SETs of the batch were left unjudged.
     * @param string $category  What left them unjudged: {@see self::CATEGORY_KEY_FETCH} or
     *                          {@see self::CATEGORY_REPLAY_STORE}.
     */
    public function __construct(
        public readonly string $operation,
        public readonly int $unjudged,
        public readonly string $category,
    ) {
    }
}
