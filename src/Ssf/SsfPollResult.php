<?php

declare(strict_types=1);

namespace Axiam\Sdk\Ssf;

/**
 * What {@see SsfReceiver::poll()} returns: the verified SETs and the refused ones, apart.
 */
final class SsfPollResult
{
    /**
     * @param list<SecurityEvent> $events        The SETs that verified, in the transmitter's order.
     * @param bool                $moreAvailable Whether the transmitter holds more.
     * @param list<RefusedSet>    $refused       The SETs that did not verify.
     */
    public function __construct(
        public readonly array $events,
        public readonly bool $moreAvailable,
        public readonly array $refused,
    ) {
    }
}
