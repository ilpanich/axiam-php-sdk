<?php

declare(strict_types=1);

namespace Axiam\Sdk\Amqp;

/**
 * One message read from the authorization requester's private reply queue, with the two
 * ways a consumer can settle it (CONTRACT.md §8 "Signed authorization responses"). A seam
 * so {@see AuthzRequester} can be driven without a broker.
 */
interface AuthzDelivery
{
    /** The delivery body, byte for byte as the broker handed it over. */
    public function body(): string;

    /** Acknowledges the delivery (an accepted, verified response). */
    public function ack(): void;

    /** Rejects the delivery WITHOUT requeue (a response that failed verification or binding). */
    public function nackNoRequeue(): void;
}
