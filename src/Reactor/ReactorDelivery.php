<?php

declare(strict_types=1);

namespace Axiam\Sdk\Reactor;

/**
 * One message off the reactor's own queue (CONTRACT.md §22.1).
 */
interface ReactorDelivery
{
    /** The raw message bytes, exactly as received. */
    public function body(): string;

    /**
     * The reply queue named in the delivery's AMQP `reply_to` basic property —
     * standard AMQP RPC.
     *
     * What the SERVER authenticates is not this property but the
     * `correlation_id` INSIDE the signed reply body (§22.1); this only says where
     * to put it.
     */
    public function replyTo(): string;

    /**
     * The delivery's AMQP `correlation_id` basic property, echoed onto the reply
     * publication. Not the authenticated binding either — the one in the signed
     * body is.
     */
    public function correlationId(): string;

    /** Acknowledges the delivery. */
    public function ack(): void;

    /**
     * Negatively acknowledges the delivery WITHOUT requeue.
     *
     * There is no requeue parameter on purpose. A reactor's dispatch window is at
     * most five seconds (§22.8), so a redelivered event can only ever produce a
     * reply the server has already stopped reading — requeuing spends the broker's
     * effort to guarantee a late answer.
     */
    public function nack(): void;
}
