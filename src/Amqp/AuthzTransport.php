<?php

declare(strict_types=1);

namespace Axiam\Sdk\Amqp;

/**
 * The seam between {@see AuthzRequester} and a broker: it declares the requester's private
 * reply queue, publishes requests, and pumps deliveries. {@see AmqpLibAuthzTransport} is the
 * `php-amqplib` implementation; tests supply a fake.
 */
interface AuthzTransport
{
    /**
     * Declares an EXCLUSIVE, auto-delete, broker-named queue only this requester consumes (an
     * `amq.gen-…` queue) and starts consuming it with manual acknowledgement, handing every
     * delivery to `$onDelivery`. Returns the queue's name.
     *
     * @param callable(AuthzDelivery): void $onDelivery
     */
    public function declareReplyQueue(callable $onDelivery): string;

    /**
     * Publishes `$body` on the DEFAULT exchange with routing key `$queue`, AMQP `reply_to` =
     * `$replyTo` and `correlation_id` = `$correlationId`.
     */
    public function publishRequest(string $queue, string $replyTo, string $correlationId, string $body): void;

    /**
     * Blocks until at least one delivery has been dispatched to the callback given to
     * {@see self::declareReplyQueue()}, or `$timeoutSeconds` elapses (a timeout returns
     * `true`: an idle tick, not an end). Returns `false` once the session has gone away.
     */
    public function wait(float $timeoutSeconds): bool;

    /** Releases the session. Idempotent. */
    public function close(): void;
}
