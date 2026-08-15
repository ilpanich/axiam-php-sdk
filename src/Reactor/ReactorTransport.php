<?php

declare(strict_types=1);

namespace Axiam\Sdk\Reactor;

/**
 * One live broker session for a reactor: a consumer on the reactor's own queue,
 * and a way to publish a reply back to the queue the delivery named
 * (CONTRACT.md §22.1, §8b).
 *
 * ACTORS CONSUME; THEY NEVER DECLARE TOPOLOGY. The server declares the exchange,
 * the per-reactor queue and the bindings from the registration's `events`. That
 * rule is enforced here **by the shape of this interface** rather than by a review
 * comment: there is a `consume` method and a `publishReply` method and **no
 * declare or bind method at all**, so there is nowhere in this package for an
 * exchange, queue or binding declaration to live.
 *
 * This is not tidiness. A reactor that can bind is a reactor that can bind itself
 * to `*.token.pre_issue` and read another tenant's issuance events. Refusing to
 * hold that capability at all is cheaper than proving each actor does not misuse
 * it.
 */
interface ReactorTransport
{
    /**
     * Starts consuming `$queue`, invoking `$onDelivery` once per message.
     *
     * `$queue` is only ever the queue the SERVER declared for THIS reactor. The
     * transport attaches to it; it does not create it.
     *
     * @param callable(ReactorDelivery): void $onDelivery
     */
    public function consume(string $queue, callable $onDelivery): void;

    /**
     * Blocks until at least one delivery has been dispatched to the consume
     * callback, or `$timeoutSeconds` elapses.
     *
     * Returns false once the session has ended, which is what tells the runtime to
     * stop. `php-amqplib` has no built-in reconnection, so a returning session is
     * the signal for a process supervisor to restart the worker — the same posture
     * this SDK's §8 consumer already documents.
     */
    public function wait(float $timeoutSeconds): bool;

    /**
     * Publishes `$body` to `$replyQueue` via the default exchange, echoing
     * `$correlationId` onto the AMQP property (§22.1).
     *
     * The default exchange exists on every broker and needs no declaration, which
     * is why a reply can be published without the transport ever declaring
     * anything.
     */
    public function publishReply(string $replyQueue, string $correlationId, string $body): void;

    /** Releases the session. Must be idempotent (§18.1 rule 2). */
    public function close(): void;
}
