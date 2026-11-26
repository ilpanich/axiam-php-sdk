<?php

declare(strict_types=1);

namespace Axiam\Sdk\Amqp;

use PhpAmqpLib\Channel\AMQPChannel;
use PhpAmqpLib\Exception\AMQPTimeoutException;
use PhpAmqpLib\Message\AMQPMessage;

/**
 * {@see AuthzTransport} over a `php-amqplib` channel — the same library the SDK's §8
 * {@see Consumer} and §22 reactor transport use.
 */
final class AmqpLibAuthzTransport implements AuthzTransport
{
    private bool $closed = false;

    /** @param AMQPChannel $channel An open channel; the caller owns the connection. */
    public function __construct(private readonly AMQPChannel $channel)
    {
    }

    /** Declares the private, exclusive, auto-delete, broker-named reply queue and consumes it with manual ack. */
    public function declareReplyQueue(callable $onDelivery): string
    {
        // Empty name: the broker names it (`amq.gen-…`). Not passive, not durable, EXCLUSIVE (only
        // this connection may consume it), auto-delete (it goes with its consumer). §8 rule 5.
        $declared = $this->channel->queue_declare('', false, false, true, true);
        $queue = is_array($declared) ? (string) ($declared[0] ?? '') : '';

        // Manual acknowledgement, exclusive consumer.
        $this->channel->basic_consume(
            $queue,
            '',
            false,
            false,
            true,
            false,
            static function (AMQPMessage $message) use ($onDelivery): void {
                $onDelivery(new AmqpLibAuthzDelivery($message));
            },
        );

        return $queue;
    }

    /** Publishes on the default exchange with the given `reply_to` and `correlation_id`. */
    public function publishRequest(string $queue, string $replyTo, string $correlationId, string $body): void
    {
        $message = new AMQPMessage($body, [
            'content_type' => 'application/json',
            'correlation_id' => $correlationId,
            'reply_to' => $replyTo,
        ]);
        // Default exchange (""), routing key = the request queue.
        $this->channel->basic_publish($message, '', $queue);
    }

    /** Pumps the channel for at most `$timeoutSeconds`; `false` once the session is gone. */
    public function wait(float $timeoutSeconds): bool
    {
        if ($this->closed || !$this->channel->is_consuming()) {
            return false;
        }

        try {
            $this->channel->wait(null, false, $timeoutSeconds);
        } catch (AMQPTimeoutException) {
            return true; // idle tick
        } catch (\Throwable) {
            return false; // the session is gone
        }

        return true;
    }

    /** Closes the channel (idempotent); the connection stays the caller's. */
    public function close(): void
    {
        if ($this->closed) {
            return;
        }
        $this->closed = true;

        try {
            $this->channel->close();
        } catch (\Throwable) {
            // A channel the broker already closed is not worth surfacing from a cleanup path.
        }
    }
}
