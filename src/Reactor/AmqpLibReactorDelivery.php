<?php

declare(strict_types=1);

namespace Axiam\Sdk\Reactor;

use PhpAmqpLib\Message\AMQPMessage;

/**
 * Adapts a `php-amqplib` {@see AMQPMessage} to {@see ReactorDelivery}
 * (CONTRACT.md §22.1).
 */
final class AmqpLibReactorDelivery implements ReactorDelivery
{
    /**
     * @param AMQPMessage $message The delivery as `php-amqplib` handed it over.
     */
    public function __construct(private readonly AMQPMessage $message)
    {
    }

    /** {@inheritDoc} */
    public function body(): string
    {
        return $this->message->getBody();
    }

    /** {@inheritDoc} */
    public function replyTo(): string
    {
        return (string) ($this->property('reply_to') ?? '');
    }

    /** {@inheritDoc} */
    public function correlationId(): string
    {
        return (string) ($this->property('correlation_id') ?? '');
    }

    /** {@inheritDoc} */
    public function ack(): void
    {
        $this->message->ack();
    }

    /** {@inheritDoc} */
    public function nack(): void
    {
        // No requeue: a reactor's dispatch window is at most five seconds, so a
        // redelivered event can only ever produce an answer the server has already
        // stopped reading.
        $this->message->nack(false);
    }

    private function property(string $name): mixed
    {
        return $this->message->has($name) ? $this->message->get($name) : null;
    }
}
