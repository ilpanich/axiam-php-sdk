<?php

declare(strict_types=1);

namespace Axiam\Sdk\Amqp;

use PhpAmqpLib\Message\AMQPMessage;

/** Adapts a `php-amqplib` {@see AMQPMessage} to {@see AuthzDelivery}. */
final class AmqpLibAuthzDelivery implements AuthzDelivery
{
    /** @param AMQPMessage $message The delivery as `php-amqplib` handed it over. */
    public function __construct(private readonly AMQPMessage $message)
    {
    }

    /** The delivery body, byte for byte as the broker handed it over. */
    public function body(): string
    {
        return $this->message->getBody();
    }

    /** Acknowledges the delivery. */
    public function ack(): void
    {
        $this->message->ack();
    }

    /** Rejects the delivery without requeue. */
    public function nackNoRequeue(): void
    {
        $this->message->nack(false);
    }
}
