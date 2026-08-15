<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Fixtures;

use Axiam\Sdk\Reactor\ReactorDelivery;

/**
 * An in-memory {@see ReactorDelivery} that records its own ack/nack, so the §22
 * runtime tests can assert the ack matrix without a broker.
 */
final class FakeReactorDelivery implements ReactorDelivery
{
    public int $acks = 0;

    public int $nacks = 0;

    public function __construct(
        private readonly string $body,
        private readonly string $replyTo = 'amq.rabbitmq.reply-to.reactor',
        private readonly string $correlationId = '22222222-2222-2222-2222-222222222222',
    ) {
    }

    public function body(): string
    {
        return $this->body;
    }

    public function replyTo(): string
    {
        return $this->replyTo;
    }

    public function correlationId(): string
    {
        return $this->correlationId;
    }

    public function ack(): void
    {
        ++$this->acks;
    }

    public function nack(): void
    {
        ++$this->nacks;
    }
}
