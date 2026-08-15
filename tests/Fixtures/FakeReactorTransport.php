<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Fixtures;

use Axiam\Sdk\Reactor\ReactorDelivery;
use Axiam\Sdk\Reactor\ReactorTransport;

/**
 * An in-memory {@see ReactorTransport} for the §22 runtime tests.
 *
 * It records what a reactor published and how many times it waited, and — like
 * the real adapter and the interface itself — it has no way to declare an
 * exchange, a queue or a binding (§22.1).
 */
final class FakeReactorTransport implements ReactorTransport
{
    /** @var list<array{queue: string, correlationId: string, body: string}> */
    public array $published = [];

    /** @var list<string> */
    public array $consumedQueues = [];

    public int $waits = 0;

    public bool $closed = false;

    public bool $failPublish = false;

    /** @var list<ReactorDelivery> */
    private array $pending;

    /** @var (callable(ReactorDelivery): void)|null */
    private $onDelivery = null;

    /** @param list<ReactorDelivery> $pending Deliveries handed over on successive waits. */
    public function __construct(array $pending = [], private readonly int $extraIdleTicks = 0)
    {
        $this->pending = $pending;
    }

    public function consume(string $queue, callable $onDelivery): void
    {
        $this->consumedQueues[] = $queue;
        $this->onDelivery = $onDelivery;
    }

    public function wait(float $timeoutSeconds): bool
    {
        ++$this->waits;

        if ($this->pending !== []) {
            $delivery = array_shift($this->pending);
            if ($this->onDelivery !== null) {
                ($this->onDelivery)($delivery);
            }

            return true;
        }

        // Idle ticks let a test exercise the loop's stop check before the session
        // is reported as ended.
        return $this->waits <= $this->extraIdleTicks;
    }

    public function publishReply(string $replyQueue, string $correlationId, string $body): void
    {
        if ($this->failPublish) {
            throw new \RuntimeException('broker refused the publication');
        }
        $this->published[] = ['queue' => $replyQueue, 'correlationId' => $correlationId, 'body' => $body];
    }

    public function close(): void
    {
        $this->closed = true;
    }
}
