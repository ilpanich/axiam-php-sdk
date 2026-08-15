<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Reactor\AmqpLibReactorDelivery;
use Axiam\Sdk\Reactor\AmqpLibReactorTransport;
use Axiam\Sdk\Reactor\ReactorDelivery;
use PhpAmqpLib\Channel\AMQPChannel;
use PhpAmqpLib\Connection\AbstractConnection;
use PhpAmqpLib\Exception\AMQPTimeoutException;
use PhpAmqpLib\Message\AMQPMessage;
use PHPUnit\Framework\TestCase;

/**
 * The `php-amqplib` adapter behind {@see AmqpLibReactorTransport}, driven against
 * a mocked channel so every branch is exercised without a broker.
 *
 * What this file is really asserting is CONTRACT.md §22.1: the adapter consumes a
 * queue the server already declared and publishes through the default exchange,
 * and there is no third thing it can do. The declare/bind source scan lives in
 * `ReactorRegistryTest`; this covers the behaviour the scan cannot see.
 */
final class ReactorTransportAdapterTest extends TestCase
{
    /** @return array{AmqpLibReactorTransport, AMQPChannel&\PHPUnit\Framework\MockObject\MockObject, AbstractConnection&\PHPUnit\Framework\MockObject\MockObject} */
    private function transport(): array
    {
        $channel = $this->createMock(AMQPChannel::class);
        $connection = $this->createMock(AbstractConnection::class);

        return [new AmqpLibReactorTransport($connection, $channel), $channel, $connection];
    }

    /**
     * Consume attaches to the SERVER-declared queue with manual acknowledgement,
     * and wraps each raw message as a {@see ReactorDelivery}.
     */
    public function testConsumeAttachesToTheQueueAndWrapsDeliveries(): void
    {
        [$transport, $channel] = $this->transport();
        $captured = null;

        $channel->expects(self::once())
            ->method('basic_consume')
            ->with(
                'axiam.reactor.q.tenant.reactor',
                'axiam-reactor',
                false, // no_local
                false, // NOT auto-ack: the runtime decides ack vs nack per §22
                false, // not exclusive
                false, // not no-wait
            )
            ->willReturnCallback(function (...$args) use (&$captured): string {
                $captured = $args[6];

                return 'consumer-tag';
            });

        $seen = [];
        $transport->consume(
            'axiam.reactor.q.tenant.reactor',
            static function (ReactorDelivery $delivery) use (&$seen): void {
                $seen[] = $delivery->body();
            },
        );

        self::assertIsCallable($captured);
        $captured(new AMQPMessage('{"event":"login.post_auth"}'));
        self::assertSame(['{"event":"login.post_auth"}'], $seen);
    }

    /**
     * `wait()` reports the session state: a timeout is an idle tick (true), a
     * broker error or a channel that stopped consuming is the end (false).
     *
     * There is no in-SDK reconnect loop behind that false — the worker returns and
     * a process supervisor restarts it, the same posture this SDK's §8 consumer
     * documents.
     */
    public function testWaitDistinguishesAnIdleTickFromTheEndOfTheSession(): void
    {
        [$transport, $channel] = $this->transport();
        $channel->method('is_consuming')->willReturn(true);
        $channel->method('wait')->willReturnOnConsecutiveCalls(
            null,
            self::throwException(new AMQPTimeoutException('idle')),
            self::throwException(new \RuntimeException('broker went away')),
        );

        self::assertTrue($transport->wait(1.0), 'a delivered message keeps the loop running');
        self::assertTrue($transport->wait(1.0), 'a timeout is an idle tick, not an end');
        self::assertFalse($transport->wait(1.0), 'a broker failure ends the session');
    }

    /** A channel that is no longer consuming ends the loop without waiting. */
    public function testWaitReturnsFalseWhenTheChannelStoppedConsuming(): void
    {
        [$transport, $channel] = $this->transport();
        $channel->method('is_consuming')->willReturn(false);
        $channel->expects(self::never())->method('wait');

        self::assertFalse($transport->wait(1.0));
    }

    /** A closed transport never waits again. */
    public function testWaitReturnsFalseOnceClosed(): void
    {
        [$transport, $channel] = $this->transport();
        $channel->method('is_consuming')->willReturn(true);

        $transport->close();

        self::assertFalse($transport->wait(1.0));
    }

    /**
     * §22.1: the reply goes to the default exchange with the routing key set to
     * the queue `reply_to` named — standard AMQP RPC, and the one publication a
     * reactor makes.
     */
    public function testPublishReplyUsesTheDefaultExchange(): void
    {
        [$transport, $channel] = $this->transport();

        $channel->expects(self::once())
            ->method('basic_publish')
            ->willReturnCallback(static function (AMQPMessage $message, string $exchange, string $routingKey): void {
                self::assertSame('', $exchange, 'a reactor never publishes to a declared exchange');
                self::assertSame('amq.rabbitmq.reply-to.abc', $routingKey);
                self::assertSame('{"decision":"allow"}', $message->getBody());
                self::assertSame('application/json', $message->get('content_type'));
                self::assertSame('corr-1', $message->get('correlation_id'));
            });

        $transport->publishReply('amq.rabbitmq.reply-to.abc', 'corr-1', '{"decision":"allow"}');
    }

    /** Close is idempotent (§18.1 rule 2) and survives a broker that already hung up. */
    public function testCloseIsIdempotentAndSwallowsCleanupFailures(): void
    {
        [$transport, $channel, $connection] = $this->transport();
        $channel->expects(self::once())->method('close')->willThrowException(new \RuntimeException('already closed'));
        $connection->expects(self::once())->method('close')->willThrowException(new \RuntimeException('already closed'));

        $transport->close();
        $transport->close();

        self::assertFalse($transport->wait(1.0));
    }

    /**
     * The delivery adapter's ack/nack matrix. A nack never requeues: a reactor's
     * dispatch window is at most five seconds (§22.8), so a redelivered event can
     * only ever produce a reply the server has stopped reading.
     */
    public function testDeliveryAcksAndNacksWithoutRequeue(): void
    {
        $channel = $this->createMock(AMQPChannel::class);
        $channel->expects(self::once())->method('basic_ack')->with(7, false);
        $channel->expects(self::once())->method('basic_nack')->with(9, false, false);

        $acked = new AMQPMessage('{}');
        $acked->setChannel($channel);
        $acked->setDeliveryTag(7);
        (new AmqpLibReactorDelivery($acked))->ack();

        $nacked = new AMQPMessage('{}');
        $nacked->setChannel($channel);
        $nacked->setDeliveryTag(9);
        (new AmqpLibReactorDelivery($nacked))->nack();
    }

    /**
     * §8b end to end: `connect()` refuses a plaintext URL before it opens a socket,
     * and on an `amqps://` URL it builds a TLS-verifying configuration and attempts
     * a real connection — which is what proves the dial path is wired rather than
     * only the URL parser.
     */
    public function testConnectRefusesPlaintextAndDialsTlsOtherwise(): void
    {
        try {
            AmqpLibReactorTransport::connect('amqp://127.0.0.1:5672');
            self::fail('a plaintext AMQP URL must be refused (§8b)');
        } catch (\InvalidArgumentException $error) {
            self::assertStringContainsString('amqps://', $error->getMessage());
        }

        // Port 1 has nothing listening, so the dial is refused immediately. The
        // point is that it got as far as dialling: every configuration statement
        // above the connection ran, and none of them was a verification-skip.
        $this->expectException(\Exception::class);
        AmqpLibReactorTransport::connect('amqps://reactor:s3cret@127.0.0.1:1/tenant-a', null, 5, 1);
    }
}
