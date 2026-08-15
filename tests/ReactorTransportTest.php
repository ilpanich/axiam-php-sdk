<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Reactor\AmqpLibReactorDelivery;
use Axiam\Sdk\Reactor\AmqpLibReactorTransport;
use PhpAmqpLib\Message\AMQPMessage;
use PHPUnit\Framework\TestCase;

/**
 * CONTRACT.md §8b (the reactor transport is TLS, with no verification-skip
 * switch) and §22.1 (a delivery's reply addressing).
 */
final class ReactorTransportTest extends TestCase
{
    /**
     * §8b: a plaintext URL is REFUSED rather than downgraded, because a fallback
     * that works is a fallback that gets used. HMAC does not substitute for TLS
     * and TLS does not substitute for HMAC.
     *
     * @dataProvider insecureUrlProvider
     */
    public function testNonAmqpsUrlsAreRefused(string $url): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/amqps|valid URL/');
        AmqpLibReactorTransport::parseAmqpsUrl($url);
    }

    /** @return array<string, array{string}> */
    public static function insecureUrlProvider(): array
    {
        return [
            'plaintext amqp' => ['amqp://guest:guest@broker.example:5672'],
            'http' => ['http://broker.example'],
            'no scheme' => ['broker.example:5671'],
            'empty' => [''],
        ];
    }

    /**
     * The URL split `php-amqplib` needs, including the default AMQPS port and the
     * percent-decoded vhost.
     *
     * @dataProvider amqpsUrlProvider
     *
     * @param array{host: string, port: int, user: string, pass: string, vhost: string} $expected
     */
    public function testAmqpsUrlIsSplitForTheBrokerClient(string $url, array $expected): void
    {
        self::assertSame($expected, AmqpLibReactorTransport::parseAmqpsUrl($url));
    }

    /** @return array<string, array{string, array{host: string, port: int, user: string, pass: string, vhost: string}}> */
    public static function amqpsUrlProvider(): array
    {
        return [
            'full' => [
                'amqps://reactor:s3cret@broker.example:5673/tenant-a',
                ['host' => 'broker.example', 'port' => 5673, 'user' => 'reactor', 'pass' => 's3cret', 'vhost' => 'tenant-a'],
            ],
            'defaults' => [
                'amqps://broker.example',
                ['host' => 'broker.example', 'port' => AmqpLibReactorTransport::DEFAULT_AMQPS_PORT, 'user' => 'guest', 'pass' => 'guest', 'vhost' => '/'],
            ],
            'root vhost' => [
                'amqps://broker.example/',
                ['host' => 'broker.example', 'port' => AmqpLibReactorTransport::DEFAULT_AMQPS_PORT, 'user' => 'guest', 'pass' => 'guest', 'vhost' => '/'],
            ],
            'percent-encoded vhost' => [
                'amqps://broker.example/%2Fshared',
                ['host' => 'broker.example', 'port' => AmqpLibReactorTransport::DEFAULT_AMQPS_PORT, 'user' => 'guest', 'pass' => 'guest', 'vhost' => '/shared'],
            ],
            'uppercase scheme' => [
                'AMQPS://broker.example',
                ['host' => 'broker.example', 'port' => AmqpLibReactorTransport::DEFAULT_AMQPS_PORT, 'user' => 'guest', 'pass' => 'guest', 'vhost' => '/'],
            ],
        ];
    }

    /**
     * §22.1's reply addressing, read off the delivery: `reply_to` says where to
     * put the reply and `correlation_id` is echoed onto the publication. Neither
     * is what the server authenticates — the correlation inside the signed body
     * is — but a delivery that carries neither must still read cleanly.
     */
    public function testDeliveryReadsItsReplyProperties(): void
    {
        $withProperties = new AmqpLibReactorDelivery(new AMQPMessage('{"a":1}', [
            'reply_to' => 'amq.rabbitmq.reply-to.abc',
            'correlation_id' => '22222222-2222-2222-2222-222222222222',
        ]));

        self::assertSame('{"a":1}', $withProperties->body());
        self::assertSame('amq.rabbitmq.reply-to.abc', $withProperties->replyTo());
        self::assertSame('22222222-2222-2222-2222-222222222222', $withProperties->correlationId());

        $bare = new AmqpLibReactorDelivery(new AMQPMessage('{}'));
        self::assertSame('', $bare->replyTo());
        self::assertSame('', $bare->correlationId());
        self::assertSame('{}', $bare->body());
    }
}
