<?php

declare(strict_types=1);

namespace Axiam\Sdk\Reactor;

use PhpAmqpLib\Channel\AMQPChannel;
use PhpAmqpLib\Connection\AbstractConnection;
use PhpAmqpLib\Connection\AMQPConnectionConfig;
use PhpAmqpLib\Connection\AMQPConnectionFactory;
use PhpAmqpLib\Exception\AMQPTimeoutException;
use PhpAmqpLib\Message\AMQPMessage;

/**
 * The `php-amqplib` implementation of {@see ReactorTransport} (CONTRACT.md §22.1,
 * §8b).
 *
 * It declares nothing: {@see self::consume()} attaches to a queue the server
 * already declared, and {@see self::publishReply()} publishes to the default
 * exchange, which exists on every broker and needs no declaration. No declare or
 * bind call appears anywhere in this class, and `ReactorRegistryTest` asserts that
 * with a source scan as well as through the shape of the interface.
 *
 * TLS is mandatory (§8b): {@see self::connect()} refuses anything that is not an
 * `amqps://` URL rather than downgrading, because a fallback that works is a
 * fallback that gets used. Peer and peer-name verification are always on and there
 * is no switch anywhere in this SDK that turns them off — HMAC does not substitute
 * for TLS and TLS does not substitute for HMAC.
 *
 * RECONNECTION IS THE SUPERVISOR'S JOB, exactly as it already is for this SDK's §8
 * consumer: `php-amqplib` has no built-in automatic reconnection, so when the
 * session ends {@see self::wait()} returns false, the runtime returns, and the
 * worker process exits for systemd / Kubernetes / supervisord to restart. A
 * heartbeat is negotiated so a half-open connection becomes a closed session
 * rather than a reactor sitting silently attached to a socket nobody is on the
 * other end of.
 */
final class AmqpLibReactorTransport implements ReactorTransport
{
    /** The AMQPS port a URL that names none falls back to. */
    public const DEFAULT_AMQPS_PORT = 5671;

    private bool $closed = false;

    /**
     * @param AbstractConnection $connection The live broker connection this transport owns and
     *                                       closes.
     * @param AMQPChannel        $channel    The session channel. Its QoS is the caller's to set;
     *                                       {@see self::connect()} does it.
     */
    public function __construct(
        private readonly AbstractConnection $connection,
        private readonly AMQPChannel $channel,
    ) {
    }

    /**
     * Splits an `amqps://` URL into the parts `php-amqplib` wants, refusing
     * anything else (§8b).
     *
     * A plaintext `amqp://` URL is refused rather than downgraded. Exposed as a
     * separate method so the refusal is directly testable without a broker.
     *
     * @return array{host: string, port: int, user: string, pass: string, vhost: string}
     *
     * @throws \InvalidArgumentException when the URL is not `amqps://`, or is unparseable.
     */
    public static function parseAmqpsUrl(string $url): array
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            throw new \InvalidArgumentException('axiam: reactor AMQP URL is not a valid URL');
        }
        if (strtolower((string) $parts['scheme']) !== 'amqps') {
            throw new \InvalidArgumentException(
                'axiam: reactor AMQP URL must use amqps:// (CONTRACT.md §8b) — TLS is not optional across a trust boundary',
            );
        }

        $path = $parts['path'] ?? '';
        $vhost = ($path === '' || $path === '/') ? '/' : rawurldecode(substr($path, 1));

        return [
            'host' => (string) $parts['host'],
            'port' => (int) ($parts['port'] ?? self::DEFAULT_AMQPS_PORT),
            'user' => rawurldecode((string) ($parts['user'] ?? 'guest')),
            'pass' => rawurldecode((string) ($parts['pass'] ?? 'guest')),
            'vhost' => $vhost,
        ];
    }

    /**
     * Connects to `$url` over TLS and opens the session channel.
     *
     * @param string      $url       An `amqps://` URL. Anything else is refused (§8b).
     * @param string|null $caFile    PEM CA bundle to verify the broker against. Omitting it uses
     *                               the host's trust store. This is the ONLY TLS-related knob:
     *                               there is no option here or anywhere else in this SDK that
     *                               weakens or disables verification.
     * @param int         $heartbeat AMQP heartbeat interval in seconds. The heartbeat is how a
     *                               half-open connection becomes a closed session, which is what
     *                               lets the supervisor restart the worker instead of leaving it
     *                               deaf.
     * @param int         $prefetch  QoS prefetch. Low by default: a reactor's dispatch window is
     *                               at most five seconds, so buffering deliveries only guarantees
     *                               late answers.
     *
     * @throws \InvalidArgumentException when `$url` is not `amqps://`.
     */
    public static function connect(
        string $url,
        ?string $caFile = null,
        int $heartbeat = 10,
        int $prefetch = 1,
    ): self {
        $parts = self::parseAmqpsUrl($url);

        $config = new AMQPConnectionConfig();
        $config->setIsSecure(true);
        $config->setHost($parts['host']);
        $config->setPort($parts['port']);
        $config->setUser($parts['user']);
        $config->setPassword($parts['pass']);
        $config->setVhost($parts['vhost']);
        $config->setHeartbeat($heartbeat);
        // §8b: verification is always on, and there is no branch here that turns
        // it off. A TLS 1.2 floor is the lowest php-amqplib's stream layer will
        // negotiate; the broker side pins TLS 1.3 where it is available.
        $config->setSslVerify(true);
        $config->setSslVerifyName(true);
        if ($caFile !== null) {
            $config->setSslCaCert($caFile);
        }

        $connection = AMQPConnectionFactory::create($config);
        $channel = $connection->channel();
        $channel->basic_qos(0, $prefetch, false);

        return new self($connection, $channel);
    }

    /**
     * Attaches a consumer to `$queue` — the queue the SERVER declared for this
     * reactor. Nothing is declared or bound here (§22.1).
     *
     * @param callable(ReactorDelivery): void $onDelivery
     */
    public function consume(string $queue, callable $onDelivery): void
    {
        $this->channel->basic_consume(
            $queue,
            'axiam-reactor',
            false,
            false,
            false,
            false,
            static function (AMQPMessage $message) use ($onDelivery): void {
                $onDelivery(new AmqpLibReactorDelivery($message));
            },
        );
    }

    /**
     * Blocks for at most `$timeoutSeconds`, returning false once the session has
     * ended.
     *
     * A timeout is an idle tick, not an end: it returns true so the runtime can
     * check whether it has been asked to stop and then wait again.
     */
    public function wait(float $timeoutSeconds): bool
    {
        if ($this->closed || !$this->channel->is_consuming()) {
            return false;
        }

        try {
            $this->channel->wait(null, false, $timeoutSeconds);
        } catch (AMQPTimeoutException) {
            return true;
        } catch (\Throwable) {
            // The session is gone. There is no in-SDK reconnect loop: the worker
            // exits and the process supervisor restarts it.
            return false;
        }

        return true;
    }

    /**
     * Publishes `$body` to `$replyQueue` through the default exchange — the one
     * publication a reactor makes.
     */
    public function publishReply(string $replyQueue, string $correlationId, string $body): void
    {
        $message = new AMQPMessage($body, [
            'content_type' => 'application/json',
            'correlation_id' => $correlationId,
        ]);
        // Default exchange (""), routing key = the queue named by reply_to.
        // Standard AMQP RPC, and no declaration required.
        $this->channel->basic_publish($message, '', $replyQueue);
    }

    /** Closes the channel and the connection. Idempotent (§18.1 rule 2). */
    public function close(): void
    {
        if ($this->closed) {
            return;
        }
        $this->closed = true;

        try {
            $this->channel->close();
        } catch (\Throwable) {
            // A channel the broker already closed is not a failure worth
            // surfacing from a cleanup path.
        }

        try {
            $this->connection->close();
        } catch (\Throwable) {
            // Same.
        }
    }
}
