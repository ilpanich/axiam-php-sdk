<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Reactor\ReactorAnswer;
use Axiam\Sdk\Reactor\ReactorConfig;
use Axiam\Sdk\Reactor\ReactorEvent;
use Axiam\Sdk\Reactor\ReactorEvents;
use Axiam\Sdk\Reactor\ReactorProtocol;
use Axiam\Sdk\Reactor\ReactorRejection;
use Axiam\Sdk\Reactor\ReactorServer;
use Axiam\Sdk\Reactor\ReactorTelemetryEvent;
use Axiam\Sdk\Tests\Fixtures\FakeReactorDelivery;
use Axiam\Sdk\Tests\Fixtures\FakeReactorTransport;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;

/**
 * CONTRACT.md §22.10's four rules on the runtime helper, §22.13's "Runtime"
 * requirements, and the §19 telemetry that makes a `fail_open` non-answer visible
 * at all.
 */
final class ReactorRuntimeTest extends TestCase
{
    private const TENANT = '11111111-1111-1111-1111-111111111111';
    private const REACTOR = '99999999-9999-9999-9999-999999999999';
    private const CORRELATION = '22222222-2222-2222-2222-222222222222';
    private const SUBKEY_HEX = '919e125ec83799c1e113a27707cac5008a2608d0557e00dfe1b3a316abed4b89';

    private int $now = 1783080000; // a fixed instant; every test signs against it

    private function subkey(): string
    {
        $key = hex2bin(self::SUBKEY_HEX);
        self::assertIsString($key);

        return $key;
    }

    private function config(string $mode = ReactorEvents::MODE_INTERCEPT): ReactorConfig
    {
        return new ReactorConfig(
            tenantId: self::TENANT,
            signingKey: new Sensitive($this->subkey()),
            reactorId: self::REACTOR,
            mode: $mode,
        );
    }

    /**
     * Signs an event the way the server would, so the runtime under test has
     * something authentic to verify.
     *
     * @param array<string, mixed> $payload
     */
    private function signedEvent(
        string $event = ReactorEvents::LOGIN_POST_AUTH,
        array $payload = ['sub' => 'alice'],
        int $timeoutMs = 500,
        ?string $nonce = null,
        ?int $issuedAt = null,
        ?string $tenantId = null,
    ): string {
        $body = new \stdClass();
        $body->tenant_id = $tenantId ?? self::TENANT;
        $body->event = $event;
        $body->correlation_id = self::CORRELATION;
        $body->payload = (object) $payload;
        $body->timeout_ms = $timeoutMs;
        $body->key_version = ReactorProtocol::KEY_VERSION;
        $body->nonce = $nonce ?? bin2hex(random_bytes(8));
        $body->issued_at = gmdate('Y-m-d\TH:i:s\Z', $issuedAt ?? $this->now);
        $body->hmac_signature = null;
        $body->hmac_signature = ReactorProtocol::sign($this->subkey(), ReactorProtocol::canonicalize($body));

        return ReactorProtocol::canonicalize($body);
    }

    /**
     * @param callable(ReactorEvent): ReactorAnswer $handler
     * @param list<ReactorTelemetryEvent>           $telemetry
     */
    private function server(
        FakeReactorTransport $transport,
        callable $handler,
        array &$telemetry,
        ?ReactorConfig $config = null,
        ?\Psr\Log\LoggerInterface $logger = null,
    ): ReactorServer {
        return new ReactorServer(
            config: $config ?? $this->config(),
            transport: $transport,
            handler: $handler,
            logger: $logger ?? new \Psr\Log\NullLogger(),
            telemetryHook: function (ReactorTelemetryEvent $event) use (&$telemetry): void {
                $telemetry[] = $event;
            },
            clock: fn (): int => $this->now,
            nonceFactory: static fn (): string => 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
        );
    }

    /** The happy path: verify, decide, sign, publish, ack. */
    public function testHappyPathPublishesASignedReply(): void
    {
        $transport = new FakeReactorTransport();
        $delivery = new FakeReactorDelivery($this->signedEvent());
        $telemetry = [];

        $this->server($transport, static fn (): ReactorAnswer => ReactorAnswer::allow(), $telemetry)
            ->dispatchDelivery($delivery);

        self::assertCount(1, $transport->published);
        self::assertSame('amq.rabbitmq.reply-to.reactor', $transport->published[0]['queue']);
        self::assertSame(self::CORRELATION, $transport->published[0]['correlationId']);
        self::assertSame(1, $delivery->acks);
        self::assertSame(0, $delivery->nacks);

        // §22.1: the correlation the server authenticates is the one INSIDE the
        // signed body, not the AMQP property.
        self::assertStringContainsString('"correlation_id":"' . self::CORRELATION . '"', $transport->published[0]['body']);

        $phases = array_map(static fn (ReactorTelemetryEvent $e): string => $e->phase, $telemetry);
        self::assertSame([ReactorTelemetryEvent::PHASE_RECEIVED, ReactorTelemetryEvent::PHASE_REPLIED], $phases);
        self::assertSame(ReactorAnswer::ALLOW, $telemetry[1]->decision);
        self::assertNotNull($telemetry[1]->durationMs);
    }

    /**
     * §22.10 rule 2 and §22.13's "a handler that throws produces NO reply".
     *
     * Assert zero published messages, not an `allow`: an SDK that answered `allow`
     * on behalf of a handler that crashed would have overridden the operator's
     * `fail_closed` setting from inside the library.
     */
    public function testHandlerThrowPublishesNothing(): void
    {
        $transport = new FakeReactorTransport();
        $delivery = new FakeReactorDelivery($this->signedEvent());
        $telemetry = [];

        $this->server(
            $transport,
            static fn (): ReactorAnswer => throw new \RuntimeException('the fraud service is down'),
            $telemetry,
        )->dispatchDelivery($delivery);

        self::assertSame([], $transport->published);
        self::assertSame(1, $delivery->acks);
        self::assertSame(ReactorTelemetryEvent::PHASE_NO_REPLY, $telemetry[1]->phase);
        self::assertSame(ReactorRejection::HANDLER_ERROR, $telemetry[1]->reason);
    }

    /**
     * An answer this SDK refuses to send (`require_mfa` off `login.post_auth`)
     * also publishes nothing, for the same reason: the registration's
     * `failure_policy` decides, never a synthesized allow.
     */
    public function testUnsendableAnswerPublishesNothing(): void
    {
        $transport = new FakeReactorTransport();
        $delivery = new FakeReactorDelivery($this->signedEvent(ReactorEvents::TOKEN_PRE_ISSUE));
        $telemetry = [];

        $this->server($transport, static fn (): ReactorAnswer => ReactorAnswer::allowWithStepUp(), $telemetry)
            ->dispatchDelivery($delivery);

        self::assertSame([], $transport->published);
        self::assertSame(ReactorRejection::REQUIRE_MFA_NOT_SUPPORTED, $telemetry[1]->reason);
    }

    /** A broker that refuses the publication is a no-reply, not a crash. */
    public function testPublishFailurePublishesNothingAndIsReported(): void
    {
        $transport = new FakeReactorTransport();
        $transport->failPublish = true;
        $delivery = new FakeReactorDelivery($this->signedEvent());
        $telemetry = [];

        $this->server($transport, static fn (): ReactorAnswer => ReactorAnswer::allow(), $telemetry)
            ->dispatchDelivery($delivery);

        self::assertSame([], $transport->published);
        self::assertSame(ReactorServer::NO_REPLY_PUBLISH_FAILED, $telemetry[1]->reason);
    }

    /**
     * §22.5: a listener never publishes a reply. The server does not read one on
     * this path, so producing one would be a message nobody consumes.
     */
    public function testListenerNeverPublishes(): void
    {
        $transport = new FakeReactorTransport();
        $delivery = new FakeReactorDelivery($this->signedEvent());
        $telemetry = [];

        $this->server(
            $transport,
            static fn (): ReactorAnswer => ReactorAnswer::deny('a listener cannot veto anything'),
            $telemetry,
            $this->config(ReactorEvents::MODE_LISTEN),
        )->dispatchDelivery($delivery);

        self::assertSame([], $transport->published);
        self::assertSame(1, $delivery->acks);
        self::assertSame(ReactorServer::NO_REPLY_LISTEN_MODE, $telemetry[1]->reason);
    }

    /**
     * §22.3: a late reply is discarded and the CPU spent producing it was spent
     * for nothing, so the runtime checks the window before signing.
     */
    public function testDeadlinePassedSkipsTheReply(): void
    {
        $transport = new FakeReactorTransport();
        $delivery = new FakeReactorDelivery($this->signedEvent(timeoutMs: 500));
        $telemetry = [];

        $server = $this->server(
            $transport,
            function (ReactorEvent $event): ReactorAnswer {
                self::assertSame(500, $event->timeoutMs);
                // A handler that overran its budget: the window has closed by the
                // time it answers.
                $this->now += 5;

                return ReactorAnswer::allow();
            },
            $telemetry,
        );
        $server->dispatchDelivery($delivery);

        self::assertSame([], $transport->published);
        self::assertSame(ReactorRejection::DEADLINE_PASSED, $telemetry[1]->reason);
    }

    /**
     * A refused delivery is nacked WITHOUT requeue, the handler never runs, and
     * the security log carries the category only — never the MAC, the key or the
     * body.
     *
     * @dataProvider refusalProvider
     */
    public function testRefusedDeliveriesNeverReachTheHandler(string $bodyFactory, string $expectedReason): void
    {
        $body = match ($bodyFactory) {
            'bad_signature' => str_replace('"sub":"alice"', '"sub":"root"', $this->signedEvent()),
            'stale' => $this->signedEvent(issuedAt: $this->now - ReactorProtocol::FRESHNESS_SKEW_SECONDS - 1),
            'future' => $this->signedEvent(issuedAt: $this->now + ReactorProtocol::FRESHNESS_SKEW_SECONDS + 1),
            'tenant_mismatch' => $this->signedEvent(tenantId: '77777777-7777-7777-7777-777777777777'),
            'unknown_event' => $this->signedEvent(event: 'nope.not_an_event'),
            'malformed' => 'not json at all',
            default => str_replace('"key_version":2', '"key_version":1', $this->signedEvent()),
        };

        $transport = new FakeReactorTransport();
        $delivery = new FakeReactorDelivery($body);
        $telemetry = [];
        $logger = new class () extends AbstractLogger {
            /** @var list<string> */
            public array $lines = [];

            /**
             * @param mixed              $level
             * @param string|\Stringable $message
             * @param array<mixed>       $context
             */
            public function log($level, $message, array $context = []): void
            {
                $this->lines[] = (string) $message;
            }
        };

        $reached = false;
        $this->server(
            $transport,
            static function () use (&$reached): ReactorAnswer {
                $reached = true;

                return ReactorAnswer::allow();
            },
            $telemetry,
            null,
            $logger,
        )->dispatchDelivery($delivery);

        self::assertFalse($reached, 'the handler must never see an unverified delivery');
        self::assertSame([], $transport->published);
        self::assertSame(0, $delivery->acks);
        self::assertSame(1, $delivery->nacks);
        self::assertSame(ReactorTelemetryEvent::PHASE_REJECTED, $telemetry[0]->phase);
        self::assertSame($expectedReason, $telemetry[0]->reason);

        self::assertCount(1, $logger->lines);
        self::assertStringContainsString($expectedReason, $logger->lines[0]);
        self::assertStringNotContainsString(self::SUBKEY_HEX, $logger->lines[0]);
        self::assertStringNotContainsString('alice', $logger->lines[0]);
    }

    /** @return array<string, array{string, string}> */
    public static function refusalProvider(): array
    {
        return [
            'tampered payload' => ['bad_signature', ReactorRejection::BAD_SIGNATURE],
            'stale' => ['stale', ReactorRejection::STALE],
            'future timestamp' => ['future', ReactorRejection::STALE],
            'another tenant' => ['tenant_mismatch', ReactorRejection::TENANT_MISMATCH],
            'name outside the registry' => ['unknown_event', ReactorRejection::UNKNOWN_EVENT],
            'not a JSON object' => ['malformed', ReactorRejection::MALFORMED],
            'key_version below the floor' => ['key_version', ReactorRejection::KEY_VERSION_TOO_OLD],
        ];
    }

    /**
     * The runtime holds ONE replay guard for its lifetime: a fresh guard per
     * delivery would defeat nonce dedup entirely.
     */
    public function testReplayGuardIsSharedAcrossDeliveries(): void
    {
        $body = $this->signedEvent(nonce: 'cafecafe-cafe-cafe-cafe-cafecafecafe');
        $transport = new FakeReactorTransport();
        $telemetry = [];
        $server = $this->server($transport, static fn (): ReactorAnswer => ReactorAnswer::allow(), $telemetry);

        $first = new FakeReactorDelivery($body);
        $second = new FakeReactorDelivery($body);
        $server->dispatchDelivery($first);
        $server->dispatchDelivery($second);

        self::assertCount(1, $transport->published, 'the redelivered nonce must not produce a second reply');
        self::assertSame(1, $second->nacks);
        self::assertSame(ReactorRejection::REPLAY, $telemetry[2]->reason);
    }

    /**
     * §22.3: `_reactor_patch` reaches the handler as READ-ONLY context so a later
     * reactor decides against the state that will actually be committed.
     */
    public function testChainPatchReachesTheHandler(): void
    {
        $transport = new FakeReactorTransport();
        $telemetry = [];
        $seen = null;

        $delivery = new FakeReactorDelivery($this->signedEvent(
            event: ReactorEvents::TOKEN_PRE_ISSUE,
            payload: ['sub' => 'alice', '_reactor_patch' => ['ext.tier' => 'gold']],
        ));

        $this->server(
            $transport,
            static function (ReactorEvent $event) use (&$seen): ReactorAnswer {
                $seen = $event->chainPatch();

                return ReactorAnswer::mutate(['ext.department' => 'eng']);
            },
            $telemetry,
        )->dispatchDelivery($delivery);

        self::assertSame(['ext.tier' => 'gold'], $seen);
        // Echoing the prior patch back is NOT how a field is preserved — the
        // server merges — so the reply carries only what this reactor set.
        self::assertStringContainsString('"patch":{"ext.department":"eng"}', $transport->published[0]['body']);
        self::assertStringNotContainsString('ext.tier', $transport->published[0]['body']);
    }

    /** An event with no chain patch reports none, and a non-map one is ignored. */
    public function testChainPatchAbsentOrMalformed(): void
    {
        $event = new ReactorEvent(
            self::TENANT,
            ReactorEvents::TOKEN_PRE_ISSUE,
            self::CORRELATION,
            ['sub' => 'alice'],
            500,
            'n',
            $this->now,
            $this->now + 1.0,
        );
        self::assertNull($event->chainPatch());
        self::assertSame(ReactorEvents::TOKEN_PRE_ISSUE, $event->spec()?->name);

        $mixed = new ReactorEvent(
            self::TENANT,
            ReactorEvents::TOKEN_PRE_ISSUE,
            self::CORRELATION,
            ['_reactor_patch' => ['ext.ok' => 'yes', 'ext.dropped' => 7]],
            500,
            'n',
            $this->now,
            $this->now + 1.0,
        );
        self::assertSame(['ext.ok' => 'yes'], $mixed->chainPatch());

        $notAMap = new ReactorEvent(
            self::TENANT,
            ReactorEvents::TOKEN_PRE_ISSUE,
            self::CORRELATION,
            ['_reactor_patch' => 'nope'],
            500,
            'n',
            $this->now,
            $this->now + 1.0,
        );
        self::assertNull($notAMap->chainPatch());
    }

    /**
     * The serve loop: it consumes the SERVER-declared queue (and nothing else),
     * dispatches, honours {@see ReactorServer::stop()}, and returns when the
     * session ends. There is no in-SDK reconnect — the supervisor restarts the
     * worker, exactly as this SDK's §8 consumer already documents.
     */
    public function testServeLoopConsumesTheServerDeclaredQueueAndStops(): void
    {
        $transport = new FakeReactorTransport([new FakeReactorDelivery($this->signedEvent())], extraIdleTicks: 3);
        $telemetry = [];
        $server = $this->server(
            $transport,
            static fn (): ReactorAnswer => ReactorAnswer::allow(),
            $telemetry,
        );

        $server->reactorServe();

        self::assertSame([ReactorEvents::queueName(self::TENANT, self::REACTOR)], $transport->consumedQueues);
        self::assertCount(1, $transport->published);
        // One delivery tick plus the idle ticks, then the session reports closed.
        self::assertSame(4, $transport->waits);
    }

    /** stop() ends the loop after the delivery in flight, without abandoning it. */
    public function testStopEndsTheLoopAfterTheCurrentDelivery(): void
    {
        $transport = new FakeReactorTransport([new FakeReactorDelivery($this->signedEvent())], extraIdleTicks: 100);
        $telemetry = [];
        $server = null;
        $server = new ReactorServer(
            config: $this->config(),
            transport: $transport,
            handler: static function () use (&$server): ReactorAnswer {
                /** @var ReactorServer $server */
                $server->stop();

                return ReactorAnswer::allow();
            },
            telemetryHook: function (ReactorTelemetryEvent $event) use (&$telemetry): void {
                $telemetry[] = $event;
            },
            clock: fn (): int => $this->now,
            nonceFactory: static fn (): string => 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
        );

        $server->reactorServe();

        self::assertSame(1, $transport->waits, 'the loop must return without taking another delivery');
        self::assertCount(1, $transport->published, 'the in-flight delivery must still have been answered');
    }

    /**
     * §22.12 / §22.13: the signing key never appears in any log line, telemetry
     * event or published body. `Sensitive` carries the §7 half; this asserts the
     * §22 half on the serialized output.
     */
    public function testSigningKeyNeverEscapes(): void
    {
        $transport = new FakeReactorTransport();
        $telemetry = [];
        $config = $this->config();

        $this->server($transport, static fn (): ReactorAnswer => ReactorAnswer::deny('embargoed region'), $telemetry)
            ->dispatchDelivery(new FakeReactorDelivery($this->signedEvent()));

        $serialized = json_encode([
            'published' => $transport->published,
            'telemetry' => array_map(static fn (ReactorTelemetryEvent $e): array => (array) $e, $telemetry),
            'config' => ['signingKey' => $config->signingKey, 'tenant' => $config->tenantId],
        ]);
        self::assertIsString($serialized);
        self::assertStringNotContainsString(self::SUBKEY_HEX, $serialized);
        self::assertStringNotContainsString($this->subkey(), $serialized);
        self::assertStringContainsString('[SENSITIVE]', $serialized);
    }

    /** The configuration refusals, each of which is a mistake worth naming early. */
    public function testConfigurationValidation(): void
    {
        $key = new Sensitive($this->subkey());

        self::assertSame(
            'axiam.reactor.q.' . self::TENANT . '.' . self::REACTOR,
            (new ReactorConfig(self::TENANT, $key, self::REACTOR))->queue(),
        );
        self::assertSame(
            'explicit.queue',
            (new ReactorConfig(self::TENANT, $key, null, 'explicit.queue'))->queue(),
        );
        self::assertFalse((new ReactorConfig(self::TENANT, $key, self::REACTOR))->isListener());
        self::assertTrue(
            (new ReactorConfig(self::TENANT, $key, self::REACTOR, null, ReactorEvents::MODE_LISTEN))->isListener(),
        );

        foreach ([
            'no tenant' => static fn () => new ReactorConfig('', $key, self::REACTOR),
            'empty key' => static fn () => new ReactorConfig(self::TENANT, new Sensitive(''), self::REACTOR),
            'no queue and no id' => static fn () => new ReactorConfig(self::TENANT, $key),
            'unknown mode' => static fn () => new ReactorConfig(self::TENANT, $key, self::REACTOR, null, 'observe'),
            'zero skew' => static fn () => new ReactorConfig(self::TENANT, $key, self::REACTOR, null, ReactorEvents::MODE_INTERCEPT, 0),
        ] as $name => $factory) {
            try {
                $factory();
                self::fail("$name must be refused");
            } catch (\InvalidArgumentException $error) {
                self::assertStringContainsString('axiam:', $error->getMessage(), $name);
            }
        }
    }

    /**
     * A runtime with no telemetry hook still works; the dispatcher's null path is
     * the overwhelmingly common one.
     */
    public function testRuntimeWithoutTelemetryOrClockOverrides(): void
    {
        $transport = new FakeReactorTransport();
        $server = new ReactorServer(
            config: $this->config(),
            transport: $transport,
            handler: static fn (): ReactorAnswer => ReactorAnswer::allow(),
        );

        // Signed at the real wall clock, since this server reads it too.
        $this->now = time();
        $server->dispatchDelivery(new FakeReactorDelivery($this->signedEvent()));

        self::assertCount(1, $transport->published);
        // A real UUIDv4 reply nonce, freshly generated rather than pinned.
        self::assertMatchesRegularExpression(
            '/"nonce":"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"/',
            $transport->published[0]['body'],
        );
    }

    /** Two replies from the same runtime never share a nonce (§22.2). */
    public function testReplyNoncesAreFresh(): void
    {
        $transport = new FakeReactorTransport();
        $server = new ReactorServer(
            config: $this->config(),
            transport: $transport,
            handler: static fn (): ReactorAnswer => ReactorAnswer::allow(),
        );
        $this->now = time();

        for ($i = 0; $i < 8; ++$i) {
            $server->dispatchDelivery(new FakeReactorDelivery($this->signedEvent()));
        }

        $nonces = [];
        foreach ($transport->published as $published) {
            preg_match('/"nonce":"([^"]+)"/', $published['body'], $matches);
            $nonces[] = $matches[1];
        }
        self::assertCount(8, $nonces);
        self::assertSame($nonces, array_unique($nonces), 'a constant reply nonce removes the body\'s only uniqueness');
    }

    /** A telemetry hook that throws must not fail a decision (§19.2 rule 2). */
    public function testThrowingTelemetryHookDoesNotFailTheDispatch(): void
    {
        $transport = new FakeReactorTransport();
        $server = new ReactorServer(
            config: $this->config(),
            transport: $transport,
            handler: static fn (): ReactorAnswer => ReactorAnswer::allow(),
            telemetryHook: static fn (): never => throw new \RuntimeException('the metrics backend is down'),
            clock: fn (): int => $this->now,
        );

        $server->dispatchDelivery(new FakeReactorDelivery($this->signedEvent()));

        self::assertCount(1, $transport->published);
    }
}
