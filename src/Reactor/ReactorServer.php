<?php

declare(strict_types=1);

namespace Axiam\Sdk\Reactor;

use Axiam\Sdk\Amqp\ReplayGuard;
use Axiam\Sdk\Core\TelemetryDispatcher;
use Axiam\Sdk\Core\TelemetryEvent;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * The CONTRACT.md §22 reactor runtime — §22.10's `reactor_serve`, spelled
 * {@see self::reactorServe()} in PHP by that subsection's per-language table.
 *
 * A **Reactor** is an external process that subscribes to named hook events on the
 * AXIAM AMQP bus and answers back — allow, deny, or a field-allow-listed mutation
 * — inside a timeout the server declared. Zitadel Actions and Keycloak SPIs solve
 * the same problem by loading third-party code *into* the authorization server; a
 * reactor stays outside it, reachable only through a signed reply schema the
 * server validates before it believes a word of it.
 *
 * Per delivery, in this order and no other (§22.3): reject `key_version < 2`,
 * verify the MAC, check freshness, check the nonce, decode the payload, dispatch
 * to the handler, sign and publish the reply. A runtime that hands an unverified
 * payload to user code has already lost.
 *
 * THE FOUR RULES §22.10 PUTS ON THIS HELPER, AND WHERE EACH ONE LIVES:
 *
 *  1. **It MUST NOT declare topology** (§22.1) — enforced by the shape of
 *     {@see ReactorTransport}, which has no declare or bind method at all.
 *  2. **It MUST fail closed on its own errors.** A handler that throws, an answer
 *     this SDK refuses to send, a reply that will not serialize: every one of them
 *     results in **no reply**, letting the operator's `failure_policy` decide. An
 *     SDK that answered `allow` on behalf of a handler that crashed would have
 *     overridden a `fail_closed` setting from inside the library.
 *  3. **It MUST NOT filter a patch** to the allowed subset (§22.4 rule 1) — see
 *     {@see ReactorAnswer::mutate()}.
 *  4. **It SHOULD honour `timeout_ms`** by abandoning work whose window has closed
 *     rather than replying late (§22.3) — see the deadline check in
 *     {@see self::dispatchDelivery()}.
 *
 * THIS IS NOT A WEB-REQUEST PATH. {@see self::reactorServe()} blocks for the
 * lifetime of the process and must run on a long-running runtime — a dedicated CLI
 * worker, never an FPM request. `php-amqplib` has no built-in automatic
 * reconnection, so as with this SDK's §8 consumer the loop returns when the
 * session ends and a process supervisor (systemd `Restart=on-failure`, a
 * Kubernetes restart policy, supervisord) brings it back. That is a deliberate,
 * documented deviation from the Go/Java runtimes' in-process reconnect loop, and
 * the same one this SDK already makes for §8.
 */
final class ReactorServer
{
    /**
     * How long one {@see ReactorTransport::wait()} call blocks before the loop
     * re-checks whether it has been asked to stop.
     *
     * A tick rather than an indefinite block, so {@see self::stop()} from a signal
     * handler is honoured promptly and the deterministic-shutdown obligation of
     * §18 is met without a second thread.
     */
    public const WAIT_TICK_SECONDS = 1.0;

    /**
     * No-reply category for a {@see ReactorEvents::MODE_LISTEN} registration: the
     * handler ran and no reply was published because the server never reads one on
     * this path (§22.5). Unlike every other no-reply category, it is not a failure
     * and no `failure_policy` is consulted for it.
     */
    public const NO_REPLY_LISTEN_MODE = 'listen_mode';

    /** No-reply category for a reply that could not be handed to the broker. */
    public const NO_REPLY_PUBLISH_FAILED = 'publish_failed';

    private readonly ReplayGuard $replayGuard;

    private readonly TelemetryDispatcher $telemetry;

    private bool $stopping = false;

    /**
     * @param ReactorConfig                                     $config       Identity, queue and
     *                                                                        signing key.
     * @param ReactorTransport                                  $transport    The broker session. It
     *                                                                        has no way to declare
     *                                                                        topology (§22.1).
     * @param callable(ReactorEvent): ReactorAnswer             $handler      Decides one event.
     *                                                                        Throwing means "I could
     *                                                                        not decide": no reply is
     *                                                                        published and the
     *                                                                        registration's
     *                                                                        `failure_policy` applies
     *                                                                        — which is the honest
     *                                                                        outcome, and the one an
     *                                                                        operator configured.
     *
     *                                                                        In
     *                                                                        {@see ReactorEvents::MODE_LISTEN}
     *                                                                        the return value is
     *                                                                        IGNORED and no reply is
     *                                                                        ever published (§22.5).
     *                                                                        Write a listener handler
     *                                                                        IDEMPOTENTLY: a
     *                                                                        redelivery after a broker
     *                                                                        hiccup is normal, and a
     *                                                                        listener that
     *                                                                        double-counts is one that
     *                                                                        assumed an exactly-once
     *                                                                        delivery it was never
     *                                                                        promised.
     * @param LoggerInterface                                   $logger       Security events only:
     *                                                                        the fact and category of
     *                                                                        a refusal, never the MAC,
     *                                                                        the key or the payload.
     * @param (callable(ReactorTelemetryEvent): void)|null      $telemetryHook §19 sink. Invoked on the
     *                                                                        dispatch path, so it must
     *                                                                        not block.
     * @param (callable(): int)|null                            $clock        Overridable "now" source
     *                                                                        (Unix seconds) for
     *                                                                        deterministic tests.
     * @param (callable(): string)|null                         $nonceFactory Overridable reply-nonce
     *                                                                        source. Defaults to a
     *                                                                        fresh UUIDv4 per reply
     *                                                                        (§22.2).
     */
    public function __construct(
        private readonly ReactorConfig $config,
        private readonly ReactorTransport $transport,
        private readonly mixed $handler,
        private readonly LoggerInterface $logger = new NullLogger(),
        ?callable $telemetryHook = null,
        private $clock = null,
        private $nonceFactory = null,
    ) {
        // ONE guard for the lifetime of the process: a fresh guard per delivery
        // would defeat nonce-replay dedup entirely.
        $this->replayGuard = new ReplayGuard($config->skewSeconds, $this->clock);
        // The §19 dispatcher speaks the base TelemetryEvent type; narrowing here
        // rather than widening the caller's hook keeps the reactor sink typed to
        // the only event class it can ever receive.
        $this->telemetry = new TelemetryDispatcher(
            $telemetryHook === null
                ? null
                : static function (TelemetryEvent $event) use ($telemetryHook): void {
                    if ($event instanceof ReactorTelemetryEvent) {
                        $telemetryHook($event);
                    }
                },
        );
        $this->clock ??= static fn (): int => time();
        $this->nonceFactory ??= static fn (): string => self::uuid4();
    }

    /**
     * §22.10's `reactor_serve`: consume the server-declared queue and answer every
     * delivery until the session ends or {@see self::stop()} is called.
     *
     * It never declares an exchange, a queue or a binding (§22.1). It returns
     * normally on a clean stop and on a lost session alike — there is no in-SDK
     * reconnect loop, by the same design decision this SDK's §8 consumer records.
     *
     * In-flight work is drained by construction rather than by a timer: deliveries
     * are dispatched one at a time on the calling thread, so when this returns
     * there is no half-finished dispatch left behind (§18).
     */
    public function reactorServe(): void
    {
        $this->transport->consume(
            $this->config->queue(),
            fn (ReactorDelivery $delivery) => $this->dispatchDelivery($delivery),
        );

        while (!$this->stopping) {
            if (!$this->transport->wait(self::WAIT_TICK_SECONDS)) {
                break;
            }
        }
    }

    /**
     * Asks {@see self::reactorServe()} to return after the delivery it is
     * currently handling, if any.
     *
     * Safe to call from a `pcntl` signal handler: it sets a flag and nothing else,
     * so a dispatch already in progress finishes and answers rather than being
     * abandoned mid-decision (§18).
     */
    public function stop(): void
    {
        $this->stopping = true;
    }

    /**
     * Verifies, dispatches and answers ONE delivery.
     *
     * Public because it is the load-bearing, separately-testable unit — the same
     * reason this SDK's §8 consumer exposes `verifyAndDispatch`. Tests drive it
     * with a fake delivery and a fake transport; no broker is involved.
     */
    public function dispatchDelivery(ReactorDelivery $delivery): void
    {
        $startedNs = hrtime(true);
        $now = ($this->clock)();

        try {
            $event = ReactorProtocol::decodeEvent(
                $this->config->signingKey->reveal(),
                $delivery->body(),
                $this->config->tenantId,
                $this->replayGuard,
                $now,
            );
        } catch (ReactorRejection $rejection) {
            // §8.3/§22.12: the fact and category of the refusal, never the
            // signature, the key or the body.
            $this->logger->warning(
                'axiam_sdk_security: reactor event refused (' . $rejection->reason() . '); nacking without requeue',
            );
            $this->telemetry->emit(new ReactorTelemetryEvent(
                phase: ReactorTelemetryEvent::PHASE_REJECTED,
                event: '',
                correlationId: $delivery->correlationId(),
                reason: $rejection->reason(),
            ));
            $delivery->nack();

            return;
        }

        $this->telemetry->emit(new ReactorTelemetryEvent(
            phase: ReactorTelemetryEvent::PHASE_RECEIVED,
            event: $event->event,
            correlationId: $event->correlationId,
        ));

        try {
            /** @var ReactorAnswer $answer */
            $answer = ($this->handler)($event);
        } catch (\Throwable) {
            // §22.10 rule 2: fail closed on our own errors. No synthesized allow —
            // the operator's failure_policy decides. The thrown value is NOT
            // interpolated anywhere: a handler that threw while holding a token
            // would otherwise put it in a log line.
            $this->noReply($event, ReactorRejection::HANDLER_ERROR, $delivery);

            return;
        }

        // A listener never publishes (§22.5): the server does not read a reply on
        // this path, so producing one would be a message nobody consumes.
        if ($this->config->isListener()) {
            $this->noReply($event, self::NO_REPLY_LISTEN_MODE, $delivery);

            return;
        }

        // §22.3: a late reply is discarded, and the CPU spent producing it was
        // spent for nothing. Checked before signing, not after publishing.
        if (($this->clock)() >= $event->deadline) {
            $this->noReply($event, ReactorRejection::DEADLINE_PASSED, $delivery);

            return;
        }

        try {
            $body = ReactorProtocol::buildReply(
                $this->config->signingKey->reveal(),
                $event,
                $answer,
                ($this->nonceFactory)(),
                ($this->clock)(),
            );
            $this->transport->publishReply($delivery->replyTo(), $delivery->correlationId(), $body);
        } catch (ReactorRejection $rejection) {
            $this->noReply($event, $rejection->reason(), $delivery);

            return;
        } catch (\Throwable) {
            $this->noReply($event, self::NO_REPLY_PUBLISH_FAILED, $delivery);

            return;
        }

        $this->telemetry->emit(new ReactorTelemetryEvent(
            phase: ReactorTelemetryEvent::PHASE_REPLIED,
            event: $event->event,
            correlationId: $event->correlationId,
            decision: $answer->decision(),
            durationMs: (hrtime(true) - $startedNs) / 1_000_000.0,
        ));
        $delivery->ack();
    }

    /**
     * Records that a verified delivery produced no reply and acknowledges it.
     *
     * The delivery is ACKed rather than NACKed: it was authentic and was seen, and
     * a redelivery could only ever produce a reply the server has stopped reading.
     * What decides the outcome now is the registration's `failure_policy` (§22.8),
     * which is exactly the point — and the telemetry below is the only place the
     * fact is visible, because a `fail_open` outcome looks identical to a reactor
     * that was never configured.
     */
    private function noReply(ReactorEvent $event, string $reason, ReactorDelivery $delivery): void
    {
        $this->telemetry->emit(new ReactorTelemetryEvent(
            phase: ReactorTelemetryEvent::PHASE_NO_REPLY,
            event: $event->event,
            correlationId: $event->correlationId,
            reason: $reason,
        ));
        $delivery->ack();
    }

    /**
     * A fresh RFC 4122 v4 UUID for one reply (§22.2).
     *
     * Emitting a constant nonce is not a small deviation: it removes the only
     * uniqueness a reply body carries beyond its timestamp, which is what makes a
     * captured reply distinguishable from a fresh one.
     */
    private static function uuid4(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0F) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3F) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($bytes), 4));
    }
}
