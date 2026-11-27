<?php

declare(strict_types=1);

namespace Axiam\Sdk\Amqp;

use PhpAmqpLib\Channel\AMQPChannel;
use PhpAmqpLib\Connection\AMQPStreamConnection;
use PhpAmqpLib\Message\AMQPMessage;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * php-amqplib blocking consume loop with HMAC verify-before-handler
 * (CONTRACT.md §8, D-04).
 *
 * This is NOT a web-request path — `consume()` blocks on `$channel->wait()`
 * for the lifetime of the process. It is meant to run on a long-running
 * runtime (a dedicated CLI worker process), restarted by a process
 * supervisor on exit (see bin/axiam-amqp-worker.php — no in-SDK
 * auto-reconnect loop, Pitfall 6).
 *
 * A consumer is TYPED (contract 1.69, §8 step 2c, D-9): it is configured with the ONE signed
 * type it consumes ({@see SignedEventType}) and the tenant whose subkey `$signingKey` is, and
 * checks the canonical bytes against that type's layout only — before the HMAC and before any
 * decode. A validly signed body of another type (every tenant-signed shape shares the key) is
 * refused as `malformed` and never reaches the application; run two consumers to consume both.
 *
 * Every discard (§8 rule 4, "Every SDK consumer, field by field", D-8) logs exactly one warning
 * whose context is `timestamp`, `exchange`, `routing_key`, `tenant_id` (the consumer's OWN
 * configured tenant, never one read from the body) and `reason`, the first that applies in the
 * contract's order: `malformed`, `unsigned`, `signature`, `key_version`, `stale`, `replay`. It
 * never carries a signature, a nonce, a key or any part of the body. No body escapes the
 * consumer (D-10): empty, BOM-prefixed, not UTF-8, deeply nested or truncated bodies are
 * discarded as `malformed` and the loop goes on to the next delivery.
 *
 * Ack/nack semantics (verifyAndDispatch):
 *   - any discard (malformed, unsigned, signature, key_version, stale, replay) -> nack WITHOUT
 *     requeue (fail closed, poison-loop risk)
 *   - Handler throws AmqpDropMessage       -> nack WITHOUT requeue (application-declared poison message)
 *   - Handler throws any other \Throwable  -> nack WITH requeue (transient failure, retry)
 *   - Handler completes successfully       -> ack
 *
 * The HMAC is verified over the RECEIVED BYTES (the body with its trailing
 * `hmac_signature` member cut out), never over a re-serialization, and the
 * handler is given the value parsed from those same verified bytes
 * (axiam#882, C2) — see {@see Hmac}. A body with a duplicate key, content
 * after the object, or a signature that is not the trailing member is
 * nacked without requeue and the handler never runs.
 *
 * NEW-4 (CONTRACT.md §8 "v2 — Replay Protection", hard cutover): once the
 * HMAC verifies, the delivery is ADDITIONALLY rejected (same nack-without-
 * requeue path) when `key_version < 2`, `issued_at` falls outside the
 * ±skew freshness window, or `nonce` has already been seen. `nonce` and
 * `issued_at` are inside the verified bytes, so they are covered by the
 * HMAC with no canonicalization step — only the {@see ReplayGuard} gates
 * are new. See ReplayGuard for the full policy.
 */
final class Consumer
{
    private const MALFORMED = 'malformed';
    private const UNSIGNED = 'unsigned';
    private const SIGNATURE = 'signature';
    private const KEY_VERSION = 'key_version';
    private const STALE = 'stale';
    private const REPLAY = 'replay';

    private ?AMQPStreamConnection $connection = null;
    private ?AMQPChannel $channel = null;

    /**
     * ONE ReplayGuard shared across every delivery handled by this Consumer
     * instance for the lifetime of the process (NEW-4) — constructing a
     * fresh guard per delivery would defeat nonce-replay dedup entirely.
     */
    private readonly ReplayGuard $replayGuard;

    /**
     * @param string $signingKey The tenant's AMQP subkey (§8 rule 1).
     * @param string $tenantId The tenant that subkey belongs to. It is what every discard event
     *        reports as `tenant_id`; a `tenant_id` read from a message body is never used.
     * @param SignedEventType $type The one signed type this consumer consumes (§8 step 2c).
     * @param int $skewSeconds Freshness window (seconds) applied to a
     *        delivery's `issued_at` (NEW-4); also sets the nonce dedup TTL
     *        (2×skewSeconds). Defaults to
     *        {@see ReplayGuard::DEFAULT_SKEW_SECONDS} (300s / 5 minutes),
     *        matching the server's DEFAULT_FRESHNESS_SKEW_SECS. Ignored
     *        when $replayGuard is supplied.
     * @param ReplayGuard|null $replayGuard Inject a preconfigured guard
     *        (e.g. with a fixed clock) for deterministic tests; when null a
     *        guard is constructed from $skewSeconds.
     */
    public function __construct(
        private readonly string $signingKey,
        private readonly string $tenantId,
        private readonly SignedEventType $type,
        private readonly LoggerInterface $logger = new NullLogger(),
        int $skewSeconds = ReplayGuard::DEFAULT_SKEW_SECONDS,
        ?ReplayGuard $replayGuard = null,
    ) {
        $this->replayGuard = $replayGuard ?? new ReplayGuard($skewSeconds);
    }

    /**
     * @param callable(array<string, mixed>): void $handler Throws AmqpDropMessage
     *        for poison messages that must never be requeued.
     */
    public function consume(
        string $host,
        int $port,
        string $user,
        string $pass,
        string $vhost,
        string $queue,
        callable $handler,
    ): void {
        $this->connection = new AMQPStreamConnection($host, $port, $user, $pass, $vhost);
        $this->channel = $this->connection->channel();
        $this->channel->basic_qos(0, 10, false);

        $this->channel->basic_consume(
            $queue,
            '',
            false,
            false,
            false,
            false,
            function (AMQPMessage $msg) use ($handler, $queue): void {
                $channel = $msg->getChannel();
                $tag = $msg->getDeliveryTag();

                $this->verifyAndDispatch(
                    $msg->getBody(),
                    $handler,
                    ack: static fn (): mixed => $channel->basic_ack($tag),
                    nackNoRequeue: static fn (): mixed => $channel->basic_nack($tag, false, false),
                    nackRequeue: static fn (): mixed => $channel->basic_nack($tag, false, true),
                    // What the broker reported; a transport that reports neither is read from the
                    // queue this consumer was started on, through the default exchange.
                    exchange: (string) ($msg->getExchange() ?? ''),
                    routingKey: (string) ($msg->getRoutingKey() ?? $queue),
                );
            }
        );

        while ($this->channel->is_consuming()) {
            $this->channel->wait(); // blocking loop — not a web-request path (D-04)
        }
    }

    /**
     * Verifies a single delivery's HMAC signature BEFORE the handler ever
     * sees it (D-04), then applies the NEW-4 replay-protection gate, then
     * maps the outcome to the ack/nack matrix documented on the class.
     *
     * Extracted from the `basic_consume` closure so it is a separately
     * testable unit — tests can drive it with fake ack/nack callables
     * without a live broker or AMQPMessage.
     *
     * @param callable(array<string, mixed>): void $handler
     * @param callable(): mixed $ack
     * @param callable(): mixed $nackNoRequeue
     * @param callable(): mixed $nackRequeue
     * @param string $exchange The delivery's exchange as the broker reported it (`""` for the
     *        default exchange); reported in the discard event.
     * @param string $routingKey The delivery's routing key as the broker reported it.
     */
    public function verifyAndDispatch(
        string $body,
        callable $handler,
        callable $ack,
        callable $nackNoRequeue,
        callable $nackRequeue,
        string $exchange,
        string $routingKey,
    ): void {
        try {
            $outcome = $this->admit($body);
        } catch (\Throwable) {
            // No body escapes the consumer (D-10): whatever made the checks throw, it is a body
            // this consumer refuses, not a reason to leave the delivery loop.
            $outcome = self::MALFORMED;
        }

        if (is_string($outcome)) {
            $this->discard($outcome, $exchange, $routingKey);
            $nackNoRequeue(); // fail closed, no requeue
            return;
        }

        try {
            $handler($outcome);
            $ack();
        } catch (AmqpDropMessage) {
            $nackNoRequeue(); // poison -> no requeue
        } catch (\Throwable) {
            $nackRequeue(); // transient -> requeue
        }
    }

    /**
     * Applies §8 steps 2a–2f and the v2 gates in the normative reason order. Returns the event
     * decoded from the VERIFIED canonical bytes, or the discard reason. The nonce is recorded
     * only by the last gate, so a body refused earlier leaves none behind.
     *
     * @return array<string, mixed>|string
     */
    private function admit(string $body): array|string
    {
        // (1) one JSON object whose first byte is `{`, that parses.
        if (!Hmac::startsWithBrace($body)) {
            return self::MALFORMED;
        }
        try {
            $members = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return self::MALFORMED;
        }
        if (!is_array($members)) {
            return self::MALFORMED;
        }

        // (2) no top-level `hmac_signature` member: unsigned, whatever else it lacks.
        if (!array_key_exists('hmac_signature', $members)) {
            return self::UNSIGNED;
        }

        // (3) a repeated member, a signature that is not the trailing 64-hex member, or a layout
        // that is not the configured type's (the typed check) — all before any HMAC is computed.
        $cut = Hmac::cut($body);
        if ($cut === null || !Hmac::hasLayout($cut[0], $this->type)) {
            return self::MALFORMED;
        }
        [$canonical, $signatureHex] = $cut;

        // (4) the HMAC, over the received bytes minus the trailing member.
        if (!Hmac::signatureMatches($this->signingKey, $canonical, $signatureHex)) {
            return self::SIGNATURE;
        }

        // (5) decode from the verified canonical bytes (never from the body).
        $event = json_decode($canonical, true);
        if (!is_array($event) || !$this->decodes($event)) {
            return self::MALFORMED;
        }

        // (6)-(8) NEW-4 gates. `nonce` and `issued_at` are inside the verified bytes, so this is an
        // ADDITIONAL validation gate, not re-verification; it records the nonce last.
        return match ($this->replayGuard->check($event)) {
            null => $event,
            'key_version' => self::KEY_VERSION,
            'issued_at' => self::STALE,
            default => self::REPLAY,
        };
    }

    /**
     * Whether the verified members decode into the configured type: each member the JSON type
     * the server's struct reads it as, identifiers and `nonce` as UUIDs, `issued_at` as an
     * RFC 3339 timestamp (§8 step 2f). Nothing here is logged.
     *
     * @param array<string, mixed> $event
     */
    private function decodes(array $event): bool
    {
        $uuids = $this->type === SignedEventType::AuthzRequest
            ? ['correlation_id', 'tenant_id', 'subject_id', 'resource_id', 'nonce']
            : ['tenant_id', 'actor_id', 'resource_id', 'nonce'];
        $strings = $this->type === SignedEventType::AuthzRequest
            ? ['action', 'scope']
            : ['actor_type', 'action', 'outcome', 'ip_address'];

        foreach ($uuids as $name) {
            if (array_key_exists($name, $event) && !self::isUuid($event[$name])) {
                return false;
            }
        }
        foreach ($strings as $name) {
            if (array_key_exists($name, $event) && !is_string($event[$name])) {
                return false;
            }
        }
        if (array_key_exists('metadata', $event) && (!is_array($event['metadata']) || array_is_list($event['metadata']) && $event['metadata'] !== [])) {
            return false;
        }

        return is_int($event['key_version'] ?? null)
            && is_string($event['issued_at'] ?? null)
            && preg_match('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?(Z|[+-]\d\d:\d\d)$/D', $event['issued_at']) === 1
            && self::parsesAsDate($event['issued_at']);
    }

    /** A real calendar date and time: the date part survives a round trip (no Feb 30, no hour 25). */
    private static function parsesAsDate(string $value): bool
    {
        try {
            $dt = new \DateTimeImmutable($value);
        } catch (\Exception) {
            return false;
        }

        return $dt->format('Y-m-d') === substr($value, 0, 10) && (int) substr($value, 11, 2) < 24;
    }

    private static function isUuid(mixed $value): bool
    {
        return is_string($value)
            && preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iD', $value) === 1;
    }

    /**
     * The one fixed security event of a discard (§8 rule 4, D-8): exactly these five members and
     * nothing read from the body, no signature, no nonce, no key.
     */
    private function discard(string $reason, string $exchange, string $routingKey): void
    {
        $this->logger->warning('axiam_sdk_security: AMQP event discarded', [
            'timestamp' => gmdate('Y-m-d\TH:i:s\Z'),
            'exchange' => $exchange,
            'routing_key' => $routingKey,
            'tenant_id' => $this->tenantId,
            'reason' => $reason,
        ]);
    }
}
