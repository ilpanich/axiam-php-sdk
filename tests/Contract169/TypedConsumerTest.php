<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract169;

use Axiam\Sdk\Amqp\Consumer;
use Axiam\Sdk\Amqp\ReplayGuard;
use Axiam\Sdk\Amqp\SignedEventType;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;

/**
 * Contract 1.69 (CONTRACT.md §8 step 2c "Typed: one configured type", protocol rule 4 "Every SDK
 * consumer, field by field", "No body escapes the consumer"; axiam#883, owner decisions D-8, D-9,
 * D-10): the event consumer is configured with the ONE signed type it consumes, refuses another
 * type's layout as `malformed` before the HMAC, refuses a byte-order-marked body without letting
 * anything escape, and logs exactly one fixed event per discard.
 */
final class TypedConsumerTest extends TestCase
{
    private const TENANT = '11111111-1111-1111-1111-111111111111';
    private const EXCHANGE = 'axiam.events';
    private const ROUTING_KEY = 'axiam.audit.events';

    /** @return array<string, mixed> */
    private static function fixture(): array
    {
        $decoded = json_decode((string) file_get_contents(__DIR__ . '/../Fixtures/v2_reference_vectors.json'), true);
        self::assertIsArray($decoded);

        return $decoded;
    }

    private static function subkey(): string
    {
        $key = hex2bin(self::fixture()['hkdf']['derived_subkey_hex']);
        self::assertIsString($key);

        return $key;
    }

    private static function now(): int
    {
        return (new \DateTimeImmutable('2026-07-10T12:00:00Z'))->getTimestamp();
    }

    /** @return array{0: Consumer, 1: object} */
    private static function consumer(SignedEventType $type): array
    {
        $logger = new class () extends AbstractLogger {
            /** @var list<array{level: mixed, message: string, context: array<string,mixed>}> */
            public array $records = [];

            public function log($level, string|\Stringable $message, array $context = []): void
            {
                $this->records[] = ['level' => $level, 'message' => (string) $message, 'context' => $context];
            }
        };

        return [
            new Consumer(
                self::subkey(),
                self::TENANT,
                $type,
                $logger,
                replayGuard: new ReplayGuard(300, static fn (): int => self::now()),
            ),
            $logger,
        ];
    }

    /** @return array{acked: int, nackedNoRequeue: int, nackedRequeue: int, calls: list<array<string,mixed>>} */
    private static function deliver(Consumer $consumer, string $body): array
    {
        $result = ['acked' => 0, 'nackedNoRequeue' => 0, 'nackedRequeue' => 0, 'calls' => []];
        $consumer->verifyAndDispatch(
            $body,
            static function (array $event) use (&$result): void {
                $result['calls'][] = $event;
            },
            ack: static function () use (&$result): void {
                ++$result['acked'];
            },
            nackNoRequeue: static function () use (&$result): void {
                ++$result['nackedNoRequeue'];
            },
            nackRequeue: static function () use (&$result): void {
                ++$result['nackedRequeue'];
            },
            exchange: self::EXCHANGE,
            routingKey: self::ROUTING_KEY,
        );

        return $result;
    }

    /** Flips the last hex digit of the trailing signature. */
    private static function withChangedSignatureDigit(string $wire): string
    {
        $i = strlen($wire) - 3; // the last hex digit, before `"}`
        $wire[$i] = $wire[$i] === '0' ? '1' : '0';

        return $wire;
    }

    /** @return iterable<string, array{string, string}> [configured type, vector delivered to it] */
    public static function crossTypeProvider(): iterable
    {
        yield 'an audit_event body to an AuthzRequest consumer' => ['AuthzRequest', 'audit_event'];
        yield 'an authz_request body to an AuditEventMessage consumer' => ['AuditEventMessage', 'authz_request'];
    }

    /** @dataProvider crossTypeProvider */
    public function testAnotherTypesWireJsonIsMalformedAndNeverReachesTheHandler(string $configured, string $vector): void
    {
        $wire = self::fixture()[$vector]['wire_json'];
        [$consumer, $logger] = self::consumer(SignedEventType::from($configured));

        $result = self::deliver($consumer, $wire);

        self::assertSame(1, $result['nackedNoRequeue']);
        self::assertSame(0, $result['acked'] + $result['nackedRequeue']);
        self::assertSame([], $result['calls']);
        self::assertCount(1, $logger->records);
        self::assertSame('malformed', $logger->records[0]['context']['reason']);
    }

    /** @dataProvider crossTypeProvider */
    public function testTheTypedCheckPrecedesTheHmac(string $configured, string $vector): void
    {
        $wire = self::withChangedSignatureDigit(self::fixture()[$vector]['wire_json']);
        [$consumer, $logger] = self::consumer(SignedEventType::from($configured));

        $result = self::deliver($consumer, $wire);

        self::assertSame(1, $result['nackedNoRequeue']);
        self::assertSame([], $result['calls']);
        self::assertSame('malformed', $logger->records[0]['context']['reason'], 'not `signature`: the layout is refused first');
    }

    /** @dataProvider ownTypeProvider */
    public function testEachTypesOwnVectorIsAcceptedByItsOwnConsumer(string $configured, string $vector): void
    {
        [$consumer, $logger] = self::consumer(SignedEventType::from($configured));

        $result = self::deliver($consumer, self::fixture()[$vector]['wire_json']);

        self::assertSame(1, $result['acked']);
        self::assertCount(1, $result['calls']);
        self::assertSame([], $logger->records);
    }

    /** @return iterable<string, array{string, string}> */
    public static function ownTypeProvider(): iterable
    {
        yield 'authz_request' => ['AuthzRequest', 'authz_request'];
        yield 'audit_event' => ['AuditEventMessage', 'audit_event'];
    }

    public function testTheDiscardEventCarriesExactlyTheFixedFieldsAndNoSecret(): void
    {
        $wire = self::fixture()['audit_event']['wire_json'];
        [$consumer, $logger] = self::consumer(SignedEventType::AuthzRequest);

        self::deliver($consumer, $wire);

        self::assertCount(1, $logger->records);
        $record = $logger->records[0];
        self::assertSame('warning', $record['level']);
        self::assertSame(['timestamp', 'exchange', 'routing_key', 'tenant_id', 'reason'], array_keys($record['context']));
        self::assertSame(self::EXCHANGE, $record['context']['exchange']);
        self::assertSame(self::ROUTING_KEY, $record['context']['routing_key']);
        self::assertSame(self::TENANT, $record['context']['tenant_id']);
        self::assertMatchesRegularExpression('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/', $record['context']['timestamp']);

        $everything = json_encode($record);
        self::assertIsString($everything);
        self::assertStringNotContainsString('c87056dfa96bf0606949104108e5fc7296df0a22ad39bf94bbc00512b214f40f', $everything);
        self::assertStringNotContainsString('88888888-8888-8888-8888-888888888888', $everything, 'no nonce');
    }

    public function testTheTenantInTheEventIsTheConfiguredOneNotTheBodys(): void
    {
        // A body naming ANOTHER tenant, with no signature member at all: `unsigned`, and the event
        // still names the consumer's own tenant.
        $body = str_replace(self::TENANT, '99999999-9999-9999-9999-999999999999', self::fixture()['audit_event']['canonical_signed_json']);
        [$consumer, $logger] = self::consumer(SignedEventType::AuditEventMessage);

        self::deliver($consumer, $body);

        self::assertSame('unsigned', $logger->records[0]['context']['reason']);
        self::assertSame(self::TENANT, $logger->records[0]['context']['tenant_id']);
        self::assertFullEvent($logger->records[0], 'unsigned');
    }

    public function testASignatureThatDoesNotVerifyIsSignature(): void
    {
        [$consumer, $logger] = self::consumer(SignedEventType::AuditEventMessage);

        self::deliver($consumer, self::withChangedSignatureDigit(self::fixture()['audit_event']['wire_json']));

        self::assertSame('signature', $logger->records[0]['context']['reason']);
        self::assertFullEvent($logger->records[0], 'signature');
    }

    /** @param array{level: mixed, message: string, context: array<string,mixed>} $record */
    private static function assertFullEvent(array $record, string $reason): void
    {
        self::assertSame('warning', $record['level']);
        self::assertSame(['timestamp', 'exchange', 'routing_key', 'tenant_id', 'reason'], array_keys($record['context']));
        self::assertSame(self::EXCHANGE, $record['context']['exchange']);
        self::assertSame(self::ROUTING_KEY, $record['context']['routing_key']);
        self::assertSame(self::TENANT, $record['context']['tenant_id']);
        self::assertSame($reason, $record['context']['reason']);
        $all = (string) json_encode($record);
        self::assertStringNotContainsString('c87056dfa96bf060', $all);
        self::assertStringNotContainsString('88888888-8888-8888-8888-888888888888', $all);
    }

    /** @dataProvider ownTypeProvider */
    public function testAByteOrderMarkedBodyIsMalformedAndTheNextDeliveryIsStillProcessed(string $configured, string $vector): void
    {
        $wire = self::fixture()[$vector]['wire_json'];
        [$consumer, $logger] = self::consumer(SignedEventType::from($configured));

        $bom = self::deliver($consumer, "\xEF\xBB\xBF" . $wire);

        self::assertSame(1, $bom['nackedNoRequeue']);
        self::assertSame([], $bom['calls']);
        self::assertSame('malformed', $logger->records[0]['context']['reason']);

        $next = self::deliver($consumer, $wire);
        self::assertSame(1, $next['acked'], 'the BOM did not consume the nonce or break the consumer');
    }

    /** @return iterable<string, array{string}> */
    public static function oddBodies(): iterable
    {
        yield 'empty' => [''];
        yield 'leading space' => [' {}'];
        yield 'not UTF-8' => ["\xff\xfe\x00"];
        yield 'deeply nested' => [str_repeat('[', 100000)];
        yield 'truncated' => ['{"correlation_id":"x'];
        yield 'a JSON scalar' => ['42'];
    }

    /** @dataProvider oddBodies */
    public function testNoBodyEscapesTheConsumer(string $body): void
    {
        [$consumer, $logger] = self::consumer(SignedEventType::AuthzRequest);

        $result = self::deliver($consumer, $body);

        self::assertSame(1, $result['nackedNoRequeue']);
        self::assertSame([], $result['calls']);
        self::assertSame('malformed', $logger->records[0]['context']['reason']);
    }

    public function testARefusedBodyLeavesNoNonceBehind(): void
    {
        // Genuinely signed, right layout, but `nonce` is not a UUID: step 2f cannot decode it.
        $canonical = str_replace('"nonce":"55555555-5555-5555-5555-555555555555"', '"nonce":"not-a-uuid"', substr(self::fixture()['authz_request']['canonical_signed_json'], 0));
        $wire = substr($canonical, 0, -1) . ',"hmac_signature":"' . hash_hmac('sha256', $canonical, self::subkey()) . '"}';
        [$consumer, $logger] = self::consumer(SignedEventType::AuthzRequest);

        $result = self::deliver($consumer, $wire);

        self::assertSame(1, $result['nackedNoRequeue']);
        self::assertSame('malformed', $logger->records[0]['context']['reason']);
    }

    public function testTheV2GatesReportTheirOwnReasons(): void
    {
        $sign = static function (string $canonical): string {
            return substr($canonical, 0, -1) . ',"hmac_signature":"' . hash_hmac('sha256', $canonical, self::subkey()) . '"}';
        };
        $base = self::fixture()['authz_request']['canonical_signed_json'];

        [$consumer, $logger] = self::consumer(SignedEventType::AuthzRequest);
        self::deliver($consumer, $sign(str_replace('"key_version":2', '"key_version":1', $base)));
        self::deliver($consumer, $sign(str_replace('2026-07-10T12:00:00Z', '2026-07-10T11:00:00Z', $base)));
        self::deliver($consumer, $sign($base));
        self::deliver($consumer, $sign($base));

        $reasons = array_map(static fn (array $r): string => $r['context']['reason'], $logger->records);
        self::assertSame(['key_version', 'stale', 'replay'], $reasons);
    }

    public function testANonceOfARefusedMessageIsStillAcceptedOnAValidOne(): void
    {
        $sign = static fn (string $c): string => substr($c, 0, -1) . ',"hmac_signature":"' . hash_hmac('sha256', $c, self::subkey()) . '"}';
        $base = self::fixture()['authz_request']['canonical_signed_json'];
        [$consumer, $logger] = self::consumer(SignedEventType::AuthzRequest);

        self::deliver($consumer, $sign(str_replace('"key_version":2', '"key_version":1', $base)));
        self::deliver($consumer, $sign(str_replace('2026-07-10T12:00:00Z', '2026-07-10T11:00:00Z', $base)));
        $valid = self::deliver($consumer, $sign($base));

        self::assertSame(['key_version', 'stale'], array_map(static fn (array $r): string => $r['context']['reason'], $logger->records));
        self::assertSame(1, $valid['acked'], 'the same nonce was not recorded by the refused messages');
    }

    /** @return iterable<string, array{string, string}> */
    public static function undecodable(): iterable
    {
        yield 'minute 60' => ['2026-07-10T12:00:00Z', '2026-07-10T12:60:00Z'];
        yield 'second 61' => ['2026-07-10T12:00:00Z', '2026-07-10T12:00:61Z'];
        yield 'hour 24' => ['2026-07-10T12:00:00Z', '2026-07-10T24:00:00Z'];
        yield 'a non-calendar date' => ['2026-07-10T12:00:00Z', '2026-02-30T12:00:00Z'];
        yield 'metadata a JSON array' => ['"outcome":"Success"', '"outcome":"Success","metadata":[1]'];
        yield 'nonce with a trailing newline' => ['"nonce":"88888888-8888-8888-8888-888888888888"', "\"nonce\":\"88888888-8888-8888-8888-888888888888\\n\""];
    }

    /** @dataProvider undecodable */
    public function testIllFormedMembersAreMalformed(string $from, string $to): void
    {
        $canonical = str_replace($from, $to, self::fixture()['audit_event']['canonical_signed_json']);
        if ($from === '"outcome":"Success"') {
            $canonical = str_replace('"outcome":"Success","ip_address":"203.0.113.7","metadata":{"method":"password"}', '"outcome":"Success","ip_address":"203.0.113.7","metadata":[1]', self::fixture()['audit_event']['canonical_signed_json']);
        }
        $wire = substr($canonical, 0, -1) . ',"hmac_signature":"' . hash_hmac('sha256', $canonical, self::subkey()) . '"}';
        [$consumer, $logger] = self::consumer(SignedEventType::AuditEventMessage);

        self::deliver($consumer, $wire);

        self::assertSame('malformed', $logger->records[0]['context']['reason']);
    }
}
