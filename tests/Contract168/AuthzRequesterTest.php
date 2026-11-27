<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract168;

use Axiam\Sdk\Amqp\AmqpLibAuthzTransport;
use Axiam\Sdk\Amqp\AuthzDecision;
use Axiam\Sdk\Amqp\AuthzDelivery;
use Axiam\Sdk\Amqp\AuthzRequester;
use Axiam\Sdk\Amqp\AuthzTransport;
use Axiam\Sdk\Amqp\StrictJson;
use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Core\NetworkError;
use PhpAmqpLib\Channel\AMQPChannel;
use PhpAmqpLib\Message\AMQPMessage;
use PHPUnit\Framework\TestCase;
use Psr\Log\AbstractLogger;

/** A scripted, broker-free {@see AuthzTransport}. */
class FakeAuthzTransport implements AuthzTransport
{
    public string $queue = 'amq.gen-Xk3p';

    /** @var list<array{queue: string, replyTo: string, correlationId: string, body: string}> */
    public array $published = [];

    /** @var list<string|\Closure(array<string,mixed>): string> bodies (or functions of the last published request) to deliver, one per wait() */
    public array $script = [];

    /** @var list<FakeAuthzDelivery> */
    public array $deliveries = [];

    public bool $closed = false;

    /** @var callable(AuthzDelivery): void */
    private $onDelivery;

    public function declareReplyQueue(callable $onDelivery): string
    {
        $this->onDelivery = $onDelivery;

        return $this->queue;
    }

    public function publishRequest(string $queue, string $replyTo, string $correlationId, string $body): void
    {
        $this->published[] = ['queue' => $queue, 'replyTo' => $replyTo, 'correlationId' => $correlationId, 'body' => $body];
    }

    public function wait(float $timeoutSeconds): bool
    {
        if ($this->script === []) {
            usleep(1000); // an idle tick
            return true;
        }
        $next = array_shift($this->script);
        if ($next instanceof \Closure) {
            $last = end($this->published);
            $request = is_array($last) ? json_decode($last['body'], true) : [];
            $next = $next(is_array($request) ? $request : []);
        }
        $delivery = new FakeAuthzDelivery($next);
        $this->deliveries[] = $delivery;
        ($this->onDelivery)($delivery);

        return true;
    }

    public function close(): void
    {
        $this->closed = true;
    }
}

final class FakeAuthzDelivery implements AuthzDelivery
{
    public int $acked = 0;

    public int $nacked = 0;

    public function __construct(private readonly string $body)
    {
    }

    public function body(): string
    {
        return $this->body;
    }

    public function ack(): void
    {
        $this->acked++;
    }

    public function nackNoRequeue(): void
    {
        $this->nacked++;
    }
}

/**
 * Security audit 2026-11-14, N2 (CONTRACT.md §8 "Signed authorization responses", contract 1.68;
 * D-9): the AMQP authorization requester. None of the SDKs had one, so N2 does not reproduce as a
 * defect of this SDK; the owner decided it gains the requester anyway, mirroring the Go reference.
 * Every test here is a plain pass/fail of new behaviour.
 */
final class AuthzRequesterTest extends TestCase
{
    // Contract 1.68 §8 test vectors.
    private const MASTER_KEY_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    private const SUBKEY_HEX = '919e125ec83799c1e113a27707cac5008a2608d0557e00dfe1b3a316abed4b89';
    private const TENANT = '11111111-1111-1111-1111-111111111111';
    private const OTHER_TENANT = '99999999-9999-9999-9999-999999999999';
    private const CORRELATION = '22222222-2222-2222-2222-222222222222';
    private const NONCE = '55555555-5555-5555-5555-555555555555';
    private const SUBJECT = '33333333-3333-3333-3333-333333333333';
    private const RESOURCE = '44444444-4444-4444-4444-444444444444';

    /** @var list<array{name: string, canonical: string, sig: string, allowed: bool, reason: ?string, code: string}> */
    private const VECTORS = [
        [
            'name' => '1 allow',
            'canonical' => '{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":true,"reason_code":"allowed","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}',
            'sig' => '8d81f0437df6c6fffafd13f4265bd41d3cfd6fcbf7c251b3bb79e0846578574a',
            'allowed' => true, 'reason' => null, 'code' => 'allowed',
        ],
        [
            'name' => '2 deny no_grant',
            'canonical' => '{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"no permission grants action \'documents:read\'","reason_code":"no_grant","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}',
            'sig' => 'f3105ee678acd79da6ffd28c02b86311e16bb8d8dfd3fd0addbacdf73bd5a400',
            'allowed' => false, 'reason' => "no permission grants action 'documents:read'", 'code' => 'no_grant',
        ],
        [
            'name' => '3 deny denied_by_rule',
            'canonical' => '{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"an explicit deny rule refuses action \'documents:read\'","reason_code":"denied_by_rule","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}',
            'sig' => '4bfc2ce9a035bd4a028ee2a5cb75a08832915c60cd2b176c8d4bf28910a61adc',
            'allowed' => false, 'reason' => "an explicit deny rule refuses action 'documents:read'", 'code' => 'denied_by_rule',
        ],
        [
            'name' => '4 escapes encoders disagree on',
            'canonical' => '{"correlation_id":"22222222-2222-2222-2222-222222222222","allowed":false,"reason":"no permission grants action \'docs:a&b</\\"c\\">/é€\'","reason_code":"no_grant","tenant_id":"11111111-1111-1111-1111-111111111111","nonce":"55555555-5555-5555-5555-555555555555"}',
            'sig' => '5194142df4bf66b07e9e8d516caf6be099af025219ab12deb26fea39e93490ff',
            'allowed' => false, 'reason' => 'no permission grants action \'docs:a&b</"c">/é€\'', 'code' => 'no_grant',
        ],
    ];

    private static function subkey(): string
    {
        return (string) hex2bin(self::SUBKEY_HEX);
    }

    /** HKDF-SHA256(salt, ikm = master, info = "axiam-amqp-v1" || key_version || tenant_id raw 16 bytes), the contract's derivation. */
    private static function subkeyFor(string $tenant, int $keyVersion): string
    {
        $info = 'axiam-amqp-v1' . chr($keyVersion) . (string) hex2bin(str_replace('-', '', $tenant));

        return hash_hkdf('sha256', (string) hex2bin(self::MASTER_KEY_HEX), 32, $info, 'axiam-amqp-hkdf-salt-v1');
    }

    /** @param array{canonical: string, sig: string} $vector */
    private static function wire(array $vector): string
    {
        return substr($vector['canonical'], 0, -1) . ',"hmac_signature":"' . $vector['sig'] . '"}';
    }

    private static function signWith(string $key, string $canonical): string
    {
        return substr($canonical, 0, -1) . ',"hmac_signature":"' . hash_hmac('sha256', $canonical, $key) . '"}';
    }

    private function logger(): object
    {
        return new class () extends AbstractLogger {
            /** @var list<string> */
            public array $lines = [];

            /** @var list<array{level: mixed, message: string, context: array<string,mixed>}> */
            public array $records = [];

            public function log(mixed $level, string|\Stringable $message, array $context = []): void
            {
                $this->lines[] = (string) $message;
                $this->records[] = ['level' => $level, 'message' => (string) $message, 'context' => $context];
            }

            /** Everything one record says, message and context together, as a searchable string. */
            public function serialized(): string
            {
                return (string) json_encode($this->records);
            }
        };
    }

    /** A requester whose request ids are the vectors' (the correlation_id, then the nonce). */
    private function vectorRequester(FakeAuthzTransport $transport, ?object $logger = null, float $timeout = 2.0): AuthzRequester
    {
        $ids = [self::CORRELATION, self::NONCE];
        $generator = static function () use (&$ids): string {
            return array_shift($ids) ?? 'ffffffff-ffff-ffff-ffff-ffffffffffff';
        };

        return new AuthzRequester(
            $transport,
            self::TENANT,
            self::subkey(),
            logger: $logger ?? new \Psr\Log\NullLogger(),
            timeoutSeconds: $timeout,
            idGenerator: $generator,
            clock: static fn (): int => 1_783_684_800,
        );
    }

    private function check(AuthzRequester $requester): AuthzDecision
    {
        return $requester->check(self::SUBJECT, 'documents:read', self::RESOURCE, 'confidential');
    }

    // ---- the vectors ---------------------------------------------------------------

    public function testTheTestsOwnHkdfDerivationMatchesTheContractsSubkey(): void
    {
        self::assertSame(self::SUBKEY_HEX, bin2hex(self::subkeyFor(self::TENANT, 2)));
    }

    /** @return iterable<string, array{int}> */
    public static function vectorIndexes(): iterable
    {
        foreach (self::VECTORS as $i => $vector) {
            yield $vector['name'] => [$i];
        }
    }

    /** @dataProvider vectorIndexes */
    public function testEachContractVectorVerifiesByteForByte(int $index): void
    {
        $vector = self::VECTORS[$index];
        $transport = new FakeAuthzTransport();
        $transport->script = [self::wire($vector)];
        $requester = $this->vectorRequester($transport);

        $decision = $this->check($requester);

        self::assertSame($vector['allowed'], $decision->allowed);
        self::assertSame($vector['reason'], $decision->reason);
        self::assertSame($vector['code'], $decision->reasonCode);
        self::assertSame(1, $transport->deliveries[0]->acked, 'an accepted response is acked');

        // Retired on acceptance: the same response again is dropped (nacked, no requeue).
        $again = new FakeAuthzDelivery(self::wire($vector));
        $requester->handleDelivery($again);
        self::assertSame(1, $again->nacked);
        self::assertSame(0, $again->acked);
    }

    public function testAResponseSignedOverEscapedBytesVerifiesBecauseTheReceivedBytesAreWhatIsChecked(): void
    {
        // C2: "é" and "€" sent as the escapes \u00e9 and \u20ac (single-quoted PHP, so the backslash
        // is in the bytes). A verifier that decoded and RE-SERIALIZED the body would produce a raw
        // "é" or "\u00e9" and fail a genuine signature; this one cuts the signature out of the
        // received bytes and checks those, then decodes the same bytes.
        $canonical = '{"correlation_id":"' . self::CORRELATION . '","allowed":false,"reason":"caf\u00e9 \/ \u20ac","reason_code":"no_grant","tenant_id":"' . self::TENANT . '","nonce":"' . self::NONCE . '"}';
        self::assertStringContainsString('\\u00e9', $canonical, 'the escape is in the bytes that are signed');
        self::assertStringNotContainsString('é', $canonical, 'and no raw é is');
        $transport = new FakeAuthzTransport();
        $transport->script = [self::signWith(self::subkey(), $canonical)];

        $decision = $this->check($this->vectorRequester($transport));

        self::assertFalse($decision->allowed);
        self::assertSame('café / €', $decision->reason, 'the decision is decoded from the verified bytes');
    }

    // ---- what is discarded ---------------------------------------------------------

    /** @return iterable<string, array{string}> bodies that must be discarded, never completed, never an allow */
    public static function discardedBodies(): iterable
    {
        $v1 = self::VECTORS[0];
        $v2 = self::VECTORS[1];
        $good = self::subkey();
        $flip = static fn (array $v, string $from, string $to): string => str_replace($from, $to, self::wire($v));

        yield "vector 1 under another tenant's subkey" => [self::signWith(self::subkeyFor(self::OTHER_TENANT, 2), $v1['canonical'])];
        yield 'vector 1 under key_version 3' => [self::signWith(self::subkeyFor(self::TENANT, 3), $v1['canonical'])];
        yield 'tampered decision: allowed flipped to false, signature kept' => [$flip($v1, '"allowed":true', '"allowed":false')];
        yield 'tampered decision: vector 2 flipped to true, signature kept' => [$flip($v2, '"allowed":false', '"allowed":true')];
        yield 'tampered reason_code' => [$flip($v2, 'no_grant', 'allowed')];
        yield 'response for another nonce' => [self::signWith($good, str_replace(self::NONCE, '66666666-6666-6666-6666-666666666666', $v1['canonical']))];
        yield 'response for another correlation_id' => [self::signWith($good, str_replace(self::CORRELATION, '77777777-7777-7777-7777-777777777777', $v1['canonical']))];
        yield 'response for another tenant (validly signed with our key)' => [self::signWith($good, str_replace(self::TENANT, self::OTHER_TENANT, $v1['canonical']))];
        yield 'no allowed: a signed AuthzRequest on the response queue' => [self::signWith($good, '{"correlation_id":"' . self::CORRELATION . '","tenant_id":"' . self::TENANT . '","subject_id":"' . self::SUBJECT . '","action":"documents:read","resource_id":"' . self::RESOURCE . '","key_version":2,"nonce":"' . self::NONCE . '","issued_at":"2026-07-10T12:00:00Z"}')];
        yield 'allowed not a boolean' => [self::signWith($good, str_replace('"allowed":true', '"allowed":"true"', $v1['canonical']))];
        yield 'no tenant_id' => [self::signWith($good, str_replace('"tenant_id":"' . self::TENANT . '",', '', $v1['canonical']))];
        yield 'no nonce' => [self::signWith($good, str_replace(',"nonce":"' . self::NONCE . '"', '', $v1['canonical']))];
        yield 'signature not the trailing member' => [str_replace('"allowed":true', '"allowed":true,"x":1', self::wire($v1))];
        yield 'duplicate allowed keys, validly signed' => [self::signWith($good, str_replace('"allowed":true', '"allowed":false,"allowed":true', $v1['canonical']))];
        yield 'case-variant allowed key, validly signed' => [self::signWith($good, str_replace('"reason_code"', '"ALLOWED":false,"reason_code"', $v1['canonical']))];
        yield 'trailing whitespace after the closing brace' => [self::wire($v1) . "\n"];
        yield 'non-hex signature' => [str_replace($v1['sig'], str_repeat('z', 64), self::wire($v1))];
        yield 'short signature' => [str_replace($v1['sig'], substr($v1['sig'], 0, 62), self::wire($v1))];
        yield 'a null hmac_signature is a signature member, not an absent one' => ['{"correlation_id":"' . self::CORRELATION . '","allowed":true,"hmac_signature":null}'];
        yield 'reason of the wrong type, validly signed' => [self::signWith($good, str_replace('"reason_code":"allowed"', '"reason":7,"reason_code":"allowed"', $v1['canonical']))];
        yield 'not JSON' => ['not json'];
        yield 'a JSON array' => ['[true]'];
        yield 'empty' => [''];
    }

    /** @dataProvider discardedBodies */
    public function testADiscardedResponseIsNackedNeverAnAllowAndLeavesTheRequestWaitingForTheGenuineAnswer(string $body): void
    {
        $logger = $this->logger();
        $transport = new FakeAuthzTransport();
        $transport->script = [$body, self::wire(self::VECTORS[0])];

        $decision = $this->check($this->vectorRequester($transport, $logger));

        // The genuine vector 1 (allow) is what completed the request; the bad body never did.
        self::assertTrue($decision->allowed);
        self::assertSame('allowed', $decision->reasonCode);
        self::assertSame(1, $transport->deliveries[0]->nacked, 'the bad response is nacked without requeue');
        self::assertSame(0, $transport->deliveries[0]->acked);
        self::assertSame(1, $transport->deliveries[1]->acked);
        self::assertNotEmpty($logger->lines, 'a security event is logged');
        foreach ($logger->lines as $line) {
            self::assertStringNotContainsString(self::VECTORS[0]['sig'], $line, 'never a signature value');
            self::assertStringContainsString('axiam_sdk_security', $line);
        }
    }

    // ---- the discard event (contract 1.69, #883; Appendix A.2) --------------------------

    /**
     * Every discard path logs ONE warning with exactly: timestamp, exchange, routing_key,
     * tenant_id (the requester's OWN) and reason, and nothing read from the body.
     *
     * @return iterable<string, array{string, string}> [body, expected reason]
     */
    public static function reasonCases(): iterable
    {
        $v1 = self::VECTORS[0];
        yield 'signature: another tenant\'s subkey' => [self::signWith(self::subkeyFor(self::OTHER_TENANT, 2), $v1['canonical']), 'signature'];
        yield 'signature: tampered decision' => [str_replace('"allowed":true', '"allowed":false', self::wire($v1)), 'signature'];
        yield 'tenant: validly signed for another tenant' => [self::signWith(self::subkey(), str_replace(self::TENANT, self::OTHER_TENANT, $v1['canonical'])), 'tenant'];
        yield 'unsigned: no signature member' => [self::unsigned(), 'unsigned'];
        yield 'unknown_request: another correlation_id' => [self::signWith(self::subkey(), str_replace(self::CORRELATION, '77777777-7777-7777-7777-777777777777', $v1['canonical'])), 'unknown_request'];
        yield 'unknown_request: another nonce' => [self::signWith(self::subkey(), str_replace(self::NONCE, '66666666-6666-6666-6666-666666666666', $v1['canonical'])), 'unknown_request'];
        yield 'malformed: not JSON' => ['not json', 'malformed'];
        yield 'malformed: not an object' => ['[true]', 'malformed'];
        yield 'malformed: duplicate keys' => [self::signWith(self::subkey(), str_replace('"allowed":true', '"allowed":false,"allowed":true', $v1['canonical'])), 'malformed'];
        yield 'malformed: allowed not a boolean' => [str_replace('"allowed":true', '"allowed":"true"', self::wire($v1)), 'malformed'];
        yield 'malformed: signature not hex' => [str_replace($v1['sig'], str_repeat('z', 64), self::wire($v1)), 'malformed'];
        yield 'signature: a member inserted into signed bytes' => [str_replace('"allowed":true', '"allowed":true,"x":1', self::wire($v1)), 'signature'];
        yield 'malformed: signature member not the trailing one' => [str_replace('"nonce":"' . self::NONCE . '"', '"hmac_signature":"' . $v1['sig'] . '","nonce":"' . self::NONCE . '"', $v1['canonical']), 'malformed'];
        yield 'malformed: validly signed, no nonce' => [self::signWith(self::subkey(), str_replace(',"nonce":"' . self::NONCE . '"', '', $v1['canonical'])), 'malformed'];
        // Contract 1.69 §8 normative order: (2) no signature member is unsigned whatever else is missing;
        // (3) a missing/ill-typed allowed, tenant_id, nonce or correlation_id is malformed BEFORE the HMAC (4).
        yield 'unsigned: neither hmac_signature nor allowed' => ['{"correlation_id":"' . self::CORRELATION . '"}', 'unsigned'];
        yield 'unsigned: only a stray member' => ['{"x":1}', 'unsigned'];
        yield 'malformed: bad HMAC and no nonce' => [str_replace(',"nonce":"' . self::NONCE . '"', '', self::wire($v1)), 'malformed'];
        yield 'malformed: bad HMAC and no tenant_id' => [str_replace('"tenant_id":"' . self::TENANT . '",', '', self::wire($v1)), 'malformed'];
        yield 'malformed: bad HMAC and no correlation_id' => [str_replace('"correlation_id":"' . self::CORRELATION . '",', '', self::wire($v1)), 'malformed'];
        yield 'malformed: bad HMAC and a non-string nonce' => [str_replace('"nonce":"' . self::NONCE . '"', '"nonce":5', self::wire($v1)), 'malformed'];
        yield 'signature: well-formed, bad HMAC, another tenant (HMAC before tenant)' => [str_replace(self::TENANT, self::OTHER_TENANT, self::wire($v1)), 'signature'];
        yield 'tenant: good HMAC, another tenant and unknown request (tenant before unknown_request)' => [self::signWith(self::subkey(), str_replace([self::TENANT, self::CORRELATION], [self::OTHER_TENANT, '77777777-7777-7777-7777-777777777777'], $v1['canonical'])), 'tenant'];
        // Contract 1.69 §8 step 2a (D-10): the first byte must be `{`; a byte-order mark or any
        // prefix is refused, never stripped, and the request keeps waiting for the genuine answer.
        yield 'malformed: a byte-order mark before the object' => ["\xEF\xBB\xBF" . self::wire($v1), 'malformed'];
        yield 'malformed: leading whitespace, signed over it' => [self::signWith(self::subkey(), ' ' . $v1['canonical']), 'malformed'];
        yield 'malformed: not UTF-8' => ["\xff\xfe\x00{", 'malformed'];
        yield 'malformed: a null signature member' => ['{"correlation_id":"' . self::CORRELATION . '","allowed":true,"hmac_signature":null}', 'malformed'];
    }

    /** @dataProvider reasonCases */
    public function testEveryDiscardPathLogsOneEventWithTheRoutingKeyTheOwnTenantAndTheReasonAndNoSecret(string $body, string $reason): void
    {
        $logger = $this->logger();
        $transport = new FakeAuthzTransport();
        $transport->queue = 'amq.gen-ReplyQ1';
        $transport->script = [$body, self::wire(self::VECTORS[0])];

        $this->check($this->vectorRequester($transport, $logger));

        self::assertCount(1, $logger->records, 'one event per discard');
        $record = $logger->records[0];
        self::assertSame('warning', $record['level']);
        self::assertSame(
            ['timestamp', 'exchange', 'routing_key', 'tenant_id', 'reason'],
            array_keys($record['context']),
            'exactly the Appendix A.2 members',
        );
        self::assertSame($reason, $record['context']['reason']);
        self::assertSame('amq.gen-ReplyQ1', $record['context']['routing_key'], 'the requester\'s own reply queue');
        self::assertSame(self::TENANT, $record['context']['tenant_id'], 'the requester\'s own tenant');
        self::assertSame('', $record['context']['exchange'], 'the default exchange');
        self::assertSame('2026-07-10T12:00:00Z', $record['context']['timestamp'], 'RFC 3339 UTC');

        // Nothing from the body and no secret anywhere in the event, message included.
        $event = $logger->serialized();
        self::assertStringNotContainsString(self::VECTORS[0]['sig'], $event);
        self::assertStringNotContainsString(self::VECTORS[1]['sig'], $event);
        self::assertStringNotContainsString(self::NONCE, $event);
        self::assertStringNotContainsString(self::CORRELATION, $event);
        self::assertStringNotContainsString(bin2hex(self::subkey()), $event);
        self::assertStringNotContainsString(self::OTHER_TENANT, $event, 'never the tenant the response claims');
        if (preg_match('/[0-9a-f]{64}/', $body, $m) === 1) {
            self::assertStringNotContainsString($m[0], $event, 'the received signature value');
        }
    }

    public function testTheSignatureEventNeverCarriesTheComputedSignatureEither(): void
    {
        $logger = $this->logger();
        $transport = new FakeAuthzTransport();
        $canonical = self::VECTORS[0]['canonical'];
        $transport->script = [str_replace('"allowed":true', '"allowed":false', self::wire(self::VECTORS[0])), self::wire(self::VECTORS[0])];

        $this->check($this->vectorRequester($transport, $logger));

        $tamperedCanonical = str_replace('"allowed":true', '"allowed":false', $canonical);
        $computed = hash_hmac('sha256', $tamperedCanonical, self::subkey());
        self::assertStringNotContainsString($computed, $logger->serialized());
    }

    public function testAForgedAllowAloneNeverCompletesTheRequest(): void
    {
        // A forged allow carrying the right ids and a wrong key, and nothing after it: the
        // request is NOT completed and NOT allowed; it times out.
        $forged = self::signWith(self::subkeyFor(self::OTHER_TENANT, 2), self::VECTORS[0]['canonical']);
        $transport = new FakeAuthzTransport();
        $transport->script = [$forged];
        $requester = $this->vectorRequester($transport, null, 0.05);

        $this->expectException(NetworkError::class);
        $this->check($requester);
    }

    // ---- unsigned (contract 1.69, #881: there is no opt-out) -------------------------

    private static function unsigned(string $correlationId = self::CORRELATION): string
    {
        return '{"correlation_id":"' . $correlationId . '","allowed":true,"reason_code":"allowed"}';
    }

    public function testAnUnsignedResponseIsDiscardedWithReasonUnsignedAndTheCheckKeepsWaiting(): void
    {
        $logger = $this->logger();
        $transport = new FakeAuthzTransport();
        $transport->script = [self::unsigned(), self::wire(self::VECTORS[1])];

        $decision = $this->check($this->vectorRequester($transport, $logger));

        self::assertFalse($decision->allowed, 'the unsigned allow was refused and the signed deny is what completed the request');
        self::assertSame(1, $transport->deliveries[0]->nacked);
        self::assertSame(0, $transport->deliveries[0]->acked);
        self::assertCount(1, $logger->records, 'one discard event');
        self::assertSame('unsigned', $logger->records[0]['context']['reason'] ?? null);
    }

    public function testAnUnsignedResponseNeverCompletesARequestEvenWhenItIsTheOnlyAnswer(): void
    {
        $transport = new FakeAuthzTransport();
        $transport->script = [self::unsigned()];

        $this->expectException(NetworkError::class);
        $this->check($this->vectorRequester($transport, null, 0.05));
    }

    public function testThereIsNoOptOutForUnsignedResponses(): void
    {
        $parameters = array_map(
            static fn (\ReflectionParameter $p): string => $p->getName(),
            (new \ReflectionMethod(AuthzRequester::class, '__construct'))->getParameters(),
        );
        foreach ($parameters as $name) {
            self::assertStringNotContainsStringIgnoringCase('unsigned', $name, 'AuthzRequester::__construct() must not offer an unsigned-response option');
        }
        self::assertFalse(
            (new \ReflectionClass(AuthzDecision::class))->hasProperty('unsigned'),
            'a decision is never "unsigned": an unsigned response is not a decision',
        );
    }

    // ---- end to end ----------------------------------------------------------------

    public function testCheckPublishesASignedRequestWithAPrivateReplyToAndFreshUnpredictableIds(): void
    {
        $transport = new FakeAuthzTransport();
        $requester = new AuthzRequester($transport, self::TENANT, self::subkey(), timeoutSeconds: 3.0, clock: static fn (): int => 1_783_684_800);
        $answer = static fn (array $request): string => self::signWith(
            self::subkey(),
            '{"correlation_id":"' . $request['correlation_id'] . '","allowed":true,"reason_code":"allowed","tenant_id":"' . self::TENANT . '","nonce":"' . $request['nonce'] . '"}',
        );
        $transport->script = [$answer, $answer];

        self::assertSame('amq.gen-Xk3p', $requester->replyTo());
        $first = $requester->check(self::SUBJECT, 'docs:a&b</"c">/é€', self::RESOURCE, 'confidential');
        $second = $requester->check(strtoupper(self::SUBJECT), 'documents:read', strtoupper(self::RESOURCE));

        self::assertTrue($first->allowed);
        self::assertTrue($second->allowed);
        self::assertCount(2, $transport->published);
        [$one, $two] = $transport->published;

        // The request: default-exchange routing to the request queue, a private reply_to, a
        // correlation_id property equal to the body's.
        self::assertSame('axiam.authz.request', $one['queue']);
        self::assertSame('amq.gen-Xk3p', $one['replyTo']);
        $body = json_decode($one['body'], true);
        self::assertSame($one['correlationId'], $body['correlation_id']);
        self::assertSame(self::TENANT, $body['tenant_id']);
        self::assertSame(2, $body['key_version']);
        self::assertSame('2026-07-10T12:00:00Z', $body['issued_at']);
        self::assertSame(['correlation_id', 'tenant_id', 'subject_id', 'action', 'resource_id', 'scope', 'key_version', 'nonce', 'issued_at', 'hmac_signature'], array_keys($body), 'the server\'s field order');
        self::assertSame(['correlation_id', 'tenant_id', 'subject_id', 'action', 'resource_id', 'key_version', 'nonce', 'issued_at', 'hmac_signature'], array_keys(json_decode($two['body'], true)), 'scope omitted, not null');
        self::assertSame(self::SUBJECT, json_decode($two['body'], true)['subject_id'], 'UUIDs are lower-cased');

        // Written as serde_json writes it: `/`, `<`, `>`, `&` and non-ASCII raw.
        self::assertStringContainsString('"action":"docs:a&b</\\"c\\">/é€"', $one['body']);

        // It verifies under the subkey over its canonical bytes (the signature member cut out).
        $suffix = ',"hmac_signature":"' . $body['hmac_signature'] . '"}';
        self::assertStringEndsWith($suffix, $one['body']);
        $canonical = substr($one['body'], 0, -strlen($suffix)) . '}';
        self::assertSame(hash_hmac('sha256', $canonical, self::subkey()), $body['hmac_signature']);

        // Fresh, distinct, independent ids per request.
        $bodyTwo = json_decode($two['body'], true);
        self::assertNotSame($one['correlationId'], $two['correlationId']);
        self::assertNotSame($body['nonce'], $bodyTwo['nonce']);
        self::assertNotSame($body['nonce'], $body['correlation_id']);
        self::assertSame(1, preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $body['nonce']), 'a random v4 UUID');
    }

    /** Contract 1.69 §8 "Canonical reference vectors": the producer emits exactly the fixture's `wire_json`. */
    public function testTheProducerEmitsTheReferenceVectorsWireJsonByteForByte(): void
    {
        $fixture = json_decode((string) file_get_contents(__DIR__ . '/../Fixtures/v2_reference_vectors.json'), true);
        self::assertIsArray($fixture);
        $subkey = hex2bin($fixture['hkdf']['derived_subkey_hex']);
        self::assertIsString($subkey);

        $transport = new FakeAuthzTransport();
        $requester = new AuthzRequester(
            $transport,
            self::TENANT,
            $subkey,
            timeoutSeconds: 0.03,
            idGenerator: (static function (): \Closure {
                $ids = [self::CORRELATION, self::NONCE];

                return static function () use (&$ids): string {
                    return array_shift($ids) ?? 'ffffffff-ffff-ffff-ffff-ffffffffffff';
                };
            })(),
            clock: static fn (): int => 1_783_684_800,
        );
        try {
            $requester->check(self::SUBJECT, 'documents:read', self::RESOURCE, 'confidential');
        } catch (NetworkError) {
            // nobody answers; only the published body matters
        }

        self::assertCount(1, $transport->published);
        self::assertSame($fixture['authz_request']['wire_json'], $transport->published[0]['body']);
    }

    public function testAForgedResponseWithTheRightIdsIsDiscardedAndTheGenuineOneCompletesTheCheck(): void
    {
        $transport = new FakeAuthzTransport();
        $requester = new AuthzRequester($transport, self::TENANT, self::subkey(), timeoutSeconds: 3.0);
        $canonical = static fn (array $r): string => '{"correlation_id":"' . $r['correlation_id'] . '","allowed":true,"reason_code":"allowed","tenant_id":"' . self::TENANT . '","nonce":"' . $r['nonce'] . '"}';
        $transport->script = [
            static fn (array $r): string => self::signWith(self::subkeyFor(self::OTHER_TENANT, 2), $canonical($r)),
            static fn (array $r): string => self::signWith(self::subkey(), $canonical($r)),
        ];

        $decision = $requester->check(self::SUBJECT, 'documents:read', self::RESOURCE);

        self::assertTrue($decision->allowed);
        self::assertSame(1, $transport->deliveries[0]->nacked, 'the forgery');
        self::assertSame(1, $transport->deliveries[1]->acked, 'the genuine answer');
    }

    public function testACheckTimesOutWithoutAnAnswerAndLeavesNothingOutstanding(): void
    {
        $transport = new FakeAuthzTransport();
        $requester = new AuthzRequester($transport, self::TENANT, self::subkey(), timeoutSeconds: 0.03);

        try {
            $requester->check(self::SUBJECT, 'a', self::RESOURCE);
            self::fail('a check with no answer must not return');
        } catch (NetworkError $e) {
            self::assertStringContainsString('timed out', $e->getMessage());
        }

        // A late answer for the abandoned request finds nothing outstanding.
        $published = $transport->published[0];
        $late = new FakeAuthzDelivery(self::signWith(self::subkey(), '{"correlation_id":"' . $published['correlationId'] . '","allowed":true,"tenant_id":"' . self::TENANT . '","nonce":"' . json_decode($published['body'], true)['nonce'] . '"}'));
        $requester->handleDelivery($late);
        self::assertSame(1, $late->nacked);
    }

    public function testAnAnswerArrivingAfterCloseIsNackedWithoutDecodingAndWithoutAnEvent(): void
    {
        $logger = $this->logger();
        $transport = new FakeAuthzTransport();
        $requester = $this->vectorRequester($transport, $logger, 0.03);
        try {
            $this->check($requester);
        } catch (NetworkError) {
            // no answer: the request is abandoned
        }
        $requester->close();

        // A delivery whose body would otherwise be discarded with an event (or accepted).
        foreach ([self::wire(self::VECTORS[0]), 'not json', self::unsigned()] as $body) {
            $late = new FakeAuthzDelivery($body);
            $requester->handleDelivery($late);
            self::assertSame(1, $late->nacked, 'nacked without requeue');
            self::assertSame(0, $late->acked);
        }
        self::assertSame([], $logger->records, 'no discard event after close');
    }

    public function testCloseReleasesTheTransportAndRefusesFurtherChecks(): void
    {
        $transport = new FakeAuthzTransport();
        $requester = new AuthzRequester($transport, self::TENANT, self::subkey());

        $requester->close();
        $requester->close(); // idempotent

        self::assertTrue($transport->closed);
        $this->expectException(NetworkError::class);
        $requester->check(self::SUBJECT, 'a', self::RESOURCE);
    }

    public function testALostReplyQueueIsAFailureNotASilentAllow(): void
    {
        $transport = new class () extends FakeAuthzTransport {
            public function wait(float $timeoutSeconds): bool
            {
                return false; // the session is gone
            }
        };
        $requester = new AuthzRequester($transport, self::TENANT, self::subkey());

        $this->expectException(NetworkError::class);
        $requester->check(self::SUBJECT, 'a', self::RESOURCE);
    }

    // ---- construction --------------------------------------------------------------

    /** @return iterable<string, array{string}> */
    public static function nonPrivateQueues(): iterable
    {
        yield 'empty' => [''];
        yield 'the shared response queue' => ['axiam.authz.response'];
        yield 'a server mail queue' => ['axiam.mail.outbound'];
        yield 'the request queue' => ['axiam.authz.request'];
    }

    /** @dataProvider nonPrivateQueues */
    public function testAReplyQueueThatIsNotPrivateIsRefused(string $queue): void
    {
        $transport = new FakeAuthzTransport();
        $transport->queue = $queue;

        try {
            new AuthzRequester($transport, self::TENANT, self::subkey());
            self::fail('reply queue "' . $queue . '" must be refused');
        } catch (AxiamException) {
            self::assertTrue($transport->closed);
        }
    }

    public function testInvalidConfigurationIsRefused(): void
    {
        foreach ([
            fn () => new AuthzRequester(new FakeAuthzTransport(), 'not-a-uuid', 'k'),
            fn () => new AuthzRequester(new FakeAuthzTransport(), self::TENANT, ''),
            fn () => new AuthzRequester(new FakeAuthzTransport(), self::TENANT, 'k', timeoutSeconds: 0.0),
            fn () => new AuthzRequester(new FakeAuthzTransport(), self::TENANT, 'k', timeoutSeconds: -1.0),
            fn () => new AuthzRequester(new FakeAuthzTransport(), self::TENANT, 'k', timeoutSeconds: NAN),
            fn () => new AuthzRequester(new FakeAuthzTransport(), self::TENANT, 'k', timeoutSeconds: INF),
            fn () => new AuthzRequester(new FakeAuthzTransport(), self::TENANT, 'k', timeoutSeconds: -INF),
        ] as $build) {
            try {
                $build();
                self::fail('must be refused');
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    /** @return iterable<string, array{float}> */
    public static function badTimeouts(): iterable
    {
        yield 'zero' => [0.0];
        yield 'negative' => [-1.0];
        yield 'NaN' => [NAN];
        yield 'infinity' => [INF];
        yield 'negative infinity' => [-INF];
    }

    /** @dataProvider badTimeouts */
    public function testAPerCallTimeoutThatIsNotFinitePositiveIsRefusedNotReplacedAndNothingIsPublished(float $timeout): void
    {
        // wait() fails the test loudly instead of blocking: a refused timeout must never reach it.
        $transport = new class () extends FakeAuthzTransport {
            public function wait(float $timeoutSeconds): bool
            {
                throw new \LogicException('the requester waited although the timeout was refused');
            }
        };
        $requester = new AuthzRequester($transport, self::TENANT, self::subkey(), timeoutSeconds: 0.05);

        try {
            $requester->check(self::SUBJECT, 'a', self::RESOURCE, null, $timeout);
            self::fail('a per-call timeout of ' . var_export($timeout, true) . ' must be refused');
        } catch (\InvalidArgumentException) {
            self::assertSame([], $transport->published, 'a refused call publishes nothing');
        }
    }

    public function testAFinitePositivePerCallTimeoutStillOverridesTheConstructorsAndBoundsTheWait(): void
    {
        $requester = new AuthzRequester(new FakeAuthzTransport(), self::TENANT, self::subkey(), timeoutSeconds: 60.0);

        $started = microtime(true);
        try {
            $requester->check(self::SUBJECT, 'a', self::RESOURCE, null, 0.03);
            self::fail('no answer arrives');
        } catch (NetworkError) {
            self::assertLessThan(5.0, microtime(true) - $started, 'the per-call bound, not the constructor\'s 60 s, applied');
        }
    }

    public function testRequestsThatCannotBeSignedByteExactlyAreRefused(): void
    {
        $requester = new AuthzRequester(new FakeAuthzTransport(), self::TENANT, 'k');
        foreach ([
            ['not-a-uuid', 'a', self::RESOURCE],
            [self::SUBJECT, 'a', 'not-a-uuid'],
            [self::SUBJECT, "a\xffb", self::RESOURCE], // invalid UTF-8: json_encode would have to repair it
        ] as [$subject, $action, $resource]) {
            try {
                $requester->check($subject, $action, $resource);
                self::fail('must be refused');
            } catch (\InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testNothingIsOutstandingAfterARefusedRequest(): void
    {
        $transport = new FakeAuthzTransport();
        $requester = new AuthzRequester($transport, self::TENANT, self::subkey(), timeoutSeconds: 0.02);
        try {
            $requester->check('not-a-uuid', 'a', self::RESOURCE);
        } catch (\InvalidArgumentException) {
        }

        self::assertSame([], $transport->published, 'a request that could not be built is never published');
    }

    // ---- strict JSON ---------------------------------------------------------------

    /** @return iterable<string, array{string, bool}> */
    public static function strictJsonCases(): iterable
    {
        yield 'plain object' => ['{"a":1,"b":{"c":[1,{"d":2}]}}', false];
        yield 'empty object' => ['{}', false];
        yield 'duplicate top-level key' => ['{"a":1,"a":2}', true];
        // single-quoted: the backslash-u is in the bytes, so the second key is "a" spelled as an escape.
        yield 'duplicate through an escape' => ['{"a":1,"\\u0061":2}', true];
        yield 'top-level duplicate through an escape, the decision member' => ['{"allowed":false,"\\u0061llowed":true}', true];
        yield 'duplicate nested key' => ['{"a":{"b":1,"b":2}}', true];
        yield 'duplicate inside an array element' => ['{"a":[{"b":1,"b":2}]}', true];
        yield 'case-variant top-level keys' => ['{"allowed":true,"ALLOWED":false}', true];
        yield 'case-variant nested keys are legitimate data' => ['{"a":{"b":1,"B":2}}', false];
        yield 'a string value that looks like a key' => ['{"a":"\"b\":1,\"b\":2"}', false];
        yield 'not an object' => ['[1]', true];
        yield 'a scalar' => ['true', true];
        yield 'malformed' => ['{"a":', true];
        yield 'trailing garbage' => ['{"a":1} x', true];
    }

    /** @dataProvider strictJsonCases */
    public function testStrictJson(string $body, bool $ambiguous): void
    {
        self::assertSame($ambiguous, StrictJson::isAmbiguousObject($body), $body);
    }

    // ---- the php-amqplib adapter ---------------------------------------------------

    public function testTheAmqpLibTransportDeclaresAPrivateExclusiveReplyQueueAndPublishesOnTheDefaultExchange(): void
    {
        $channel = $this->createMock(AMQPChannel::class);
        $consumeCallback = null;
        $channel->expects(self::once())->method('queue_declare')
            // empty name (broker-named), not passive, not durable, EXCLUSIVE, auto-delete
            ->with('', false, false, true, true)
            ->willReturn(['amq.gen-abc', 0, 0]);
        $channel->expects(self::once())->method('basic_consume')
            ->willReturnCallback(static function (string $queue, string $tag, bool $noLocal, bool $noAck, bool $exclusive, bool $noWait, callable $callback) use (&$consumeCallback): string {
                self::assertSame('amq.gen-abc', $queue);
                self::assertFalse($noAck, 'manual acknowledgement');
                self::assertTrue($exclusive, 'an exclusive consumer');
                $consumeCallback = $callback;

                return 'tag';
            });
        $published = [];
        $channel->expects(self::once())->method('basic_publish')
            ->willReturnCallback(static function (AMQPMessage $message, string $exchange, string $routingKey) use (&$published): void {
                $published = [$message, $exchange, $routingKey];
            });

        $transport = new AmqpLibAuthzTransport($channel);
        $received = [];
        self::assertSame('amq.gen-abc', $transport->declareReplyQueue(static function (AuthzDelivery $d) use (&$received): void {
            $received[] = $d->body();
        }));
        $transport->publishRequest('axiam.authz.request', 'amq.gen-abc', 'cid-1', '{"x":1}');

        [$message, $exchange, $routingKey] = $published;
        self::assertSame('', $exchange, 'the default exchange');
        self::assertSame('axiam.authz.request', $routingKey);
        self::assertSame('amq.gen-abc', $message->get('reply_to'));
        self::assertSame('cid-1', $message->get('correlation_id'));
        self::assertSame('{"x":1}', $message->getBody());

        self::assertNotNull($consumeCallback);
        $consumeCallback(new AMQPMessage('body-1'));
        self::assertSame(['body-1'], $received);
    }
}
