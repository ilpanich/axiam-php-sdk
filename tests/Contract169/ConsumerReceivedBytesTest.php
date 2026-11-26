<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract169;

use Axiam\Sdk\Amqp\Consumer;
use Axiam\Sdk\Amqp\Hmac;
use Axiam\Sdk\Amqp\ReplayGuard;
use PHPUnit\Framework\TestCase;

/**
 * axiam#882: the AMQP event consumer verifies the HMAC over the bytes the broker delivered (the
 * body with its trailing `hmac_signature` member cut out) and hands the handler a value parsed
 * from those same bytes, never from a re-serialization.
 *
 * Every body here is built the way the server writes one: a compact JSON object whose last member
 * is `"hmac_signature":"<64 hex>"`, signed over the bytes before it. The `action` is written by
 * hand, byte for byte, so each test controls exactly which escapes are on the wire.
 */
final class ConsumerReceivedBytesTest extends TestCase
{
    private const KEY = 'consumer-received-bytes-test-key';
    private const NOW = 1_800_000_000;

    /** The signed message as the server writes it, with `$actionJson` as the raw JSON text of `action`. */
    private static function canonical(string $actionJson, string $nonce = 'nonce-1'): string
    {
        return '{"correlation_id":"11111111-1111-1111-1111-111111111111","tenant_id":"22222222-2222-2222-2222-222222222222",'
            . '"subject_id":"33333333-3333-3333-3333-333333333333","action":' . $actionJson . ','
            . '"resource_id":"44444444-4444-4444-4444-444444444444","key_version":2,"nonce":"' . $nonce . '",'
            . '"issued_at":"' . (new \DateTimeImmutable('@' . self::NOW))->format('Y-m-d\TH:i:s\Z') . '"}';
    }

    private static function sign(string $canonical): string
    {
        return substr($canonical, 0, -1) . ',"hmac_signature":"' . hash_hmac('sha256', $canonical, self::KEY) . '"}';
    }

    /**
     * @return array{acked: int, nackedNoRequeue: int, nackedRequeue: int, calls: list<array<string,mixed>>}
     */
    private static function deliver(string $body): array
    {
        $result = ['acked' => 0, 'nackedNoRequeue' => 0, 'nackedRequeue' => 0, 'calls' => []];
        $consumer = new Consumer(self::KEY, replayGuard: new ReplayGuard(300, static fn (): int => self::NOW));
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
        );

        return $result;
    }

    /** @return iterable<string, array{string, string}> [raw JSON text of action, the decoded value] */
    public static function genuineActions(): iterable
    {
        yield 'less-than' => ['"a<b"', 'a<b'];
        yield 'greater-than' => ['"a>b"', 'a>b'];
        yield 'ampersand' => ['"a&b"', 'a&b'];
        yield 'all three with a slash and a quote' => ['"docs:a&b</\\"c\\">/x"', 'docs:a&b</"c">/x'];
        yield 'raw non-ASCII' => ['"café €"', 'café €'];
        // The backslash-u IS in the bytes (single-quoted PHP): an encoder that decodes and
        // re-serializes writes a raw é and no longer matches what was signed.
        yield 'a \u escape' => ['"caf\u00e9"', 'café'];
        yield 'an escaped slash' => ['"a\/b"', 'a/b'];
        yield 'a surrogate-pair escape' => ['"\ud83d\ude00"', "\u{1F600}"];
    }

    /** @dataProvider genuineActions */
    public function testAGenuineMessageVerifiesAndTheHandlerGetsAValueParsedFromTheVerifiedBytes(string $actionJson, string $decoded): void
    {
        $body = self::sign(self::canonical($actionJson));

        self::assertTrue(Hmac::verify(self::KEY, $body), 'Hmac::verify');
        $result = self::deliver($body);

        self::assertSame(1, $result['acked']);
        self::assertSame(0, $result['nackedNoRequeue']);
        self::assertCount(1, $result['calls']);
        self::assertSame($decoded, $result['calls'][0]['action']);
        self::assertArrayNotHasKey('hmac_signature', $result['calls'][0]);
    }

    public function testAnAuditEventMessageWithItsOptionalMembersVerifiesAndReachesTheHandlerUnchanged(): void
    {
        $canonical = '{"tenant_id":"22222222-2222-2222-2222-222222222222","actor_id":"u1","actor_type":"user","action":"a<b>&c",'
            . '"outcome":"success","metadata":{"a":"x<y","b":"caf","c":"z&"},"key_version":2,"nonce":"nonce-2","issued_at":"'
            . (new \DateTimeImmutable('@' . self::NOW))->format('Y-m-d\TH:i:s\Z') . '"}';

        $result = self::deliver(self::sign($canonical));

        self::assertSame(1, $result['acked']);
        self::assertSame(json_decode($canonical, true), $result['calls'][0]);
    }

    public function testTheHandlerValueIsExactlyWhatTheVerifiedBytesDecodeTo(): void
    {
        $canonical = self::canonical('"caf\u00e9 <&>"');
        $result = self::deliver(self::sign($canonical));

        self::assertSame(json_decode($canonical, true), $result['calls'][0]);
    }

    /** @return iterable<string, array{string}> bodies that must be nacked without requeue, handler never run */
    public static function refusedBodies(): iterable
    {
        $genuine = self::sign(self::canonical('"read"'));
        $canonical = self::canonical('"read"');
        $sig = hash_hmac('sha256', $canonical, self::KEY);

        yield 'trailing newline after a genuine message' => [$genuine . "\n"];
        yield 'trailing space after a genuine message' => [$genuine . ' '];
        yield 'trailing content after a genuine message' => [$genuine . '{"x":1}'];
        yield 'two messages concatenated' => [$genuine . $genuine];
        yield 'leading whitespace' => [' ' . $genuine];
        yield 'whitespace inside, signature otherwise genuine' => [str_replace('"action":', '"action" :', $genuine)];
        // The genuine signature, and a duplicate `action` placed before the real one: a
        // last-wins decoder then re-serializes to exactly the signed bytes and would accept it
        // while a first-wins reader of the same body sees "evil".
        yield 'a duplicate key placed before the real one' => [str_replace('"action":"read"', '"action":"evil","action":"read"', $genuine)];
        yield 'a duplicate key placed after the real one' => [str_replace('"action":"read"', '"action":"read","action":"evil"', $genuine)];
        yield 'a duplicate key spelled through an escape' => [str_replace('"action":"read"', '"action":"evil","\u0061ction":"read"', $genuine)];
        yield 'a duplicate key signed over its own bytes' => [self::sign(str_replace('"action":"read"', '"action":"read","action":"evil"', $canonical))];
        yield 'a nested duplicate key signed over its own bytes' => [self::sign(str_replace('"action":"read"', '"action":"read","meta":{"k":1,"k":2}', $canonical))];
        yield 'signature not the trailing member' => [str_replace('"nonce":"nonce-1"', '"hmac_signature":"' . $sig . '","nonce":"nonce-1"', $canonical)];
        yield 'signature of a different message' => [str_replace('"read"', '"write"', $genuine)];
        yield 'no signature' => [$canonical];
        yield 'a null signature' => [substr($canonical, 0, -1) . ',"hmac_signature":null}'];
        yield 'a short signature' => [substr($canonical, 0, -1) . ',"hmac_signature":"' . substr($sig, 0, 62) . '"}'];
        yield 'an upper-cased member name' => [str_replace('"hmac_signature"', '"HMAC_SIGNATURE"', $genuine)];
        yield 'not JSON' => ['not json'];
        yield 'a JSON array' => ['[1]'];
        yield 'empty' => [''];
    }

    /** @return iterable<string, array{string}> validly signed, but not the signed layout of an event type */
    public static function wrongLayoutBodies(): iterable
    {
        $canonical = self::canonical('"read"');
        // Validly signed over their own canonical bytes, but not the signed layout (§8 step 2c).
        yield 'members in another order, signature over the canonical bytes' => [self::sign('{"tenant_id":"22222222-2222-2222-2222-222222222222","correlation_id":"11111111-1111-1111-1111-111111111111","subject_id":"33333333-3333-3333-3333-333333333333","action":"read","resource_id":"44444444-4444-4444-4444-444444444444","key_version":2,"nonce":"nonce-1","issued_at":"2027-01-15T08:00:00Z"}')];
        yield 'an extra unsigned-type member, validly signed' => [self::sign(str_replace('"action":"read"', '"action":"read","extra":1', $canonical))];
        yield 'a required member missing, validly signed' => [self::sign(str_replace('"subject_id":"33333333-3333-3333-3333-333333333333",', '', $canonical))];
        yield 'an AuthzResponse signed with the same tenant subkey' => [self::sign('{"correlation_id":"11111111-1111-1111-1111-111111111111","allowed":true,"reason_code":"allowed","tenant_id":"22222222-2222-2222-2222-222222222222","nonce":"nonce-1"}')];
    }

    /** @dataProvider wrongLayoutBodies */
    public function testAValidlySignedMessageOfAnotherShapeIsNackedAndTheHandlerNeverRuns(string $body): void
    {
        // The signature is fine (the primitive accepts it); the layout check (§8 step 2c) refuses it.
        self::assertTrue(Hmac::verify(self::KEY, $body));

        $result = self::deliver($body);

        self::assertSame(1, $result['nackedNoRequeue']);
        self::assertSame([], $result['calls']);
    }

    /** @dataProvider refusedBodies */
    public function testAnAmbiguousOrAlteredBodyIsNackedWithoutRequeueAndTheHandlerNeverRuns(string $body): void
    {
        self::assertFalse(Hmac::verify(self::KEY, $body), 'Hmac::verify must refuse it');

        $result = self::deliver($body);

        self::assertSame(1, $result['nackedNoRequeue']);
        self::assertSame(0, $result['acked']);
        self::assertSame(0, $result['nackedRequeue']);
        self::assertSame([], $result['calls'], 'the handler never runs');
    }

    public function testTheCanonicalBytesAreTheReceivedBytesWithTheTrailingMemberCutOut(): void
    {
        $canonical = self::canonical('"caf\u00e9 \/ <&>"');

        self::assertSame($canonical, Hmac::verifiedCanonical(self::KEY, self::sign($canonical)));
        self::assertNull(Hmac::verifiedCanonical('another-key', self::sign($canonical)));
    }
}
