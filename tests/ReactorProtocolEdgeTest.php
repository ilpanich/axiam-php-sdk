<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Amqp\ReplayGuard;
use Axiam\Sdk\Reactor\ReactorAnswer;
use Axiam\Sdk\Reactor\ReactorEvent;
use Axiam\Sdk\Reactor\ReactorEvents;
use Axiam\Sdk\Reactor\ReactorProtocol;
use Axiam\Sdk\Reactor\ReactorRejection;
use PHPUnit\Framework\TestCase;

/**
 * The malformed-body refusals of CONTRACT.md §22.3, and the PHP-specific
 * canonicalization traps §22.2 makes load-bearing.
 *
 * Every refusal here produces NO REPLY, which hands the outcome to the
 * registration's `failure_policy` (§22.8) — never to a synthesized allow.
 */
final class ReactorProtocolEdgeTest extends TestCase
{
    private const TENANT = '11111111-1111-1111-1111-111111111111';
    private const SUBKEY_HEX = '919e125ec83799c1e113a27707cac5008a2608d0557e00dfe1b3a316abed4b89';

    private int $now = 1783080000;

    private function subkey(): string
    {
        $key = hex2bin(self::SUBKEY_HEX);
        self::assertIsString($key);

        return $key;
    }

    private function guard(): ReplayGuard
    {
        return new ReplayGuard(ReactorProtocol::FRESHNESS_SKEW_SECONDS, fn (): int => $this->now);
    }

    /**
     * Signs whatever object it is handed, so a test can omit or mistype exactly
     * one field and still present an authentically signed body — which is the only
     * way to prove the SHAPE check fires rather than the MAC check.
     */
    private function sign(\stdClass $body): string
    {
        $body->hmac_signature = null;
        $body->hmac_signature = ReactorProtocol::sign($this->subkey(), ReactorProtocol::canonicalize($body));

        return ReactorProtocol::canonicalize($body);
    }

    private function wellFormed(): \stdClass
    {
        $body = new \stdClass();
        $body->tenant_id = self::TENANT;
        $body->event = ReactorEvents::LOGIN_POST_AUTH;
        $body->correlation_id = '22222222-2222-2222-2222-222222222222';
        $body->payload = (object) ['sub' => 'alice'];
        $body->timeout_ms = 500;
        $body->key_version = ReactorProtocol::KEY_VERSION;
        $body->nonce = bin2hex(random_bytes(8));
        $body->issued_at = gmdate('Y-m-d\TH:i:s\Z', $this->now);

        return $body;
    }

    private function decode(string $body): ReactorEvent
    {
        return ReactorProtocol::decodeEvent($this->subkey(), $body, self::TENANT, $this->guard(), $this->now);
    }

    /**
     * A body that is authentically signed but structurally wrong is MALFORMED, not
     * a signature failure — the distinction matters because only one of them
     * indicates an attacker.
     *
     * @dataProvider malformedProvider
     */
    public function testStructurallyInvalidBodiesAreMalformed(string $mutation): void
    {
        $body = $this->wellFormed();
        match ($mutation) {
            'no nonce' => $body->nonce = null,
            'empty nonce' => $body->nonce = '',
            'issued_at not a string' => $body->issued_at = 1783080000,
            'issued_at not a timestamp' => $body->issued_at = 'the day before yesterday',
            'tenant not a string' => $body->tenant_id = 42,
            'event not a string' => $body->event = ['login.post_auth'],
            'correlation not a string' => $body->correlation_id = null,
            'timeout not an int' => $body->timeout_ms = '500',
            default => $body->payload = 'not an object',
        };

        try {
            $this->decode($this->sign($body));
            self::fail("$mutation must be refused");
        } catch (ReactorRejection $rejection) {
            self::assertSame(ReactorRejection::MALFORMED, $rejection->reason(), $mutation);
        }
    }

    /** @return array<string, array{string}> */
    public static function malformedProvider(): array
    {
        return array_map(
            static fn (string $name): array => [$name],
            array_combine(
                $names = [
                    'no nonce', 'empty nonce', 'issued_at not a string', 'issued_at not a timestamp',
                    'tenant not a string', 'event not a string', 'correlation not a string',
                    'timeout not an int', 'payload not an object',
                ],
                $names,
            ),
        );
    }

    /** A body that is not JSON, or not a JSON object, never reaches a shape check. */
    public function testNonObjectBodiesAreMalformed(): void
    {
        foreach (['', 'null', '[1,2,3]', '"a string"', '{oops'] as $body) {
            try {
                $this->decode($body);
                self::fail("a body of " . var_export($body, true) . ' must be refused');
            } catch (ReactorRejection $rejection) {
                self::assertSame(ReactorRejection::MALFORMED, $rejection->reason(), $body);
            }
        }
    }

    /**
     * §8.3's strict-mode default, carried into §22: a missing or non-string
     * signature is a refusal, not a body to verify leniently.
     */
    public function testMissingOrNonStringSignatureIsRefused(): void
    {
        foreach ([null, 12345, ['a']] as $signature) {
            $body = $this->wellFormed();
            $body->hmac_signature = $signature;
            try {
                $this->decode(ReactorProtocol::canonicalize($body));
                self::fail('a body with no usable signature must be refused');
            } catch (ReactorRejection $rejection) {
                self::assertSame(ReactorRejection::BAD_SIGNATURE, $rejection->reason());
            }
        }

        // A missing key_version is refused by the FIRST gate, before the signature
        // is even considered (§22.2).
        $body = $this->wellFormed();
        $body->key_version = null;
        try {
            $this->decode(ReactorProtocol::canonicalize($body));
            self::fail('a body with no key_version must be refused');
        } catch (ReactorRejection $rejection) {
            self::assertSame(ReactorRejection::KEY_VERSION_TOO_OLD, $rejection->reason());
        }
    }

    /** Verification never throws on a signature that is not even hex. */
    public function testVerifyRejectsNonHexSignatures(): void
    {
        self::assertFalse(ReactorProtocol::verify($this->subkey(), '{}', 'not-hex-at-all'));
        self::assertFalse(ReactorProtocol::verify($this->subkey(), '{}', ''));
        self::assertTrue(ReactorProtocol::verify(
            $this->subkey(),
            '{}',
            ReactorProtocol::sign($this->subkey(), '{}'),
        ));
    }

    /**
     * Canonicalization refuses bytes that are not valid UTF-8 rather than emitting
     * `false` and letting an empty MAC be computed over nothing.
     */
    public function testCanonicalizeRefusesUnencodableBytes(): void
    {
        $body = new \stdClass();
        $body->reason = "\xB1\x31"; // not valid UTF-8

        $this->expectException(ReactorRejection::class);
        ReactorProtocol::canonicalize($body);
    }

    /**
     * The PHP encoder must agree with `serde_json` on slashes and non-ASCII: PHP
     * escapes both by default and Rust escapes neither, so a deny reason with an
     * accent or a URL would otherwise produce a MAC the server never reconstructs.
     */
    public function testCanonicalizationDoesNotEscapeSlashesOrUnicode(): void
    {
        $event = new ReactorEvent(
            self::TENANT,
            ReactorEvents::LOGIN_POST_AUTH,
            '22222222-2222-2222-2222-222222222222',
            [],
            500,
            'n',
            $this->now,
            $this->now + 1.0,
        );

        $body = ReactorProtocol::buildReply(
            $this->subkey(),
            $event,
            ReactorAnswer::deny('blocked by https://policy.example/rules — région interdite'),
            'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
            $this->now,
        );

        self::assertStringContainsString('https://policy.example/rules', $body);
        self::assertStringContainsString('région', $body);
        self::assertStringNotContainsString('\\/', $body);
        self::assertStringNotContainsString('\\u00e9', $body);
    }

    /**
     * A patch whose keys look numeric must still serialize as a JSON object. A PHP
     * array with keys "0" and "1" encodes as `["a","b"]`, which is not a patch the
     * server can read at all.
     */
    public function testNumericPatchKeysStaySerializedAsAnObject(): void
    {
        $event = new ReactorEvent(
            self::TENANT,
            ReactorEvents::USER_PRE_CREATE,
            '22222222-2222-2222-2222-222222222222',
            [],
            500,
            'n',
            $this->now,
            $this->now + 1.0,
        );

        $body = ReactorProtocol::buildReply(
            $this->subkey(),
            $event,
            ReactorAnswer::mutate(['1' => 'b', '0' => 'a']),
            'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
            $this->now,
        );

        self::assertStringContainsString('"patch":{"0":"a","1":"b"}', $body);
    }

    /**
     * An empty payload object survives the round trip as `{}` rather than becoming
     * `[]` — the trap that decoding into an associative array would spring, and
     * the reason this SDK decodes reactor bodies into `stdClass`.
     */
    public function testEmptyPayloadObjectVerifies(): void
    {
        $body = $this->wellFormed();
        $body->payload = new \stdClass();

        $event = $this->decode($this->sign($body));

        self::assertSame([], $event->payload);
        self::assertSame(ReactorEvents::LOGIN_POST_AUTH, $event->event);
    }

    /** `timeout_ms` reaches the handler as the dispatch deadline it implies. */
    public function testTimeoutBecomesTheDeadline(): void
    {
        $body = $this->wellFormed();
        $body->timeout_ms = 2500;

        $event = $this->decode($this->sign($body));

        self::assertSame(2500, $event->timeoutMs);
        self::assertEqualsWithDelta($this->now + 2.5, $event->deadline, 0.001);
        self::assertSame($this->now, $event->issuedAt);
    }
}
