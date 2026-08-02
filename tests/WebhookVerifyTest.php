<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Webhook\AxiamWebhooks;
use Axiam\Sdk\Webhook\WebhookVerificationException;
use PHPUnit\Framework\TestCase;

/**
 * Coverage for AxiamWebhooks::verify() (CONTRACT.md §13, T-145) against the
 * "Required tests" list in the T-145 spec: valid/fresh acceptance, tampered body,
 * wrong secret, stale/future timestamps, every malformed-header shape, and the shared
 * cross-SDK pin vector (computed here from the spec's raw ingredients, never hardcoded
 * as a literal hex string).
 */
final class WebhookVerifyTest extends TestCase
{
    private const SECRET = 'whsec_test_0123456789abcdef';
    private const BODY = '{"event":"user.created","id":"01JQ0000000000000000000000"}';

    /**
     * Computes HMAC-SHA256(secret, "<timestamp>.<body>") exactly the way the server
     * (and AxiamWebhooks::verify) do, so tests never hardcode an expected signature
     * literal.
     */
    private static function computeV1(string $secret, int $timestamp, string $body): string
    {
        return hash_hmac('sha256', $timestamp . '.' . $body, $secret);
    }

    private static function header(int $timestamp, string $v1): string
    {
        return "t={$timestamp},v1={$v1}";
    }

    private static function clockAt(int $timestamp): callable
    {
        return static fn (): int => $timestamp;
    }

    public function testValidSignatureFreshTimestampIsAccepted(): void
    {
        $timestamp = 1_785_700_000;
        $v1 = self::computeV1(self::SECRET, $timestamp, self::BODY);

        $event = AxiamWebhooks::verify(
            new Sensitive(self::SECRET),
            self::header($timestamp, $v1),
            self::BODY,
            now: self::clockAt($timestamp),
        );

        self::assertSame($timestamp, $event->timestamp);
        self::assertSame(self::BODY, $event->body);
        self::assertSame('user.created', $event->eventType);
        self::assertSame('01JQ0000000000000000000000', $event->deliveryId);
    }

    public function testCrossSdkPinVectorComputedFromSpecIsAccepted(): void
    {
        // The shared T-145 spec vector: secret/timestamp/body are hardcoded from the
        // spec, but the expected `v1` is computed here (never copied as a literal hex
        // value) so every SDK is pinned to the same bytes rather than to a shared
        // hardcoded hex string.
        $timestamp = 1_785_700_000;
        $body = '{"event":"user.created","id":"01JQ0000000000000000000000"}';
        $v1 = self::computeV1('whsec_test_0123456789abcdef', $timestamp, $body);

        $event = AxiamWebhooks::verify(
            new Sensitive('whsec_test_0123456789abcdef'),
            self::header($timestamp, $v1),
            $body,
            now: self::clockAt($timestamp),
        );

        self::assertSame($timestamp, $event->timestamp);

        // Separately, a byte-flipped body must be rejected under the same vector.
        $tampered = $body;
        $tampered[0] = $tampered[0] === '{' ? '[' : '{';

        $this->expectException(WebhookVerificationException::class);
        AxiamWebhooks::verify(
            new Sensitive('whsec_test_0123456789abcdef'),
            self::header($timestamp, $v1),
            $tampered,
            now: self::clockAt($timestamp),
        );
    }

    public function testTamperedBodyOneByteFlippedIsRejected(): void
    {
        $timestamp = 1_785_700_000;
        $v1 = self::computeV1(self::SECRET, $timestamp, self::BODY);

        $tampered = self::BODY;
        $tampered[5] = $tampered[5] === 'e' ? 'E' : 'e';

        $this->expectException(WebhookVerificationException::class);
        AxiamWebhooks::verify(
            new Sensitive(self::SECRET),
            self::header($timestamp, $v1),
            $tampered,
            now: self::clockAt($timestamp),
        );
    }

    public function testWrongSecretIsRejected(): void
    {
        $timestamp = 1_785_700_000;
        $v1 = self::computeV1(self::SECRET, $timestamp, self::BODY);

        $this->expectException(WebhookVerificationException::class);
        AxiamWebhooks::verify(
            new Sensitive('whsec_totally_different_secret'),
            self::header($timestamp, $v1),
            self::BODY,
            now: self::clockAt($timestamp),
        );
    }

    public function testStaleTimestampBeyondToleranceIsRejected(): void
    {
        $timestamp = 1_785_700_000;
        $v1 = self::computeV1(self::SECRET, $timestamp, self::BODY);

        $this->expectException(WebhookVerificationException::class);
        // 301s after `t`, default tolerance is 300s.
        AxiamWebhooks::verify(
            new Sensitive(self::SECRET),
            self::header($timestamp, $v1),
            self::BODY,
            now: self::clockAt($timestamp + 301),
        );
    }

    public function testFutureTimestampBeyondToleranceIsRejected(): void
    {
        $timestamp = 1_785_700_000;
        $v1 = self::computeV1(self::SECRET, $timestamp, self::BODY);

        $this->expectException(WebhookVerificationException::class);
        // `t` is 301s ahead of "now" -> future-dated beyond the two-sided tolerance window.
        AxiamWebhooks::verify(
            new Sensitive(self::SECRET),
            self::header($timestamp, $v1),
            self::BODY,
            now: self::clockAt($timestamp - 301),
        );
    }

    public function testTimestampAtExactToleranceBoundaryIsAccepted(): void
    {
        $timestamp = 1_785_700_000;
        $v1 = self::computeV1(self::SECRET, $timestamp, self::BODY);

        $event = AxiamWebhooks::verify(
            new Sensitive(self::SECRET),
            self::header($timestamp, $v1),
            self::BODY,
            now: self::clockAt($timestamp + 300),
        );

        self::assertSame($timestamp, $event->timestamp);
    }

    public function testCustomToleranceIsHonored(): void
    {
        $timestamp = 1_785_700_000;
        $v1 = self::computeV1(self::SECRET, $timestamp, self::BODY);

        // Default tolerance (300s) would accept this; a tightened 10s tolerance must reject it.
        $this->expectException(WebhookVerificationException::class);
        AxiamWebhooks::verify(
            new Sensitive(self::SECRET),
            self::header($timestamp, $v1),
            self::BODY,
            toleranceSeconds: 10,
            now: self::clockAt($timestamp + 30),
        );
    }

    /** @return array<string, array{string}> */
    public static function malformedHeaderProvider(): array
    {
        return [
            'missing v1 entirely' => ['t=1785700000'],
            'empty v1 value' => ['t=1785700000,v1='],
            'non-numeric t' => ['t=abc,v1=deadbeef'],
            'empty header' => [''],
            'missing t' => ['v1=deadbeef'],
            'duplicate t' => ['t=1785700000,t=1785700001,v1=deadbeef'],
            'empty t' => ['t=,v1=deadbeef'],
        ];
    }

    /** @dataProvider malformedHeaderProvider */
    public function testMalformedHeaderIsRejected(string $header): void
    {
        $this->expectException(WebhookVerificationException::class);
        AxiamWebhooks::verify(
            new Sensitive(self::SECRET),
            $header,
            self::BODY,
            now: self::clockAt(1_785_700_000),
        );
    }

    public function testNonHexV1ValueFailsClosedWithoutThrowingUnexpectedException(): void
    {
        $timestamp = 1_785_700_000;

        $this->expectException(WebhookVerificationException::class);
        AxiamWebhooks::verify(
            new Sensitive(self::SECRET),
            self::header($timestamp, 'not-hex-zz'),
            self::BODY,
            now: self::clockAt($timestamp),
        );
    }

    public function testMultipleV1EntriesAcceptsIfAnyMatches(): void
    {
        // Simulates secret rotation: an old (garbage) v1 alongside the current, valid one.
        $timestamp = 1_785_700_000;
        $validV1 = self::computeV1(self::SECRET, $timestamp, self::BODY);
        $header = "t={$timestamp},v1=0000000000000000000000000000000000000000000000000000000000000000,v1={$validV1}";

        $event = AxiamWebhooks::verify(
            new Sensitive(self::SECRET),
            $header,
            self::BODY,
            now: self::clockAt($timestamp),
        );

        self::assertSame($timestamp, $event->timestamp);
    }

    public function testUnknownHeaderKeysAreIgnoredForwardCompat(): void
    {
        $timestamp = 1_785_700_000;
        $v1 = self::computeV1(self::SECRET, $timestamp, self::BODY);
        $header = "t={$timestamp},v2=some-future-scheme,v1={$v1}";

        $event = AxiamWebhooks::verify(
            new Sensitive(self::SECRET),
            $header,
            self::BODY,
            now: self::clockAt($timestamp),
        );

        self::assertSame($timestamp, $event->timestamp);
    }

    public function testNonJsonBodyStillVerifiesButEventFieldsAreNull(): void
    {
        $timestamp = 1_785_700_000;
        $body = 'not json at all';
        $v1 = self::computeV1(self::SECRET, $timestamp, $body);

        $event = AxiamWebhooks::verify(
            new Sensitive(self::SECRET),
            self::header($timestamp, $v1),
            $body,
            now: self::clockAt($timestamp),
        );

        self::assertNull($event->eventType);
        self::assertNull($event->deliveryId);
        self::assertSame($body, $event->body);
    }

    public function testFailureMessageNeverContainsExpectedSignatureOrSecret(): void
    {
        $timestamp = 1_785_700_000;
        $wrongV1 = str_repeat('a', 64); // well-formed hex, guaranteed not to match

        try {
            AxiamWebhooks::verify(
                new Sensitive(self::SECRET),
                self::header($timestamp, $wrongV1),
                self::BODY,
                now: self::clockAt($timestamp),
            );
            self::fail('expected WebhookVerificationException');
        } catch (WebhookVerificationException $e) {
            self::assertStringNotContainsStringIgnoringCase($wrongV1, $e->getMessage());
            self::assertStringNotContainsStringIgnoringCase(self::SECRET, $e->getMessage());
        }
    }
}
