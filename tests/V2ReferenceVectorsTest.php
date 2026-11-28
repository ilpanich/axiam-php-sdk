<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Amqp\Consumer;
use Axiam\Sdk\Amqp\Hmac;
use Axiam\Sdk\Amqp\ReplayGuard;
use Axiam\Sdk\Amqp\SignedEventType;
use PHPUnit\Framework\TestCase;

/**
 * NEW-4 ground-truth parity test. `crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json`
 * contains server-generated (Rust `sign_payload`) canonical bytes + expected
 * HMAC for both v2 `AuthzRequest` and `AuditEventMessage` (CONTRACT.md §8 "v2
 * — Replay Protection"). This is the ground truth for every SDK, not
 * PHP-owned — read directly from the crates fixture rather than a local
 * copy, so it can never drift from the authoritative vectors.
 *
 * Proves:
 *   1. The HKDF-SHA256 per-tenant subkey derivation reproduces
 *      `derived_subkey_hex` (traceability only — Hmac::verify's public
 *      contract takes an already-derived per-tenant key, CONTRACT.md §8.1;
 *      the PHP SDK never performs this derivation itself at runtime).
 *   2. HMAC-SHA256(derived_subkey, canonical_signed_json) reproduces
 *      `hmac_signature_hex` byte-for-byte for BOTH message types.
 *   3. The received-bytes path (the wire body with its trailing
 *      `hmac_signature` member cut out, Hmac::verifiedCanonical) yields
 *      `canonical_signed_json` byte-for-byte, with no re-serialization.
 *   4. Hmac::verify() ACCEPTS the reconstructed wire delivery.
 *   5. ReplayGuard::check() (the NEW-4 gate) also accepts the same
 *      delivery once its clock is pinned to the fixture's `issued_at`.
 *
 * NOTE on the fixture's "message" object: it is JSON-pretty-printed with
 * alphabetized keys for human readability and is NOT the real wire byte
 * order for an order-preserving decoder. PHP's json_decode(..., true)
 * preserves whatever key order it is given, so this test reconstructs the
 * simulated wire body from `canonical_signed_json` (the real signed byte
 * order) plus `hmac_signature` appended last -- mirroring how the server
 * appends the signature after signing -- rather than decoding the fixture's
 * `message` object directly.
 */
final class V2ReferenceVectorsTest extends TestCase
{
    /**
     * Vendored from the AXIAM server's own AMQP test fixtures
     * (crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json in
     * ilpanich/axiam). While this SDK lived inside that monorepo the test read
     * the server's copy directly across the tree; a standalone repository has no
     * such path, so the vectors are committed here instead.
     *
     * These are CROSS-LANGUAGE reference vectors: their whole purpose is that the
     * server and every SDK independently reproduce the same bytes. Re-copy this
     * file from the server whenever CONTRACT.md §8's wire format changes.
     */
    private const FIXTURE_PATH = __DIR__ . '/Fixtures/v2_reference_vectors.json';

    /** @return array<string, mixed> */
    private static function loadFixture(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURE_PATH), true);
        self::assertIsArray($decoded, 'v2_reference_vectors.json must decode to an array');

        return $decoded;
    }

    /**
     * Test-local only: HKDF-SHA256(salt=app_salt, ikm=master,
     * info=domain_tag || key_version(1 byte) || tenant_id(16 raw bytes)),
     * mirroring crates/axiam-amqp/src/messages.rs::derive_tenant_key. The
     * PHP SDK's public Hmac API takes an already-derived per-tenant
     * subkey (CONTRACT.md §8.1, out-of-band provisioning) and never
     * performs this derivation at runtime -- this helper exists purely to
     * prove traceability from the fixture's master key to its subkey.
     */
    private static function deriveTenantKey(string $masterHex, string $tenantId, int $keyVersion, string $appSalt, string $domainTag): string
    {
        $master = hex2bin($masterHex);
        self::assertIsString($master);
        $tenantRaw = hex2bin(str_replace('-', '', $tenantId));
        self::assertIsString($tenantRaw);
        self::assertSame(16, strlen($tenantRaw), 'tenant_id must decode to 16 raw bytes');

        $info = $domainTag . chr($keyVersion) . $tenantRaw;

        return hash_hkdf('sha256', $master, 32, $info, $appSalt);
    }

    public function testDerivesTheSamePerTenantSubkeyAsTheFixture(): void
    {
        $fixture = self::loadFixture();

        $subkey = self::deriveTenantKey(
            $fixture['master_signing_key_hex'],
            $fixture['tenant_id'],
            $fixture['key_version'],
            $fixture['hkdf']['app_salt_utf8'],
            $fixture['hkdf']['domain_tag_utf8'],
        );

        self::assertSame($fixture['hkdf']['derived_subkey_hex'], bin2hex($subkey));
    }

    /** @return array<int, array{string}> */
    public static function messageTypeProvider(): array
    {
        return [
            'authz_request' => ['authz_request'],
            'audit_event' => ['audit_event'],
        ];
    }

    /** @dataProvider messageTypeProvider */
    public function testReproducesTheServerHmacSignatureHexByteForByte(string $messageType): void
    {
        $fixture = self::loadFixture();
        $entry = $fixture[$messageType];
        $subkey = hex2bin($fixture['hkdf']['derived_subkey_hex']);
        self::assertIsString($subkey);

        $computed = hash_hmac('sha256', $entry['canonical_signed_json'], $subkey);

        self::assertSame($entry['hmac_signature_hex'], $computed);
    }

    /**
     * @dataProvider messageTypeProvider
     *
     * Simulates the real wire delivery (the canonical bytes with
     * `,"hmac_signature":"<hex>"` appended as the last member, as the server
     * writes it) and proves Hmac::verifiedCanonical() cuts it back to
     * `canonical_signed_json` exactly and Hmac::verify() accepts it.
     */
    public function testRoundTripReproducesCanonicalBytesAndHmacVerifyAccepts(string $messageType): void
    {
        $fixture = self::loadFixture();
        $entry = $fixture[$messageType];
        $canonical = $entry['canonical_signed_json'];
        $subkey = hex2bin($fixture['hkdf']['derived_subkey_hex']);
        self::assertIsString($subkey);

        // The wire body: the canonical bytes closed after the signature member (CONTRACT §8 step 2).
        $wireBody = substr($canonical, 0, -1) . ',"hmac_signature":"' . $entry['hmac_signature_hex'] . '"}';

        self::assertSame($canonical, Hmac::verifiedCanonical($subkey, $wireBody), 'the received bytes minus the trailing member are canonical_signed_json byte-for-byte');

        self::assertTrue(Hmac::verify($subkey, $wireBody), 'Hmac::verify must ACCEPT the server-signed v2 reference vector');
    }

    /**
     * @dataProvider messageTypeProvider
     *
     * Full-pipeline proof: once the HMAC verifies, ReplayGuard::check()
     * (the NEW-4 gate) also accepts the same genuine v2 delivery -- using a
     * clock pinned to the fixture's own `issued_at` so this assertion never
     * depends on how much wall-clock time has passed since the fixture was
     * generated.
     */
    public function testReplayGuardAcceptsTheGenuineV2Delivery(string $messageType): void
    {
        $fixture = self::loadFixture();
        $entry = $fixture[$messageType];
        $ordered = json_decode($entry['canonical_signed_json'], true);
        self::assertIsArray($ordered);

        $fixedNow = (new \DateTimeImmutable($ordered['issued_at']))->getTimestamp();
        $guard = new ReplayGuard(ReplayGuard::DEFAULT_SKEW_SECONDS, static fn (): int => $fixedNow);

        self::assertNull($guard->check($ordered));
    }

    /**
     * @dataProvider messageTypeProvider
     *
     * Contract 1.69: the vector's `wire_json` is the exact delivered body. The received-bytes
     * verifier cuts it to exactly `canonical_signed_json`, verifies it, the layout check accepts it
     * and the consumer dispatches it.
     */
    public function testWireJsonCutsToTheCanonicalBytesVerifiesAndDispatches(string $messageType): void
    {
        $fixture = self::loadFixture();
        $entry = $fixture[$messageType];
        self::assertIsString($entry['wire_json']);
        $subkey = hex2bin($fixture['hkdf']['derived_subkey_hex']);
        self::assertIsString($subkey);

        self::assertSame($entry['canonical_signed_json'], Hmac::verifiedCanonical($subkey, $entry['wire_json']));
        self::assertTrue(Hmac::hasLayout($entry['canonical_signed_json'], SignedEventType::from($messageType === 'audit_event' ? 'AuditEventMessage' : 'AuthzRequest')));

        $ordered = json_decode($entry['canonical_signed_json'], true);
        $fixedNow = (new \DateTimeImmutable($ordered['issued_at']))->getTimestamp();
        $acked = 0;
        $nacked = 0;
        $seen = [];
        (new Consumer($subkey, $fixture['tenant_id'], SignedEventType::from($messageType === 'audit_event' ? 'AuditEventMessage' : 'AuthzRequest'), replayGuard: new ReplayGuard(ReplayGuard::DEFAULT_SKEW_SECONDS, static fn (): int => $fixedNow)))
            ->verifyAndDispatch(
                $entry['wire_json'],
                static function (array $event) use (&$seen): void {
                    $seen[] = $event;
                },
                static function () use (&$acked): void {
                    ++$acked;
                },
                static function () use (&$nacked): void {
                    ++$nacked;
                },
                static function () use (&$nacked): void {
                    ++$nacked;
                },
                '',
                'axiam.queue',
            );

        self::assertSame(1, $acked);
        self::assertSame(0, $nacked);
        self::assertSame([$ordered], $seen, 'the handler gets the value decoded from the verified canonical bytes');
    }

    /**
     * The `message` member is for reading: key-sorted, signature in the middle. It is not wire
     * bytes, and a conforming consumer refuses it.
     *
     * @dataProvider messageTypeProvider
     */
    public function testTheMessageMemberIsNotWireBytesAndIsRefused(string $messageType): void
    {
        $fixture = self::loadFixture();
        $subkey = hex2bin($fixture['hkdf']['derived_subkey_hex']);
        self::assertIsString($subkey);

        self::assertNull(Hmac::verifiedCanonical($subkey, (string) json_encode($fixture[$messageType]['message'])));
    }
}
