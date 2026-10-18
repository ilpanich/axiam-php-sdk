<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract161;

use Axiam\Sdk\Management\ConflictError;
use Axiam\Sdk\Management\Models;
use Axiam\Sdk\Management\ReadModifyWrite;
use Axiam\Sdk\Ssf\SsfEventTypes;
use Axiam\Sdk\Tests\Contract158\ManagementRouteTestCase;
use Axiam\Sdk\Tests\Fixtures\RoutedHandler;

/**
 * CONTRACT.md contract 1.61: `Certificate.user_id` and its request members (§27.11 rule 5's
 * required test), `SsfStreamInput.expected_updated_at` and the three meanings of
 * `events_requested` on an update (§32.2, §32.3 rule 4, §32.8 test 1). Everything runs on
 * the SDK's real request path.
 *
 * `CibaPendingList` (§33.3 rule 16) is not modelled by this SDK: no registry operation
 * returns it and the SDK generates models only for the types its operations carry.
 */
final class Contract161Test extends ManagementRouteTestCase
{
    private const STREAMS = '/api/v1/tenants/' . self::TENANT_ID . '/ssf/streams';

    /**
     * @param array<string,mixed> $extra
     * @return array<string,mixed>
     */
    private static function certificate(array $extra = []): array
    {
        return array_merge([
            'cert_type' => 'User', 'created_at' => '2026-10-13T00:00:00Z', 'fingerprint' => 'example',
            'id' => self::uuid(), 'issuer_ca_id' => self::uuid(), 'key_algorithm' => 'Rsa4096',
            'metadata' => [], 'not_after' => '2027-10-13T00:00:00Z', 'not_before' => '2026-10-13T00:00:00Z',
            'public_cert_pem' => 'example', 'status' => 'Active', 'subject' => 'example',
            'tenant_id' => self::TENANT_ID,
        ], $extra);
    }

    // -- §27.11 rule 5: the required test -------------------------------------------------

    public function testGenerateAndSignCsrSendUserIdExactlyAsGivenAndNoKeyWithoutOne(): void
    {
        $user = self::uuid();
        $this->routes->on('POST', '/api/v1/certificates', RoutedHandler::json(201, self::certificate([
            'user_id' => $user, 'private_key_pem' => 'example',
        ])));
        $this->routes->on('POST', '/api/v1/certificates/sign-csr', RoutedHandler::json(201, self::certificate(['user_id' => $user])));
        $certificates = $this->client()->management()->certificates();
        $issuer = self::uuid();

        $certificates->generate(new Models\CreateCertificateRequest(
            Models\CertificateType::User,
            $issuer,
            Models\KeyAlgorithm::Rsa4096,
            'example',
            365,
            userId: $user,
        ));
        $certificates->generate(new Models\CreateCertificateRequest(
            Models\CertificateType::User,
            $issuer,
            Models\KeyAlgorithm::Rsa4096,
            'example',
            365,
        ));
        $sent = $this->bodies('POST', '/api/v1/certificates');
        self::assertIsArray($sent[0]);
        self::assertIsArray($sent[1]);
        self::assertSame($user, $sent[0]['user_id'] ?? null, 'sent exactly as given');
        self::assertArrayNotHasKey('user_id', $sent[1], 'no account named: no key, and never null');

        $certificates->signCsr(new Models\SignCertificateCsrRequest(Models\CertificateType::User, 'example', $issuer, 365, userId: $user));
        $certificates->signCsr(new Models\SignCertificateCsrRequest(Models\CertificateType::User, 'example', $issuer, 365));
        $sent = $this->bodies('POST', '/api/v1/certificates/sign-csr');
        self::assertIsArray($sent[0]);
        self::assertIsArray($sent[1]);
        self::assertSame($user, $sent[0]['user_id'] ?? null);
        self::assertArrayNotHasKey('user_id', $sent[1]);
    }

    public function testACertificateBodyWithAUuidANullAndNoMemberAllDecode(): void
    {
        $user = self::uuid();
        $withUuid = self::certificate(['user_id' => $user]);
        $withNull = self::certificate(['user_id' => null]);
        $without = self::certificate(); // a server before 1.1.0 omits the member
        $client = $this->client();
        foreach ([$withUuid, $withNull, $without] as $body) {
            $this->routes->on('GET', '/api/v1/certificates/' . $body['id'], RoutedHandler::json(200, $body));
        }

        $certificates = $client->management()->certificates();
        self::assertSame($user, $certificates->get($withUuid['id'])->userId);
        self::assertNull($certificates->get($withNull['id'])->userId, 'null: no account named');
        self::assertNull($certificates->get($without['id'])->userId, 'absent: no account named');

        // Inside GeneratedCertificate: the same member, the same rule.
        self::assertSame($user, Models\GeneratedCertificate::fromArray($withUuid + ['private_key_pem' => 'example'])->userId);
        self::assertNull(Models\GeneratedCertificate::fromArray($without + ['private_key_pem' => 'example'])->userId);

        // Never synthesised from the metadata or the subject.
        $legacy = Models\Certificate::fromArray(self::certificate(['metadata' => ['user_id' => $user], 'subject' => 'jane@example.test']));
        self::assertNull($legacy->userId);
    }

    // -- §32.8 test 1: expected_updated_at and events_requested ---------------------------

    /**
     * @param array<string,mixed> $extra
     * @return array<string,mixed>
     */
    private static function stream(array $extra = []): array
    {
        return array_merge([
            'id' => self::uuid(), 'tenant_id' => self::TENANT_ID, 'receiver_client_id' => 'rp-1',
            'audience' => 'https://rp.example', 'description' => null, 'delivery_method' => 'push',
            'endpoint_url' => 'https://rp.example/ssf', 'authorization_header_set' => false,
            'events_allowed' => [SsfEventTypes::SESSION_REVOKED],
            'events_requested' => [SsfEventTypes::SESSION_REVOKED],
            'events_delivered' => [], 'subject_format' => 'iss_sub', 'status' => 'enabled',
            'status_reason' => null, 'status_actor' => 'admin', 'last_verification_at' => null,
            'created_at' => '2026-10-04T00:00:00Z', 'updated_at' => '2026-10-04T00:00:00Z',
            'transmitter_active' => true,
        ], $extra);
    }

    private static function input(?array $requested = null, ?string $expectedUpdatedAt = null): Models\SsfStreamInput
    {
        return new Models\SsfStreamInput(
            audience: 'https://rp.example',
            deliveryMethod: Models\SsfDeliveryMethod::Push,
            eventsAllowed: [Models\SsfEventType::SessionRevoked],
            receiverClientId: 'rp-1',
            endpointUrl: 'https://rp.example/ssf',
            eventsRequested: $requested,
            expectedUpdatedAt: $expectedUpdatedAt,
        );
    }

    public function testExpectedUpdatedAtIsSentExactlyAsGivenAndEventsRequestedKeepsItsThreeMeanings(): void
    {
        $id = self::uuid();
        $this->routes->on('PUT', self::STREAMS . '/' . $id, RoutedHandler::json(200, self::stream(['id' => $id])));
        $ssf = $this->client()->ssf();

        // A non-UTC offset and a trailing-zero fraction a re-formatting client would lose.
        $read = '2026-10-05T02:00:00.120000+02:00';
        $ssf->updateStream($id, self::input(null, $read));
        $ssf->updateStream($id, self::input());
        $ssf->updateStream($id, self::input([]));
        $ssf->updateStream($id, self::input([Models\SsfEventType::SessionRevoked]));
        $sent = $this->bodies('PUT', self::STREAMS . '/' . $id);

        self::assertIsArray($sent[0]);
        self::assertSame($read, $sent[0]['expected_updated_at'] ?? null, 'the string, not re-formatted');
        self::assertIsArray($sent[1]);
        self::assertArrayNotHasKey('expected_updated_at', $sent[1], 'absent when unset, never null');
        self::assertArrayNotHasKey('events_requested', $sent[1], 'unset: absent (resets to all of events_allowed)');
        self::assertIsArray($sent[2]);
        self::assertSame([], $sent[2]['events_requested'] ?? null, '[] is sent as []');
        self::assertStringContainsString('"events_requested":[]', (string) $this->routes->sent('PUT', self::STREAMS . '/' . $id)[2]->getBody());
        self::assertIsArray($sent[3]);
        self::assertSame([SsfEventTypes::SESSION_REVOKED], $sent[3]['events_requested'] ?? null, 'a list is sent as given');
    }

    public function testAConflictOnUpdateIsSurfacedAndNotRetried(): void
    {
        $id = self::uuid();
        $this->routes->on('PUT', self::STREAMS . '/' . $id, RoutedHandler::json(409, ['error' => 'conflict', 'message' => 'the stream changed since it was read']));
        $ssf = $this->client()->ssf();

        try {
            $ssf->updateStream($id, self::input(null, '2026-10-04T00:00:00Z'));
            self::fail('a 409 must surface');
        } catch (ConflictError $e) {
            self::assertStringContainsString('409', $e->getMessage());
        }
        $sent = $this->bodies('PUT', self::STREAMS . '/' . $id);
        self::assertCount(1, $sent, 'one request, no retry');
        self::assertIsArray($sent[0]);
        self::assertSame('2026-10-04T00:00:00Z', $sent[0]['expected_updated_at'] ?? null);
    }

    public function testTheReadModifyWriteHelperSendsBackWhatItRead(): void
    {
        $id = self::uuid();
        $this->routes->on('PUT', self::STREAMS . '/' . $id, RoutedHandler::json(200, self::stream(['id' => $id])));
        $ssf = $this->client()->ssf();

        // The receiver narrowed the stream to "none": [] goes back as [], never omitted.
        $none = Models\SsfStream::fromArray(self::stream(['events_requested' => [], 'updated_at' => '2026-10-05T00:00:00.5+02:00']));
        self::assertSame([], $none->eventsRequested);
        $body = ReadModifyWrite::ssfStream($none, ['description' => 'edited']);
        self::assertSame([], $body->eventsRequested);
        self::assertSame('2026-10-05T00:00:00.5+02:00', $body->expectedUpdatedAt, 'the read version, as read');
        $ssf->updateStream($id, $body);

        // A list goes back as given; lowering the ceiling cuts it, and naming it overrides.
        $two = Models\SsfStream::fromArray(self::stream([
            'events_allowed' => [SsfEventTypes::SESSION_REVOKED, SsfEventTypes::CREDENTIAL_CHANGE],
            'events_requested' => [SsfEventTypes::SESSION_REVOKED, SsfEventTypes::CREDENTIAL_CHANGE],
        ]));
        $ssf->updateStream($id, ReadModifyWrite::ssfStream($two));
        $ssf->updateStream($id, ReadModifyWrite::ssfStream($two, ['events_allowed' => [SsfEventTypes::SESSION_REVOKED]]));
        $ssf->updateStream($id, ReadModifyWrite::ssfStream($none, ['events_allowed' => [SsfEventTypes::SESSION_REVOKED]]));

        $sent = $this->bodies('PUT', self::STREAMS . '/' . $id);
        self::assertIsArray($sent[0]);
        self::assertSame([], $sent[0]['events_requested'] ?? null, '[] goes back as []');
        self::assertSame('2026-10-05T00:00:00.5+02:00', $sent[0]['expected_updated_at'] ?? null);
        self::assertSame('edited', $sent[0]['description'] ?? null);
        self::assertIsArray($sent[1]);
        self::assertSame([SsfEventTypes::SESSION_REVOKED, SsfEventTypes::CREDENTIAL_CHANGE], $sent[1]['events_requested'] ?? null);
        self::assertIsArray($sent[2]);
        self::assertSame([SsfEventTypes::SESSION_REVOKED], $sent[2]['events_requested'] ?? null, 'cut to the new ceiling');
        self::assertIsArray($sent[3]);
        self::assertSame([], $sent[3]['events_requested'] ?? null, 'a "none" stays none after the cut');
    }
}
