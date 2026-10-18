<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract162;

use Axiam\Sdk\Management\Models;
use Axiam\Sdk\Management\ReadModifyWrite;
use Axiam\Sdk\Management\SsfApi;
use Axiam\Sdk\Management\ValidationError;
use Axiam\Sdk\Ssf\SsfEventTypes;
use Axiam\Sdk\Tests\Contract158\ManagementRouteTestCase;
use Axiam\Sdk\Tests\Fixtures\RoutedHandler;

/**
 * Contract 1.62's request-member rules and its SSF form, on the SDK's real request path:
 *
 * - §32.8 test 7 and §32.2 (e), (g), (h): the change-taking read-modify-write form
 *   {@see ReadModifyWrite::ssfStream()}, the server's own `updated_at` string, and the three
 *   meanings of `events_requested` written where `updateStream` is documented;
 * - §27.11 rule 5 (f): an assigned `null` on `user_id` or `expected_updated_at` is "none" —
 *   the key is omitted and `null` is never sent;
 * - §27.11 rule 5 (i): the request `user_id` is an untyped string, so a malformed value
 *   reaches the server and its `400` is surfaced.
 */
final class RequestMembersAndSsfFormTest extends ManagementRouteTestCase
{
    private const STREAMS = '/api/v1/tenants/' . self::TENANT_ID . '/ssf/streams';
    private const A = SsfEventTypes::SESSION_REVOKED;
    private const B = SsfEventTypes::CREDENTIAL_CHANGE;
    private const C = SsfEventTypes::ACCOUNT_DISABLED;

    /**
     * A stream read: three event types allowed, two requested, and an `updated_at` in the
     * spelling a re-rendering client would change (`+00:00`, nine fraction digits).
     *
     * @param array<string,mixed> $extra
     */
    private static function stream(array $extra = []): Models\SsfStream
    {
        return Models\SsfStream::fromArray(array_merge([
            'id' => self::uuid(), 'tenant_id' => self::TENANT_ID, 'receiver_client_id' => 'rp-1',
            'audience' => 'https://rp.example', 'description' => null, 'delivery_method' => 'push',
            'endpoint_url' => 'https://rp.example/ssf', 'authorization_header_set' => false,
            'events_allowed' => [self::A, self::B, self::C],
            'events_requested' => [self::A, self::B],
            'events_delivered' => [self::A, self::B], 'subject_format' => 'iss_sub', 'status' => 'enabled',
            'status_reason' => null, 'status_actor' => 'admin', 'last_verification_at' => null,
            'created_at' => '2026-10-04T00:00:00Z', 'updated_at' => '2026-10-15T08:30:00.123456789+00:00',
            'transmitter_active' => true,
        ], $extra));
    }

    // -- §32.8 test 7: the change-taking form ---------------------------------------------

    public function testALoweredCeilingCutsEventsRequestedToWhatIsStillAllowedInTheirOrder(): void
    {
        $stream = self::stream();

        $body = ReadModifyWrite::ssfStream($stream, ['events_allowed' => [self::A]])->toArray();
        self::assertSame([self::A], $body['events_requested'], 'only what is in the new ceiling');
        self::assertSame([self::A], $body['events_allowed']);

        $body = ReadModifyWrite::ssfStream($stream, ['events_allowed' => [self::C, self::B]])->toArray();
        self::assertSame([self::B], $body['events_requested']);

        // The read order survives the cut: the entries of the READ list, not the ceiling's.
        $reordered = self::stream(['events_requested' => [self::B, self::A]]);
        $body = ReadModifyWrite::ssfStream($reordered, ['events_allowed' => [self::A, self::B]])->toArray();
        self::assertSame([self::B, self::A], $body['events_requested']);

        // A ceiling that raises, or one that leaves the requested list alone, cuts nothing.
        $body = ReadModifyWrite::ssfStream($stream, ['events_allowed' => [self::A, self::B, self::C, SsfEventTypes::ACCOUNT_ENABLED]])->toArray();
        self::assertSame([self::A, self::B], $body['events_requested']);
    }

    public function testAnEventsRequestedTheCallerNamesIsSentAsGiven(): void
    {
        $body = ReadModifyWrite::ssfStream(self::stream(), [
            'events_allowed' => [self::A], 'events_requested' => [self::C],
        ])->toArray();

        self::assertSame([self::C], $body['events_requested'], 'the server judges it (400), the SDK does not');
    }

    public function testAChangeThatLeavesEventsAloneSendsEventsRequestedAsReadAnEmptyListAsAnEmptyListAndTheServersOwnString(): void
    {
        $stream = self::stream();
        $body = ReadModifyWrite::ssfStream($stream, ['description' => 'edited'])->toArray();
        self::assertSame([self::A, self::B], $body['events_requested']);
        self::assertSame('2026-10-15T08:30:00.123456789+00:00', $body['expected_updated_at'], 'byte for byte');
        self::assertSame('edited', $body['description']);

        $none = self::stream(['events_requested' => []]);
        $body = ReadModifyWrite::ssfStream($none, ['description' => 'edited'])->toArray();
        self::assertSame([], $body['events_requested'], 'the receiver\'s "none" is not "absent"');
        $body = ReadModifyWrite::ssfStream($none, ['events_allowed' => [self::A]])->toArray();
        self::assertSame([], $body['events_requested'], 'and survives a cut');

        // And on the wire: the bytes of the request carry the string and the empty list.
        $id = self::uuid();
        $this->routes->on('PUT', self::STREAMS . '/' . $id, RoutedHandler::json(200, $stream->toArray()));
        $client = $this->client();
        $client->ssf()->updateStream($id, ReadModifyWrite::ssfStream($none));
        $raw = (string) $this->routes->sent('PUT', self::STREAMS . '/' . $id)[0]->getBody();
        self::assertStringContainsString('"expected_updated_at":"2026-10-15T08:30:00.123456789+00:00"', $raw);
        self::assertStringContainsString('"events_requested":[]', $raw);
    }

    public function testAnAssignedNullForExpectedUpdatedAtLeavesTheKeyOut(): void
    {
        $body = ReadModifyWrite::ssfStream(self::stream(), ['expected_updated_at' => null]);
        self::assertNull($body->expectedUpdatedAt);
        self::assertArrayNotHasKey('expected_updated_at', $body->toArray());
        self::assertStringNotContainsString('expected_updated_at', (string) json_encode($body));
        self::assertStringNotContainsString('null', (string) json_encode($body->toArray()), 'null is never sent for it');

        $id = self::uuid();
        $this->routes->on('PUT', self::STREAMS . '/' . $id, RoutedHandler::json(200, self::stream()->toArray()));
        $this->client()->ssf()->updateStream($id, $body);
        $sent = $this->bodies('PUT', self::STREAMS . '/' . $id)[0];
        self::assertIsArray($sent);
        self::assertArrayNotHasKey('expected_updated_at', $sent);
    }

    public function testTheUpdateStreamDocumentationStatesTheThreeMeaningsAndTheFormsDocumentationNamesTheCallersDuty(): void
    {
        $doc = (string) (new \ReflectionMethod(SsfApi::class, 'updateStream'))->getDocComment();
        $flat = (string) preg_replace('/\s*\n\s*\*\s*/', ' ', $doc);
        foreach ([
            '*absent*', 'resets', 'every event of `events_allowed`', '`[]` is stored', 'none',
            'a list is stored as given', 'refused (`400`)', 'outside `events_allowed`',
            'omitted members take these defaults', 'A caller with no SDK',
            'left out of the `PUT` resets the stream', 'ReadModifyWrite::ssfStream()',
        ] as $needle) {
            self::assertStringContainsString($needle, $flat, "updateStream's documentation lacks: $needle");
        }

        $form = (string) (new \ReflectionMethod(ReadModifyWrite::class, 'ssfStream'))->getDocComment();
        $flat = (string) preg_replace('/\s*\n\s*\*\s*/', ' ', $form);
        foreach (['change-taking form', 'caller\'s duty', 'three meanings', '`409`', 'new `events_allowed`'] as $needle) {
            self::assertStringContainsString($needle, $flat, "the form's documentation lacks: $needle");
        }
    }

    // -- (f): an assigned null is "none" ----------------------------------------------------------

    public function testAnAssignedNullOnUserIdIsOmittedFromBothCertificateRequests(): void
    {
        $issuer = self::uuid();
        $generate = new Models\CreateCertificateRequest(Models\CertificateType::User, $issuer, Models\KeyAlgorithm::Rsa4096, 'jane', 365, userId: null);
        $sign = new Models\SignCertificateCsrRequest(Models\CertificateType::User, 'csr', $issuer, 365, userId: null);

        foreach ([$generate->toArray(), $sign->toArray()] as $wire) {
            self::assertArrayNotHasKey('user_id', $wire);
        }
        foreach ([$generate, $sign] as $request) {
            self::assertStringNotContainsString('user_id', (string) json_encode($request));
        }
        // A wire object with an explicit `null` decodes to the same thing.
        $decoded = Models\CreateCertificateRequest::fromArray($generate->toArray() + ['user_id' => null]);
        self::assertNull($decoded->userId);
        self::assertArrayNotHasKey('user_id', $decoded->toArray());
    }

    public function testAnAssignedNullOnExpectedUpdatedAtIsOmittedFromTheScimTargetToo(): void
    {
        $input = new Models\ScimTargetInput(
            auth: new Models\ScimTargetAuthBearer(),
            baseUrl: 'https://idp.example/scim/v2',
            name: 'Downstream',
            scope: new Models\ScimTargetScopeAllUsers(),
            expectedUpdatedAt: null,
        );
        self::assertArrayNotHasKey('expected_updated_at', $input->toArray());

        $target = Models\ScimTargetResponse::fromArray([
            'id' => self::uuid(), 'tenant_id' => self::TENANT_ID, 'name' => 'Downstream',
            'base_url' => 'https://idp.example/scim/v2', 'auth' => ['type' => 'bearer'],
            'scope' => ['type' => 'all_users'], 'enabled' => true, 'deprovision' => 'disable',
            'push_groups' => false, 'user_name_from' => 'email', 'state' => null,
            'created_at' => '2026-10-04T00:00:00Z', 'updated_at' => '2026-10-15T08:30:00.123456789+00:00',
        ]);
        $read = ReadModifyWrite::scimTarget($target)->toArray();
        self::assertSame('2026-10-15T08:30:00.123456789+00:00', $read['expected_updated_at'], 'the read\'s own string');
        $cleared = ReadModifyWrite::scimTarget($target, ['expected_updated_at' => null])->toArray();
        self::assertArrayNotHasKey('expected_updated_at', $cleared);
    }

    // -- (i): the request user_id is an untyped string ------------------------------------------------

    public function testAMalformedUserIdReachesTheServerAndItsBadRequestIsSurfaced(): void
    {
        $this->routes->on('POST', '/api/v1/certificates', RoutedHandler::json(400, [
            'error' => 'validation_error', 'message' => 'user_id: is not a UUID',
        ]));
        $this->routes->on('POST', '/api/v1/certificates/sign-csr', RoutedHandler::json(400, [
            'error' => 'validation_error', 'message' => 'user_id: is not a UUID',
        ]));
        $certificates = $this->client()->certificates();
        $issuer = self::uuid();
        $property = new \ReflectionProperty(Models\CreateCertificateRequest::class, 'userId');
        self::assertSame('?string', (string) $property->getType(), 'a plain optional string, not a UUID type');

        foreach ([
            fn () => $certificates->generate(new Models\CreateCertificateRequest(Models\CertificateType::User, $issuer, Models\KeyAlgorithm::Rsa4096, 'jane', 365, userId: 'not-a-uuid')),
            fn () => $certificates->signCsr(new Models\SignCertificateCsrRequest(Models\CertificateType::User, 'csr', $issuer, 365, userId: 'not-a-uuid')),
        ] as $call) {
            try {
                $call();
                self::fail('expected the server\'s 400 to be surfaced');
            } catch (ValidationError $e) {
                self::assertSame('user_id: is not a UUID', $e->serverMessage);
            }
        }
        self::assertSame('not-a-uuid', $this->bodies('POST', '/api/v1/certificates')[0]['user_id'] ?? null, 'sent exactly as given');
        self::assertSame('not-a-uuid', $this->bodies('POST', '/api/v1/certificates/sign-csr')[0]['user_id'] ?? null);

        // The RESPONSE member stays what it was: a nullable string the model decodes.
        self::assertSame('not-a-uuid', Models\Certificate::fromArray([
            'cert_type' => 'User', 'created_at' => '2026-10-13T00:00:00Z', 'fingerprint' => 'example',
            'id' => self::uuid(), 'issuer_ca_id' => $issuer, 'key_algorithm' => 'Rsa4096',
            'metadata' => [], 'not_after' => '2027-10-13T00:00:00Z', 'not_before' => '2026-10-13T00:00:00Z',
            'public_cert_pem' => 'example', 'status' => 'Active', 'subject' => 'example',
            'tenant_id' => self::TENANT_ID, 'user_id' => 'not-a-uuid',
        ])->userId);
    }
}
