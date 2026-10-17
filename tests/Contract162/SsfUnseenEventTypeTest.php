<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract162;

use Axiam\Sdk\Management\Models;
use Axiam\Sdk\Management\ReadModifyWrite;
use Axiam\Sdk\Ssf\SsfEventTypes;
use Axiam\Sdk\Tests\Contract158\ManagementRouteTestCase;
use Axiam\Sdk\Tests\Fixtures\RoutedHandler;

/**
 * C162-03 — an event-type URI this SDK has never seen is decoded WITH its value and goes back
 * UNCHANGED (CONTRACT.md §34.2 P12.2(b)); it is never `SsfEventType::Unknown`, whose wire
 * spelling is the empty string, which P12.2(a) forbids sending.
 *
 * The members `events_allowed`, `events_requested` and `events_delivered` of `SsfStream` and
 * `SsfStreamInput` are `list<SsfEventType|string>`: a known URI is its enum case, an unseen
 * one is its own string.
 */
final class SsfUnseenEventTypeTest extends ManagementRouteTestCase
{
    private const STREAMS = '/api/v1/tenants/' . self::TENANT_ID . '/ssf/streams';
    private const NEW = 'https://example.test/secevent/new-event';
    private const A = SsfEventTypes::SESSION_REVOKED;
    private const B = SsfEventTypes::CREDENTIAL_CHANGE;

    /** @param array<string,mixed> $extra */
    private static function stream(array $extra = []): Models\SsfStream
    {
        return Models\SsfStream::fromArray(array_merge([
            'id' => self::uuid(), 'tenant_id' => self::TENANT_ID, 'receiver_client_id' => 'rp-1',
            'audience' => 'https://rp.example', 'description' => null, 'delivery_method' => 'push',
            'endpoint_url' => 'https://rp.example/ssf', 'authorization_header_set' => false,
            'events_allowed' => [self::A, self::NEW, self::B],
            'events_requested' => [self::NEW, self::A],
            'events_delivered' => [self::A, self::NEW], 'subject_format' => 'iss_sub', 'status' => 'enabled',
            'status_reason' => null, 'status_actor' => 'admin', 'last_verification_at' => null,
            'created_at' => '2026-10-04T00:00:00Z', 'updated_at' => '2026-10-15T08:30:00.123456789+00:00',
            'transmitter_active' => true,
        ], $extra));
    }

    public function testAnUnseenUriDecodesWithItsValueAndAKnownOneAsItsCase(): void
    {
        $stream = self::stream();

        self::assertSame(Models\SsfEventType::SessionRevoked, $stream->eventsAllowed[0], 'known: its case');
        self::assertSame(self::NEW, $stream->eventsAllowed[1], 'unseen: its own string');
        self::assertSame(self::NEW, $stream->eventsRequested[0]);
        self::assertSame(self::NEW, $stream->eventsDelivered[1]);
        foreach ([$stream->eventsAllowed, $stream->eventsRequested, $stream->eventsDelivered] as $list) {
            self::assertNotContains(Models\SsfEventType::Unknown, $list, 'Unknown is never produced');
        }

        // The input model decodes the same way, both members.
        $input = Models\SsfStreamInput::fromArray([
            'audience' => 'https://rp.example', 'delivery_method' => 'push', 'receiver_client_id' => 'rp-1',
            'events_allowed' => [self::NEW], 'events_requested' => [self::NEW],
        ]);
        self::assertSame([self::NEW], $input->eventsAllowed);
        self::assertSame([self::NEW], $input->eventsRequested);
    }

    public function testTheConverterAndTheChangeTakingFormEncodeItBackByteForByte(): void
    {
        $stream = self::stream();
        $allowed = json_encode([self::A, self::NEW, self::B]);
        $requested = json_encode([self::NEW, self::A]);

        $plain = ReadModifyWrite::ssfStream($stream)->toArray();
        self::assertSame($allowed, json_encode($plain['events_allowed']));
        self::assertSame($requested, json_encode($plain['events_requested']));

        $changed = ReadModifyWrite::ssfStream($stream, ['description' => 'x'])->toArray();
        self::assertSame($allowed, json_encode($changed['events_allowed']));
        self::assertSame($requested, json_encode($changed['events_requested']));
        self::assertSame('x', $changed['description']);

        // The model's own wire form, too.
        $own = $stream->toArray();
        self::assertSame($allowed, json_encode($own['events_allowed']));
        self::assertSame(json_encode([self::A, self::NEW]), json_encode($own['events_delivered']));
        self::assertStringNotContainsString('""', (string) json_encode($changed));
    }

    public function testThroughUpdateStreamTheWireBodyCarriesItAndNeverTheEmptyString(): void
    {
        $stream = self::stream();
        $id = self::uuid();
        $this->routes->on('PUT', self::STREAMS . '/' . $id, RoutedHandler::json(200, $stream->toArray()));
        $ssf = $this->client()->ssf();

        $ssf->updateStream($id, ReadModifyWrite::ssfStream($stream));
        $ssf->updateStream($id, ReadModifyWrite::ssfStream($stream, ['description' => 'x']));

        foreach ($this->routes->sent('PUT', self::STREAMS . '/' . $id) as $request) {
            $raw = (string) $request->getBody();
            self::assertStringContainsString('"events_allowed":["' . self::A . '","' . self::NEW . '","' . self::B . '"]', str_replace('\\/', '/', $raw));
            self::assertStringContainsString('"events_requested":["' . self::NEW . '","' . self::A . '"]', str_replace('\\/', '/', $raw));
            self::assertStringNotContainsString('""', $raw, 'P12.2(a): never the empty string');
        }
        self::assertCount(2, $this->bodies('PUT', self::STREAMS . '/' . $id));
    }

    public function testALoweredCeilingThatStillHoldsItKeepsItAndOneThatDoesNotDropsIt(): void
    {
        $stream = self::stream();

        // Still in the new ceiling: kept, in the read order.
        $kept = ReadModifyWrite::ssfStream($stream, ['events_allowed' => [self::A, self::NEW]])->toArray();
        self::assertSame([self::NEW, self::A], $kept['events_requested']);
        self::assertSame([self::A, self::NEW], $kept['events_allowed']);

        // A ceiling of the unseen URI alone keeps only it.
        $only = ReadModifyWrite::ssfStream($stream, ['events_allowed' => [self::NEW]])->toArray();
        self::assertSame([self::NEW], $only['events_requested']);

        // Not in the new ceiling: dropped, and the known one stays.
        $dropped = ReadModifyWrite::ssfStream($stream, ['events_allowed' => [self::A, self::B]])->toArray();
        self::assertSame([self::A], $dropped['events_requested']);
    }
}
