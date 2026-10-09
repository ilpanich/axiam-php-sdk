<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract158;

use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Management\ConflictError;
use Axiam\Sdk\Management\ManagementTransport;
use Axiam\Sdk\Management\Models;
use Axiam\Sdk\Management\NotFoundError;
use Axiam\Sdk\Management\Page;
use Axiam\Sdk\Management\PageRequest;
use Axiam\Sdk\Management\ReadModifyWrite;
use Axiam\Sdk\Management\ValidationError;
use Axiam\Sdk\Ssf\SsfEventTypes;
use Axiam\Sdk\Tests\Fixtures\RoutedHandler;
use GuzzleHttp\Psr7\Response;

/**
 * The `ssf` management namespace — CONTRACT.md §32.8's six management tests. (The receiver
 * helper's eight are in {@see SsfReceiverTest}.)
 */
final class SsfManagementTest extends ManagementRouteTestCase
{
    private const STREAMS = '/api/v1/tenants/' . self::TENANT_ID . '/ssf/streams';

    private static function header(): string
    {
        return 'Bearer ' . bin2hex(random_bytes(20));
    }

    /**
     * @param array<string,mixed> $extra
     * @return array<string,mixed>
     */
    private static function stream(array $extra = []): array
    {
        return array_merge([
            'id' => self::uuid(), 'tenant_id' => self::TENANT_ID, 'receiver_client_id' => 'rp-1',
            'audience' => 'https://rp.example', 'description' => null, 'delivery_method' => 'push',
            'endpoint_url' => 'https://rp.example/ssf', 'authorization_header_set' => true,
            'events_allowed' => [SsfEventTypes::SESSION_REVOKED], 'events_requested' => [SsfEventTypes::SESSION_REVOKED],
            'events_delivered' => [SsfEventTypes::SESSION_REVOKED],
            'subject_format' => 'iss_sub', 'status' => 'enabled', 'status_reason' => null,
            'status_actor' => 'admin', 'last_verification_at' => null,
            'created_at' => '2026-10-04T00:00:00Z', 'updated_at' => '2026-10-04T00:00:00Z',
            'transmitter_active' => true,
        ], $extra);
    }

    private static function input(?string $header = null, bool $full = false): Models\SsfStreamInput
    {
        return new Models\SsfStreamInput(
            audience: 'https://rp.example',
            deliveryMethod: Models\SsfDeliveryMethod::Push,
            eventsAllowed: [Models\SsfEventType::SessionRevoked],
            receiverClientId: 'rp-1',
            authorizationHeader: $header !== null ? new Sensitive($header) : null,
            clearAuthorizationHeader: $full ? false : null,
            description: 'the RP',
            endpointUrl: 'https://rp.example/ssf',
            eventsRequested: $full ? [Models\SsfEventType::SessionRevoked] : null,
            status: $full ? Models\SsfStreamStatus::Enabled : null,
            statusReason: $full ? 'ok' : null,
            subjectFormat: $full ? Models\SsfSubjectFormat::IssSub : null,
        );
    }

    // -- 1. Replacement ------------------------------------------------------------------

    public function testUpdateStreamPutsEveryMemberItModels(): void
    {
        $client = $this->client();
        $id = self::uuid();
        $this->routes->on('PUT', self::STREAMS . '/' . $id, RoutedHandler::json(200, self::stream()));

        $stream = $client->ssf()->updateStream($id, self::input(full: true));
        self::assertTrue($stream->transmitterActive);
        $sent = $this->bodies('PUT', self::STREAMS . '/' . $id)[0];
        self::assertIsArray($sent);
        foreach (['receiver_client_id', 'audience', 'delivery_method', 'events_allowed', 'description',
            'endpoint_url', 'events_requested', 'subject_format', 'status', 'status_reason',
            'clear_authorization_header'] as $member) {
            self::assertArrayHasKey($member, $sent);
        }
        self::assertSame([SsfEventTypes::SESSION_REVOKED], $sent['events_allowed']);
        self::assertArrayNotHasKey('authorization_header', $sent, 'absent keeps the stored header');

        $this->expectException(\ArgumentCountError::class);
        /** @phpstan-ignore-next-line deliberately missing arguments */
        new Models\SsfStreamInput(audience: 'a');
    }

    // -- 2. The header is Sensitive ------------------------------------------------------

    public function testThePushHeaderIsSentAndNeverRenderedOrDecoded(): void
    {
        $client = $this->client();
        $header = self::header();
        $body = self::input($header);
        self::assertNoFragment(self::renderings($body), $header);
        $this->routes->on('POST', self::STREAMS, RoutedHandler::json(201, self::stream(['authorization_header' => $header])));

        $created = $client->ssf()->createStream($body);
        $sent = $this->bodies('POST', self::STREAMS)[0];
        self::assertIsArray($sent);
        self::assertSecretEquals($header, $sent['authorization_header'] ?? null, 'authorization_header');
        self::assertNoFragment(self::renderings($created), $header);
        self::assertFalse(property_exists($created, 'authorizationHeader'), 'no accessor for the header');
        self::assertTrue($created->authorizationHeaderSet);
    }

    // -- 3. Open decoding -------------------------------------------------------------

    public function testUnknownValuesAndBothTransmitterStatesDecode(): void
    {
        $odd = Models\SsfStream::fromArray(self::stream([
            'status' => 'quarantined', 'delivery_method' => 'websocket', 'subject_format' => 'opaque',
            'status_actor' => 'policy', 'events_allowed' => ['https://example.test/event-type/new'],
        ]));
        self::assertSame(Models\SsfStreamStatus::Unknown, $odd->status);
        self::assertSame(Models\SsfDeliveryMethod::Unknown, $odd->deliveryMethod);
        self::assertSame(Models\SsfSubjectFormat::Unknown, $odd->subjectFormat);
        self::assertSame(Models\SsfStatusActor::Unknown, $odd->statusActor);
        self::assertSame(Models\SsfEventType::Unknown, $odd->eventsAllowed[0]);

        $inactive = Models\SsfStream::fromArray(self::stream([
            'transmitter_active' => false,
            'transmitter_inactive_reason' => 'per-tenant issuers are off in a multi-tenant deployment',
        ]));
        self::assertFalse($inactive->transmitterActive);
        self::assertNotNull($inactive->transmitterInactiveReason);
        self::assertNull(Models\SsfStream::fromArray(self::stream())->transmitterInactiveReason);
    }

    // -- 4. Pagination -------------------------------------------------------------------

    public function testListStreamsPagesAndTheWalkCarriesSearch(): void
    {
        $client = $this->client();
        $this->routes->on('GET', self::STREAMS, self::pager(self::stream(), 2));
        $ssf = $client->ssf();

        $page = $ssf->listStreams(new PageRequest(0, 1, 'rp.example'));
        self::assertInstanceOf(Page::class, $page);
        self::assertSame(2, $page->total);
        $all = iterator_to_array(ManagementTransport::walk(
            static fn (PageRequest $p): Page => $ssf->listStreams($p),
            new PageRequest(0, 1, 'rp.example'),
        ), false);
        self::assertCount(2, $all);
        foreach ($this->queries('GET', self::STREAMS) as $query) {
            self::assertStringContainsString('search=rp.example', $query);
        }
    }

    // -- 5. No retry ---------------------------------------------------------------------

    public function testNoneOfTheThreeWritesIsRetriedOn503(): void
    {
        $client = $this->client(retry: true);
        $id = self::uuid();
        $routes = [['POST', self::STREAMS], ['PUT', self::STREAMS . '/' . $id], ['DELETE', self::STREAMS . '/' . $id]];
        foreach ($routes as [$method, $path]) {
            $this->routes->on($method, $path, new Response(503));
        }
        $s = $client->ssf();
        foreach ([
            fn () => $s->createStream(self::input(self::header())),
            fn () => $s->updateStream($id, self::input()),
            fn () => $s->deleteStream($id),
        ] as $call) {
            try {
                $call();
                self::fail('expected a NetworkError');
            } catch (NetworkError $e) {
                self::assertNotInstanceOf(ValidationError::class, $e);
            }
        }
        foreach ($routes as [$method, $path]) {
            self::assertCount(1, $this->routes->sent($method, $path), $method . ' ' . $path);
        }
    }

    // -- 6. Errors -----------------------------------------------------------------------

    public function testStatusesMapPerSection2(): void
    {
        $client = $this->client();
        $id = self::uuid();
        $this->routes->on('PUT', self::STREAMS . '/' . $id, RoutedHandler::json(400, ['error' => 'validation_error', 'message' => 'endpoint_url: must be https']));
        $this->routes->on('POST', self::STREAMS, RoutedHandler::json(409, ['error' => 'conflict', 'message' => 'audience']));
        $this->routes->on('GET', self::STREAMS . '/' . $id, RoutedHandler::json(404, ['error' => 'not_found', 'message' => 'no']));
        $this->routes->on('DELETE', self::STREAMS . '/' . $id, RoutedHandler::json(401, ['error' => 'unauthorized', 'message' => 'human only']));
        $this->routes->on('POST', '/api/v1/auth/refresh', RoutedHandler::json(401, ['error' => 'unauthorized']));

        $s = $client->ssf();
        $expect = function (callable $call, string $type): \Throwable {
            try {
                $call();
            } catch (\Throwable $e) {
                self::assertInstanceOf($type, $e);

                return $e;
            }
            self::fail('expected ' . $type);
        };
        self::assertStringContainsString('https', $expect(fn () => $s->updateStream($id, self::input()), ValidationError::class)->getMessage());
        $expect(fn () => $s->createStream(self::input()), ConflictError::class);
        $expect(fn () => $s->getStream($id), NotFoundError::class);
        $expect(fn () => $s->deleteStream($id), AuthError::class);
    }

    public function testAReadConvertsIntoTheReplacementBodyWithoutTheHeader(): void
    {
        $stream = Models\SsfStream::fromArray(self::stream());
        $body = ReadModifyWrite::ssfStream($stream);
        self::assertNull($body->authorizationHeader);
        self::assertNull($body->clearAuthorizationHeader);
        self::assertSame($stream->eventsRequested, $body->eventsRequested);

        $header = self::header();
        $moved = ReadModifyWrite::ssfStream($stream, ['endpoint_url' => 'https://rp2.example/ssf', 'authorization_header' => $header]);
        self::assertSame('https://rp2.example/ssf', $moved->endpointUrl);
        self::assertNotNull($moved->authorizationHeader);
        self::assertSecretEquals($header, $moved->authorizationHeader->reveal(), 'authorization_header');
    }
}
