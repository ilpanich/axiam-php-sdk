<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract162;

use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Management\ConflictError;
use Axiam\Sdk\Management\ManagementTransport;
use Axiam\Sdk\Management\Models;
use Axiam\Sdk\Management\NetworkApi;
use Axiam\Sdk\Management\NotFoundError;
use Axiam\Sdk\Management\Page;
use Axiam\Sdk\Management\PageRequest;
use Axiam\Sdk\Management\ValidationError;
use Axiam\Sdk\Tests\Contract158\ManagementRouteTestCase;
use Axiam\Sdk\Tests\Fixtures\RoutedHandler;
use GuzzleHttp\Psr7\Response;

/**
 * The `network` namespace — CONTRACT.md §36.8's five required tests (contract 1.62), against a
 * mocked HTTP server on the SDK's real request path.
 *
 * The manifest half of the namespace (§27.6.2) is in {@see NetworkManifestTest}.
 */
final class NetworkManagementTest extends ManagementRouteTestCase
{
    private const SEGMENTS = '/api/v1/network/segments';
    private const PROFILES = '/api/v1/network/profiles';
    private const POLICY = '/api/v1/network/policy';

    /**
     * @param array<string,mixed> $extra
     * @return array<string,mixed>
     */
    private static function segment(array $extra = []): array
    {
        return array_merge([
            'id' => self::uuid(), 'tenant_id' => self::TENANT_ID,
            'path' => '/network/zones/hq/staff', 'name' => 'staff', 'site_key' => 'hq',
            'kind' => 'access', 'vlan_id' => 20, 'filter_ids' => ['staff-in'], 'rank' => 1,
            'enabled' => true, 'version' => 3,
            'created_by' => self::uuid(), 'updated_by' => self::uuid(),
            'created_at' => '2026-10-16T08:00:00Z', 'updated_at' => '2026-10-16T09:00:00Z',
        ], $extra);
    }

    /**
     * @param array<string,mixed> $extra
     * @return array<string,mixed>
     */
    private static function profile(string $segmentId, array $extra = []): array
    {
        return array_merge([
            'segment_id' => $segmentId, 'tenant_id' => self::TENANT_ID,
            'dictionary' => 'axiam-radius-reply/1', 'session_timeout_secs' => 3600,
            'session_timeout_clamped' => false, 'termination_action' => 'radius_request',
            'idle_timeout_secs' => 600, 'filter_id' => 'staff-in', 'service_type' => 'framed_user',
            'version' => 2,
            'created_by' => self::uuid(), 'updated_by' => self::uuid(),
            'created_at' => '2026-10-16T08:00:00Z', 'updated_at' => '2026-10-16T09:00:00Z',
        ], $extra);
    }

    /** @return array<string,mixed> */
    private static function policy(): array
    {
        return ['tenant_id' => self::TENANT_ID, 'session_timeout_max_secs' => 3600, 'version' => 0];
    }

    private static function input(): Models\NetworkReplyProfileInput
    {
        return new Models\NetworkReplyProfileInput(sessionTimeoutSecs: 1800);
    }

    // -- 1. The surface ------------------------------------------------------------------

    public function testTheTwelveOperationsHaveTheirPathsAndMethodsAndTheDecisionRouteHasNone(): void
    {
        $client = $this->client();
        $id = self::uuid();
        $this->routes->on('GET', self::SEGMENTS, RoutedHandler::json(200, ['items' => [], 'total' => 0, 'offset' => 0, 'limit' => 50]));
        $this->routes->on('POST', self::SEGMENTS, RoutedHandler::json(201, self::segment()));
        $this->routes->on('GET', self::SEGMENTS . '/' . $id, RoutedHandler::json(200, self::segment()));
        $this->routes->on('PUT', self::SEGMENTS . '/' . $id, RoutedHandler::json(200, self::segment()));
        $this->routes->on('DELETE', self::SEGMENTS . '/' . $id, new Response(204));
        $this->routes->on('GET', self::PROFILES, RoutedHandler::json(200, ['items' => [], 'total' => 0, 'offset' => 0, 'limit' => 50]));
        $this->routes->on('POST', self::PROFILES, RoutedHandler::json(201, self::profile($id)));
        $this->routes->on('GET', self::PROFILES . '/' . $id, RoutedHandler::json(200, self::profile($id)));
        $this->routes->on('PUT', self::PROFILES . '/' . $id, RoutedHandler::json(200, self::profile($id)));
        $this->routes->on('DELETE', self::PROFILES . '/' . $id, new Response(204));
        $this->routes->on('GET', self::POLICY, RoutedHandler::json(200, self::policy()));
        $this->routes->on('PUT', self::POLICY, RoutedHandler::json(200, self::policy()));

        $n = $client->network();
        $n->listSegments();
        $n->createSegment(new Models\CreateNetworkSegmentRequest(Models\NetworkSegmentKind::Access, 'staff', 'hq', 20, rank: 1));
        $n->getSegment($id);
        $n->replaceSegment($id, new Models\ReplaceNetworkSegmentRequest(true, [], 3, 20, 1));
        $n->deleteSegment($id, 3);
        $n->listProfiles();
        $n->createProfile(new Models\CreateNetworkReplyProfileRequest(self::input(), $id, 3));
        $n->getProfile($id);
        $n->replaceProfile($id, new Models\ReplaceNetworkReplyProfileRequest(self::input(), 3, 2));
        $n->deleteProfile($id, 2);
        $n->getPolicy();
        $n->replacePolicy(new Models\ReplaceNetworkPolicyRequest(3600, 0));

        // 12 management requests after the login: every one reached the path and method of §36.1.
        $reached = [];
        foreach (\array_slice($this->routes->requests, 1) as $request) {
            $reached[] = $request->getMethod() . ' ' . $request->getUri()->getPath();
        }
        self::assertSame([
            'GET ' . self::SEGMENTS, 'POST ' . self::SEGMENTS, 'GET ' . self::SEGMENTS . '/' . $id,
            'PUT ' . self::SEGMENTS . '/' . $id, 'DELETE ' . self::SEGMENTS . '/' . $id,
            'GET ' . self::PROFILES, 'POST ' . self::PROFILES, 'GET ' . self::PROFILES . '/' . $id,
            'PUT ' . self::PROFILES . '/' . $id, 'DELETE ' . self::PROFILES . '/' . $id,
            'GET ' . self::POLICY, 'PUT ' . self::POLICY,
        ], $reached);

        // `management()->network()` and `client->network()` are the same handle.
        self::assertInstanceOf(NetworkApi::class, $client->management()->network());

        // The registry holds exactly these twelve and excludes the decision route by name; the
        // handle has no method for it. (§27.8's regeneration check is what keeps it out.)
        $registry = json_decode((string) file_get_contents(__DIR__ . '/../../management-registry.json'), true);
        self::assertIsArray($registry);
        $paths = [];
        foreach ($registry['namespaces']['network']['operations'] as $operation) {
            $paths[] = $operation['method'] . ' ' . $operation['path'];
        }
        self::assertCount(12, $paths);
        self::assertSame(202, $registry['operation_count']);
        self::assertSame(29, $registry['namespace_count']);
        self::assertNotContains('POST /api/v1/network/decide', $paths);
        self::assertArrayHasKey('POST /api/v1/network/decide', $registry['excluded_operations']);
        $methods = array_diff(get_class_methods(NetworkApi::class), get_class_methods(\Axiam\Sdk\Management\ManagementSupport::class));
        sort($methods);
        self::assertSame([
            'createProfile', 'createSegment', 'deleteProfile', 'deleteSegment', 'getPolicy', 'getProfile',
            'getSegment', 'listProfiles', 'listSegments', 'replacePolicy', 'replaceProfile', 'replaceSegment',
        ], $methods);
    }

    // -- 2. Versions ---------------------------------------------------------------------

    public function testEveryWriteSendsTheVersionItWasGivenExactly(): void
    {
        $client = $this->client();
        $id = self::uuid();
        $this->routes->on('PUT', self::SEGMENTS . '/' . $id, RoutedHandler::json(200, self::segment()));
        $this->routes->on('DELETE', self::SEGMENTS . '/' . $id, new Response(204));
        $this->routes->on('DELETE', self::PROFILES . '/' . $id, new Response(204));
        $this->routes->on('POST', self::PROFILES, RoutedHandler::json(201, self::profile($id)));
        $this->routes->on('PUT', self::PROFILES . '/' . $id, RoutedHandler::json(200, self::profile($id)));
        $this->routes->on('PUT', self::POLICY, RoutedHandler::json(200, self::policy()));
        $n = $client->network();

        $n->replaceSegment($id, new Models\ReplaceNetworkSegmentRequest(true, ['a'], 41, 20, 1));
        $n->deleteSegment($id, 42);
        $n->deleteProfile($id, 43);
        $n->createProfile(new Models\CreateNetworkReplyProfileRequest(self::input(), $id, 44));
        $n->replaceProfile($id, new Models\ReplaceNetworkReplyProfileRequest(self::input(), 45, 46));
        $n->replacePolicy(new Models\ReplaceNetworkPolicyRequest(7200, 0));

        $put = $this->bodies('PUT', self::SEGMENTS . '/' . $id)[0];
        self::assertIsArray($put);
        self::assertSame(41, $put['version']);
        self::assertSame('version=42', $this->queries('DELETE', self::SEGMENTS . '/' . $id)[0]);
        self::assertSame('version=43', $this->queries('DELETE', self::PROFILES . '/' . $id)[0]);
        $created = $this->bodies('POST', self::PROFILES)[0];
        self::assertIsArray($created);
        self::assertSame(44, $created['segment_version']);
        self::assertSame($id, $created['segment_id']);
        $replaced = $this->bodies('PUT', self::PROFILES . '/' . $id)[0];
        self::assertIsArray($replaced);
        self::assertSame(46, $replaced['version']);
        self::assertSame(45, $replaced['segment_version']);
        $policy = $this->bodies('PUT', self::POLICY)[0];
        self::assertIsArray($policy);
        self::assertSame(0, $policy['version'], 'a tenant that has never written one sends version 0');

        // A delete cannot be called without its version.
        $this->expectException(\ArgumentCountError::class);
        /** @phpstan-ignore-next-line deliberately missing argument */
        $n->deleteSegment($id);
    }

    public function testDeleteProfileCannotBeCalledWithoutAVersion(): void
    {
        $client = $this->client();
        $this->expectException(\ArgumentCountError::class);
        /** @phpstan-ignore-next-line deliberately missing argument */
        $client->network()->deleteProfile(self::uuid());
    }

    public function testA409ToEachWriteIsAConflictErrorAfterOneRequestAndExposesItsReasonCode(): void
    {
        $client = $this->client(retry: true);
        $id = self::uuid();
        $stale = RoutedHandler::json(409, ['error' => 'conflict', 'message' => 'the row changed', 'reason_code' => 'stale_version']);
        $writes = [
            ['POST', self::SEGMENTS], ['PUT', self::SEGMENTS . '/' . $id], ['DELETE', self::SEGMENTS . '/' . $id],
            ['POST', self::PROFILES], ['PUT', self::PROFILES . '/' . $id], ['DELETE', self::PROFILES . '/' . $id],
            ['PUT', self::POLICY],
        ];
        foreach ($writes as [$method, $path]) {
            $this->routes->on($method, $path, $stale);
        }
        $n = $client->network();
        $calls = [
            fn () => $n->createSegment(new Models\CreateNetworkSegmentRequest(Models\NetworkSegmentKind::Access, 'staff', 'hq', 20, rank: 1)),
            fn () => $n->replaceSegment($id, new Models\ReplaceNetworkSegmentRequest(true, [], 3, 20, 1)),
            fn () => $n->deleteSegment($id, 3),
            fn () => $n->createProfile(new Models\CreateNetworkReplyProfileRequest(self::input(), $id, 3)),
            fn () => $n->replaceProfile($id, new Models\ReplaceNetworkReplyProfileRequest(self::input(), 3, 2)),
            fn () => $n->deleteProfile($id, 2),
            fn () => $n->replacePolicy(new Models\ReplaceNetworkPolicyRequest(3600, 0)),
        ];
        foreach ($calls as $call) {
            try {
                $call();
                self::fail('expected a ConflictError');
            } catch (ConflictError $e) {
                self::assertSame('stale_version', $e->getReasonCode());
                self::assertInstanceOf(AuthzError::class, $e, '§27.4 rule 7: a 409 stays under AuthzError');
                self::assertStringContainsString('the row changed', $e->getMessage());
            }
        }
        foreach ($writes as [$method, $path]) {
            self::assertCount(1, $this->routes->sent($method, $path), "$method $path is never retried");
        }
    }

    public function testAnAlreadyExists409ExposesItsReasonCodeToo(): void
    {
        $client = $this->client();
        $this->routes->on('POST', self::SEGMENTS, RoutedHandler::json(409, [
            'error' => 'already_exists', 'message' => 'VLAN 20 is taken at hq', 'reason_code' => 'duplicate_vlan',
        ]));

        try {
            $client->network()->createSegment(new Models\CreateNetworkSegmentRequest(Models\NetworkSegmentKind::Access, 'other', 'hq', 20, rank: 2));
            self::fail('expected a ConflictError');
        } catch (ConflictError $e) {
            self::assertSame('duplicate_vlan', $e->getReasonCode());
        }
    }

    public function testAReasonCodeThisSdkHasNeverSeenIsSurfacedVerbatimAndAbsenceIsNull(): void
    {
        $client = $this->client();
        $this->routes->on('POST', self::SEGMENTS, RoutedHandler::json(409, ['error' => 'conflict', 'reason_code' => 'a_code_from_2027']));
        $this->routes->on('POST', self::PROFILES, RoutedHandler::json(409, ['error' => 'conflict', 'message' => 'a server before 1.1.0']));
        $n = $client->network();

        try {
            $n->createSegment(new Models\CreateNetworkSegmentRequest(Models\NetworkSegmentKind::Access, 'staff', 'hq', 20, rank: 1));
            self::fail('expected a ConflictError');
        } catch (ConflictError $e) {
            self::assertSame('a_code_from_2027', $e->getReasonCode());
        }
        try {
            $n->createProfile(new Models\CreateNetworkReplyProfileRequest(self::input(), self::uuid(), 1));
            self::fail('expected a ConflictError');
        } catch (ConflictError $e) {
            self::assertNull($e->getReasonCode());
        }
    }

    // -- 3. Closed bodies ----------------------------------------------------------------

    public function testRequestBodiesCarryExactlyTheKeysTheMembersSetNameAndNeverNull(): void
    {
        $segment = new Models\CreateNetworkSegmentRequest(Models\NetworkSegmentKind::Quarantine, 'jail', 'hq', 99);
        self::assertSame(['kind' => 'quarantine', 'name' => 'jail', 'site_key' => 'hq', 'vlan_id' => 99], $segment->toArray());
        $full = new Models\CreateNetworkSegmentRequest(Models\NetworkSegmentKind::Access, 'staff', 'hq', 20, true, ['a', 'b'], 1);
        self::assertEqualsCanonicalizing(['kind', 'name', 'site_key', 'vlan_id', 'enabled', 'filter_ids', 'rank'], array_keys($full->toArray()));

        $replace = new Models\ReplaceNetworkSegmentRequest(true, ['a'], 3, 20);
        self::assertEqualsCanonicalizing(['enabled', 'filter_ids', 'version', 'vlan_id'], array_keys($replace->toArray()), 'no kind, site_key or name, and an unset rank is absent');
        self::assertEqualsCanonicalizing(['enabled', 'filter_ids', 'version', 'vlan_id', 'rank'], array_keys((new Models\ReplaceNetworkSegmentRequest(true, ['a'], 3, 20, 2))->toArray()));

        $minimal = (new Models\CreateNetworkReplyProfileRequest(self::input(), 'seg', 7))->toArray();
        self::assertEqualsCanonicalizing(['profile', 'segment_id', 'segment_version'], array_keys($minimal));
        self::assertSame(['session_timeout_secs' => 1800], $minimal['profile'], 'unset idle_timeout_secs, filter_id and service_type are absent, not null');
        $input = new Models\NetworkReplyProfileInput(1800, 'axiam-radius-reply/1', 'f', 120, Models\RadiusServiceType::FramedUser, Models\RadiusTerminationAction::Default);
        self::assertEqualsCanonicalizing(
            ['dictionary', 'filter_id', 'idle_timeout_secs', 'service_type', 'session_timeout_secs', 'termination_action'],
            array_keys($input->toArray()),
        );
        self::assertArrayNotHasKey('vlan_id', $input->toArray(), 'a profile has no VLAN member: the VLAN is the segment\'s');
        self::assertFalse(property_exists(Models\NetworkReplyProfileInput::class, 'vlanId'));

        self::assertSame(
            ['session_timeout_max_secs' => 3600, 'version' => 0],
            (new Models\ReplaceNetworkPolicyRequest(3600, 0))->toArray(),
        );
        $replaceProfile = (new Models\ReplaceNetworkReplyProfileRequest(self::input(), 4, 5))->toArray();
        self::assertEqualsCanonicalizing(['profile', 'segment_version', 'version'], array_keys($replaceProfile));

        // The replace types cannot be built without their required members.
        foreach ([
            fn () => new Models\ReplaceNetworkSegmentRequest(true),
            fn () => new Models\ReplaceNetworkReplyProfileRequest(self::input()),
            fn () => new Models\ReplaceNetworkPolicyRequest(3600),
            fn () => new Models\CreateNetworkReplyProfileRequest(self::input()),
        ] as $build) {
            try {
                /** @phpstan-ignore-next-line deliberately missing arguments */
                $build();
                self::fail('expected an ArgumentCountError');
            } catch (\ArgumentCountError) {
                $this->addToAssertionCount(1);
            }
        }
    }

    // -- 4. Open decoding and pagination -------------------------------------------------

    public function testOpenEnumerationsDecodeAndAClampedProfileKeepsBothMembers(): void
    {
        $odd = Models\NetworkSegmentResponse::fromArray(self::segment(['kind' => 'transit']));
        self::assertSame(Models\NetworkSegmentKind::Unknown, $odd->kind);

        $segmentId = self::uuid();
        $profile = Models\NetworkReplyProfile::fromArray(self::profile($segmentId, [
            'termination_action' => 'coa', 'service_type' => 'callback_login',
        ]));
        self::assertSame(Models\RadiusTerminationAction::Unknown, $profile->terminationAction);
        self::assertSame(Models\RadiusServiceType::Unknown, $profile->serviceType);

        $clamped = Models\NetworkReplyProfile::fromArray(self::profile($segmentId, [
            'session_timeout_secs' => 900, 'session_timeout_clamped' => true,
        ]));
        self::assertTrue($clamped->sessionTimeoutClamped);
        self::assertSame(900, $clamped->sessionTimeoutSecs);
    }

    public function testBothListsReturnAPageWithItsTotalAndTheWalkCarriesSearchAndSite(): void
    {
        $client = $this->client();
        $this->routes->on('GET', self::SEGMENTS, self::pager(self::segment(), 2));
        $this->routes->on('GET', self::PROFILES, self::pager(self::profile(self::uuid()), 2));
        $n = $client->network();

        $segments = $n->listSegments(new PageRequest(0, 1, 'staff'), 'hq');
        self::assertInstanceOf(Page::class, $segments);
        self::assertSame(2, $segments->total);
        self::assertCount(1, $segments, 'total is the server\'s count, not the length of the page');
        $profiles = $n->listProfiles(new PageRequest(0, 1));
        self::assertSame(2, $profiles->total);

        $this->routes->requests = [];
        $all = iterator_to_array(ManagementTransport::walk(
            static fn (PageRequest $p): Page => $n->listSegments($p, 'hq'),
            new PageRequest(0, 1, 'staff'),
        ), false);
        self::assertCount(2, $all);
        $queries = $this->queries('GET', self::SEGMENTS);
        self::assertCount(3, $queries, 'two pages and the empty one that ends the walk');
        foreach ($queries as $query) {
            parse_str($query, $parsed);
            self::assertSame('staff', $parsed['search'] ?? null, 'search is on every request of the walk');
            self::assertSame('hq', $parsed['site'] ?? null, 'so is site');
        }
    }

    // -- 5. Errors -----------------------------------------------------------------------

    public function testStatusesMapPerSection2(): void
    {
        $client = $this->client();
        $id = self::uuid();
        $this->routes->on('POST', self::SEGMENTS, RoutedHandler::json(403, [
            'error' => 'authorization_denied', 'message' => 'missing permission', 'action' => 'network:grant', 'resource_id' => $id,
        ]));
        $this->routes->on('PUT', self::SEGMENTS . '/' . $id, RoutedHandler::json(400, ['error' => 'validation_error', 'message' => 'vlan_id: must be 1 to 4094']));
        $this->routes->on('GET', self::PROFILES . '/' . $id, RoutedHandler::json(404, ['error' => 'not_found', 'message' => 'no']));
        $this->routes->on('GET', self::POLICY, RoutedHandler::json(401, ['error' => 'unauthorized', 'message' => 'human only']));
        $this->routes->on('POST', '/api/v1/auth/refresh', RoutedHandler::json(401, ['error' => 'unauthorized']));
        $n = $client->network();

        try {
            $n->createSegment(new Models\CreateNetworkSegmentRequest(Models\NetworkSegmentKind::Access, 'staff', 'hq', 20, rank: 1));
            self::fail('expected an AuthzError');
        } catch (AuthzError $e) {
            self::assertNotInstanceOf(ConflictError::class, $e);
            self::assertNotInstanceOf(NotFoundError::class, $e);
            self::assertSame('network:grant', $e->getAction());
            self::assertSame($id, $e->getResourceId());
        }
        try {
            $n->replaceSegment($id, new Models\ReplaceNetworkSegmentRequest(true, [], 1, 5000));
            self::fail('expected a ValidationError');
        } catch (ValidationError $e) {
            self::assertSame('vlan_id: must be 1 to 4094', $e->serverMessage);
        }
        try {
            $n->getProfile($id);
            self::fail('expected a NotFoundError');
        } catch (NotFoundError) {
            $this->addToAssertionCount(1);
        }
        try {
            $n->getPolicy();
            self::fail('expected an AuthError');
        } catch (AuthError) {
            $this->addToAssertionCount(1);
        }
    }

    public function testNoneOfTheSevenWritesIsRetriedOn429Or503(): void
    {
        foreach ([429, 503] as $status) {
            $this->setUp();
            $client = $this->client(retry: true);
            $id = self::uuid();
            $writes = [
                ['POST', self::SEGMENTS], ['PUT', self::SEGMENTS . '/' . $id], ['DELETE', self::SEGMENTS . '/' . $id],
                ['POST', self::PROFILES], ['PUT', self::PROFILES . '/' . $id], ['DELETE', self::PROFILES . '/' . $id],
                ['PUT', self::POLICY],
            ];
            foreach ($writes as [$method, $path]) {
                $this->routes->on($method, $path, new Response($status));
            }
            $n = $client->network();
            $calls = [
                fn () => $n->createSegment(new Models\CreateNetworkSegmentRequest(Models\NetworkSegmentKind::Access, 'staff', 'hq', 20, rank: 1)),
                fn () => $n->replaceSegment($id, new Models\ReplaceNetworkSegmentRequest(true, [], 3, 20, 1)),
                fn () => $n->deleteSegment($id, 3),
                fn () => $n->createProfile(new Models\CreateNetworkReplyProfileRequest(self::input(), $id, 3)),
                fn () => $n->replaceProfile($id, new Models\ReplaceNetworkReplyProfileRequest(self::input(), 3, 2)),
                fn () => $n->deleteProfile($id, 2),
                fn () => $n->replacePolicy(new Models\ReplaceNetworkPolicyRequest(3600, 0)),
            ];
            foreach ($calls as $call) {
                try {
                    $call();
                    self::fail("expected a NetworkError on $status");
                } catch (NetworkError $e) {
                    self::assertNotInstanceOf(ValidationError::class, $e);
                }
            }
            foreach ($writes as [$method, $path]) {
                self::assertCount(1, $this->routes->sent($method, $path), "$method $path on $status");
            }
        }
    }
}
