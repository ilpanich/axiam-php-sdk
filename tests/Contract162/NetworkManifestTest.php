<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract162;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Management\ConflictError;
use Axiam\Sdk\Management\JsonNull;
use Axiam\Sdk\Management\Manifest\ApplyReport;
use Axiam\Sdk\Management\Manifest\ChangeAction;
use Axiam\Sdk\Management\Manifest\ManagementManifest;
use Axiam\Sdk\Management\Manifest\ManifestBuilder;
use Axiam\Sdk\Management\Manifest\ManifestEntity;
use Axiam\Sdk\Management\Manifest\ManifestException;
use Axiam\Sdk\Management\Manifest\ManifestKind;
use Axiam\Sdk\Management\Manifest\ManagementPlan;
use Axiam\Sdk\Management\Models;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * The `network` namespace in a manifest — CONTRACT.md §27.6.2 and the "Manifest, `network`"
 * block of §27.9 (contract 1.62), against {@see FakeNetworkServer}, whose versions move and are
 * checked the way the real server's do.
 *
 * Each test names the sentence of the contract it pins.
 */
final class NetworkManifestTest extends TestCase
{
    private const SEGMENTS = '/api/v1/network/segments';
    private const PROFILES = '/api/v1/network/profiles';
    private const POLICY = '/api/v1/network/policy';

    private FakeNetworkServer $server;

    protected function setUp(): void
    {
        $this->server = new FakeNetworkServer();
    }

    private function client(bool $retry = true): AxiamClient
    {
        $client = new AxiamClient(
            'https://iam.example.test',
            'acme',
            orgId: '11111111-1111-4111-8111-111111111111',
            oidcTenantId: FakeNetworkServer::TENANT_ID,
            transportHandler: $this->server,
            retryEnabled: $retry,
        );
        $client->login('admin@example.test', bin2hex(random_bytes(8)));

        return $client;
    }

    /** The manifest every "full" test starts from: a policy, two access segments, one profile. */
    private function manifest(?ManifestBuilder $builder = null): ManagementManifest
    {
        return ($builder ?? $this->builder())->build();
    }

    private function builder(): ManifestBuilder
    {
        return ManagementManifest::builder()
            ->networkPolicy(7200)
            ->networkSegment('staff', 'hq', 'access', 'staff', 20, rank: 1, filterIds: ['staff-in', 'staff-out'])
            ->networkSegment('guest', 'hq', 'access', 'guest', 30, rank: 2)
            ->networkProfile('staff', 3600, idleTimeoutSecs: 600, filterId: 'staff-in');
    }

    private function plan(ManagementManifest $manifest): ManagementPlan
    {
        return $this->client()->management()->manifest()->plan($manifest);
    }

    private function apply(ManagementManifest $manifest, ?AxiamClient $client = null): ApplyReport
    {
        return ($client ?? $this->client())->management()->manifest()->apply($manifest);
    }

    private static function assertConverged(ManagementPlan $plan): void
    {
        self::assertSame([], $plan->describe(), 'every action should be NoChange');
        self::assertTrue($plan->isConverged());
    }

    // -- plan writes nothing -------------------------------------------------------------

    public function testPlanOfAPolicyASegmentAndAProfileIssuesGetsOnly(): void
    {
        $id = $this->server->seedSegment('hq', 'access', 'staff', 20, 1);
        $this->server->seedProfile($id, 3600);

        $plan = $this->plan($this->manifest());

        self::assertSame([], $this->server->writes(), 'plan must issue no write');
        $calls = $this->server->calls();
        self::assertContains('GET ' . self::POLICY, $calls);
        self::assertContains('GET ' . self::SEGMENTS, $calls);
        self::assertContains('GET ' . self::PROFILES, $calls);
        foreach ($calls as $call) {
            self::assertStringStartsWith('GET ', $call);
        }
        self::assertNotEmpty($plan->pending());
    }

    public function testTwoPlansAgainstUnchangedStateAreEqualAndInThePoliciesSegmentsProfilesOrder(): void
    {
        $first = $this->plan($this->manifest())->describe();
        $second = $this->plan($this->manifest())->describe();

        self::assertSame($first, $second);
        self::assertSame([
            'update network_policy:network',
            'create network_segment:guest',
            'create network_segment:staff',
            'create network_profile:staff',
        ], $first, 'policy, then segments, then profiles (§27.6.2 item 2)');
    }

    public function testThePolicyIsNeverACreate(): void
    {
        $plan = $this->plan($this->manifest(ManagementManifest::builder()->networkPolicy(3600)));
        self::assertSame([ChangeAction::Unchanged], array_map(static fn ($c) => $c->action, $plan->changes), 'the default cap is already 3600');

        $plan = $this->plan($this->manifest(ManagementManifest::builder()->networkPolicy(900)));
        self::assertSame([ChangeAction::Update], array_map(static fn ($c) => $c->action, $plan->changes));
    }

    // -- apply on an empty tenant, then plan: idempotence -------------------------------------

    public function testOnAnEmptyTenantApplyCreatesTheSegmentThenItsProfileWithTheCreateResponsesVersion(): void
    {
        $report = $this->apply($this->manifest());

        self::assertTrue($report->isComplete(), implode("\n", $report->describe()));
        $writes = $this->server->writes();
        self::assertSame([
            'PUT ' . self::POLICY,
            'POST ' . self::SEGMENTS,
            'POST ' . self::SEGMENTS,
            'POST ' . self::PROFILES,
        ], $writes, 'policy, segments, profile — and the profile after its segment');

        $staffId = $this->server->segmentId('hq', 'access', 'staff');
        self::assertNotNull($staffId);
        $profile = $this->server->bodies('POST', self::PROFILES)[0];
        self::assertSame($staffId, $profile['segment_id'], 'the new segment\'s id');
        self::assertSame($this->server->firstVersion, $profile['segment_version'], 'the version of the create response');
        self::assertEquals(
            ['session_timeout_secs' => 3600, 'idle_timeout_secs' => 600, 'filter_id' => 'staff-in'],
            $profile['profile'],
            'only the stated members, and no dictionary',
        );
        $segment = $this->server->bodies('POST', self::SEGMENTS)[1];
        self::assertSame('access', $segment['kind'], 'the wire spelling');
        self::assertSame(['staff-in', 'staff-out'], $segment['filter_ids']);

        // The policy was written first, so the profile's 3600 and the cap's 7200 never met.
        self::assertSame(['session_timeout_max_secs' => 7200, 'version' => 0], $this->server->bodies('PUT', self::POLICY)[0]);

        self::assertConverged($this->plan($this->manifest()));
    }

    public function testApplyThenPlanIsAllNoChangeWhateverIsStated(): void
    {
        $builder = ManagementManifest::builder()
            ->networkPolicy(7200)
            ->networkSegment('jail', 'hq', Models\NetworkSegmentKind::Quarantine, 'jail', 99, enabled: false)
            ->networkSegment('staff', 'hq', 'access', 'staff', 20, rank: 1, filterIds: ['b', 'a'], enabled: true)
            ->networkProfile('staff', 3600, Models\RadiusTerminationAction::Default, 600, 'a', Models\RadiusServiceType::FramedUser)
            ->networkProfile('jail', 300);
        $manifest = $builder->build();

        self::assertTrue($this->apply($manifest)->isComplete());
        self::assertConverged($this->plan($manifest));
        $writesBefore = $this->server->writes();
        self::assertTrue($this->apply($manifest)->isComplete());
        self::assertSame($writesBefore, $this->server->writes(), 'a second apply sends nothing');
    }

    // -- an Update is the full, version-conditional replacement ------------------------------

    public function testASegmentUpdateSendsTheFullReplacementBodyBuiltFromTheRead(): void
    {
        $id = $this->server->seedSegment('hq', 'access', 'staff', 20, 1, ['staff-in'], false);
        $manifest = ManagementManifest::builder()
            ->networkSegment('staff', 'hq', 'access', 'staff', 21) // states only the VLAN
            ->build();

        $report = $this->apply($manifest);

        self::assertTrue($report->isComplete(), implode("\n", $report->describe()));
        $put = $this->server->bodies('PUT', self::SEGMENTS . '/' . $id)[0];
        self::assertEqualsCanonicalizing(['enabled', 'filter_ids', 'rank', 'version', 'vlan_id'], array_keys($put), 'the exact key set: no kind, site_key or name');
        self::assertSame($this->server->firstVersion, $put['version'], 'the version plan read');
        self::assertSame(21, $put['vlan_id']);
        self::assertFalse($put['enabled'], 'unstated members are carried from the read, not reset');
        self::assertSame(['staff-in'], $put['filter_ids']);
        self::assertSame(1, $put['rank']);
    }

    public function testAProfileUpdateCarriesWhatItDoesNotStateAndAStatedNullLeavesTheKeyOut(): void
    {
        $id = $this->server->seedSegment('hq', 'access', 'staff', 20, 1, ['staff-in']);
        $this->server->seedProfile($id, 3600, [
            'idle_timeout_secs' => 600, 'filter_id' => 'staff-in', 'service_type' => 'framed_user',
            'termination_action' => 'default',
        ]);
        $manifest = ManagementManifest::builder()
            ->networkSegment('staff', 'hq', 'access', 'staff', 20, rank: 1, filterIds: ['staff-in'])
            ->networkProfile('staff', 1800, filterId: JsonNull::Null) // changes the timeout, clears the Filter-Id
            ->build();

        $plan = $this->plan($manifest);
        self::assertSame(['update network_profile:staff'], $plan->describe());
        $report = $this->apply($manifest);

        self::assertTrue($report->isComplete(), implode("\n", $report->describe()));
        $put = $this->server->bodies('PUT', self::PROFILES . '/' . $id)[0];
        self::assertEqualsCanonicalizing(['profile', 'segment_version', 'version'], array_keys($put));
        self::assertSame($this->server->firstVersion, $put['version'], 'the profile\'s own version as read');
        self::assertSame($this->server->firstVersion, $put['segment_version'], 'the segment was not written, so the read\'s');
        self::assertSame([
            'session_timeout_secs' => 1800,
            'dictionary' => 'axiam-radius-reply/1',
            'idle_timeout_secs' => 600,
            'service_type' => 'framed_user',
            'termination_action' => 'default',
        ], $put['profile'], 'the stated none is OUT of the body; the unstated members are carried, the dictionary included');
        self::assertArrayNotHasKey('filter_id', $put['profile']);

        self::assertConverged($this->plan($manifest));
    }

    public function testASegmentAndItsProfileChangedInOneApplyUseTheReplaceSegmentResponsesVersion(): void
    {
        $id = $this->server->seedSegment('hq', 'access', 'staff', 20, 1, ['staff-in']);
        $this->server->seedProfile($id, 3600, ['filter_id' => 'staff-in']);
        $manifest = ManagementManifest::builder()
            ->networkSegment('staff', 'hq', 'access', 'staff', 21, filterIds: ['staff-in'])
            ->networkProfile('staff', 1800)
            ->build();

        $report = $this->apply($manifest);

        self::assertTrue($report->isComplete(), implode("\n", $report->describe()));
        self::assertSame(['PUT ' . self::SEGMENTS . '/' . $id, 'PUT ' . self::PROFILES . '/' . $id], $this->server->writes());
        $replaced = $this->server->segments[$id]['version'];
        self::assertSame($this->server->firstVersion + 1, $replaced);
        $profile = $this->server->bodies('PUT', self::PROFILES . '/' . $id)[0];
        self::assertSame($replaced, $profile['segment_version'], 'the replace_segment response\'s version, not the one plan read');
        self::assertNotSame($this->server->firstVersion, $profile['segment_version']);
    }

    public function testAProfileOfAnExistingSegmentWithNoProfileIsACreateAgainstTheReadsVersion(): void
    {
        $id = $this->server->seedSegment('hq', 'access', 'staff', 20, 1);
        $manifest = ManagementManifest::builder()
            ->networkSegment('staff', 'hq', 'access', 'staff', 20, rank: 1)
            ->networkProfile('staff', 1800)
            ->build();

        self::assertSame(['create network_profile:staff'], $this->plan($manifest)->describe());
        self::assertTrue($this->apply($manifest)->isComplete());
        $body = $this->server->bodies('POST', self::PROFILES)[0];
        self::assertSame($id, $body['segment_id']);
        self::assertSame($this->server->firstVersion, $body['segment_version']);
    }

    // -- a 409 is the action's failure -------------------------------------------------------

    /**
     * @return iterable<string,array{0:string,1:string,2:string,3:string}> reason, error slug, method, path
     */
    public static function conflicts(): iterable
    {
        yield 'a stale version on the policy' => ['stale_version', 'conflict', 'PUT', self::POLICY];
        yield 'a stale version on a segment create' => ['stale_version', 'conflict', 'POST', self::SEGMENTS];
        yield 'a duplicate VLAN on a segment create' => ['duplicate_vlan', 'already_exists', 'POST', self::SEGMENTS];
        yield 'a code from the future' => ['a_code_from_2027', 'conflict', 'POST', self::SEGMENTS];
    }

    /** @dataProvider conflicts */
    public function testAConflictMakesOneRequestStopsTheApplyAndExposesItsReasonCode(
        string $reason,
        string $error,
        string $method,
        string $path,
    ): void {
        $this->server->failNext($method, '#^' . preg_quote($path, '#') . '$#', new Response(409, ['Content-Type' => 'application/json'], (string) json_encode([
            'error' => $error, 'message' => 'refused', 'reason_code' => $reason,
        ])));

        $report = $this->apply($this->manifest());

        self::assertFalse($report->isComplete());
        self::assertInstanceOf(ConflictError::class, $report->failure);
        self::assertSame($reason, $report->failureReasonCode());
        self::assertSame($reason, $report->failure->getReasonCode());
        $attempted = \count(array_keys($this->server->writes(), $method . ' ' . $path, true));
        self::assertSame(1, $attempted, 'exactly one request, never retried (retry is switched on)');
        // Nothing after the failed action was attempted.
        $last = $this->server->writes();
        self::assertSame($method . ' ' . $path, end($last), 'the failed request is the last write');
        if ($path === self::POLICY) {
            self::assertCount(1, $this->server->writes(), 'policy fails first; no segment is written');
        }
    }

    public function testAConflictOnTheFirstSegmentSkipsTheRestAndTheOutcomeNamesIt(): void
    {
        $this->server->failNext('POST', '#^' . preg_quote(self::SEGMENTS, '#') . '$#', new Response(409, ['Content-Type' => 'application/json'], (string) json_encode([
            'error' => 'already_exists', 'message' => 'VLAN taken', 'reason_code' => 'duplicate_vlan',
        ])));

        $report = $this->apply($this->manifest());

        self::assertSame('duplicate_vlan', $report->failureReasonCode());
        self::assertSame('create network_segment:guest', $report->failed?->describe());
        self::assertSame(
            ['create network_segment:staff', 'create network_profile:staff'],
            array_map(static fn ($c) => $c->describe(), $report->remaining),
        );
        self::assertSame(['update network_policy:network'], array_map(static fn ($c) => $c->describe(), $report->applied));
        self::assertNotContains('POST ' . self::PROFILES, $this->server->writes(), 'the profile was never attempted');
        self::assertCount(1, array_keys($this->server->writes(), 'POST ' . self::SEGMENTS, true), 'the second segment was never attempted');
    }

    // -- pruning -------------------------------------------------------------------------

    public function testNothingIsDeletedAndThePolicyHasNoDelete(): void
    {
        $this->server->seedSegment('hq', 'access', 'legacy', 10, 9);
        $stray = $this->server->seedSegment('hq', 'access', 'stray', 11, 8);
        $this->server->seedProfile($stray, 600);

        $plan = $this->plan($this->manifest());
        $report = $this->apply($this->manifest());

        self::assertTrue($report->isComplete());
        foreach ($this->server->writes() as $write) {
            self::assertStringStartsNotWith('DELETE ', $write, 'pruning is not offered, so omission is never deletion (§27.6 rule 4)');
        }
        self::assertSame([], array_filter(ChangeAction::cases(), static fn (ChangeAction $a): bool => $a->name === 'Delete'));
        self::assertNotNull($this->server->segmentId('hq', 'access', 'legacy'), 'a segment the manifest does not state is left alone');
        self::assertNotNull($this->server->segmentId('hq', 'access', 'stray'));
        self::assertArrayHasKey($stray, $this->server->profiles, 'and so is its profile');
        self::assertNotEmpty($plan->changes);
    }

    // -- refusals with zero wire calls ---------------------------------------------------

    public function testTwoSegmentsWithOneSiteKindAndNameAreRefusedWithZeroWireCalls(): void
    {
        $client = $this->client();
        $before = \count($this->server->requests);
        $builder = ManagementManifest::builder()
            ->networkSegment('a', 'hq', 'access', 'staff', 20, rank: 1)
            ->networkSegment('b', 'hq', 'access', 'staff', 21, rank: 2);

        try {
            $builder->build();
            self::fail('expected a ManifestException');
        } catch (ManifestException $e) {
            self::assertStringContainsString('hq / access / staff', $e->getMessage());
        }
        // Built by hand, bypassing the builder: plan() and apply() refuse it before any request.
        $manifest = new ManagementManifest([
            new ManifestEntity(ManifestKind::NetworkSegment, 'a', '["hq","access","staff"]', ['site_key' => 'hq', 'kind' => 'access', 'name' => 'staff', 'vlan_id' => 20]),
            new ManifestEntity(ManifestKind::NetworkSegment, 'b', '["hq","access","staff"]', ['site_key' => 'hq', 'kind' => 'access', 'name' => 'staff', 'vlan_id' => 21]),
        ]);
        foreach ([fn () => $client->management()->manifest()->plan($manifest), fn () => $client->management()->manifest()->apply($manifest)] as $call) {
            try {
                $call();
                self::fail('expected a ManifestException');
            } catch (ManifestException) {
                $this->addToAssertionCount(1);
            }
        }
        self::assertCount($before, $this->server->requests, 'zero wire calls');
    }

    public function testAProfileWhoseSegmentIsNotInTheManifestIsDanglingAndRefusedWithZeroWireCalls(): void
    {
        $client = $this->client();
        $before = \count($this->server->requests);
        $builder = ManagementManifest::builder()
            ->networkSegment('staff', 'hq', 'access', 'staff', 20, rank: 1)
            ->networkProfile('guest', 600);

        try {
            $builder->build();
            self::fail('expected a ManifestException');
        } catch (ManifestException $e) {
            self::assertStringContainsString('"guest"', $e->getMessage());
        }
        $manifest = new ManagementManifest([
            new ManifestEntity(ManifestKind::NetworkProfile, 'guest', 'guest', ['session_timeout_secs' => 600], segment: 'guest'),
        ]);
        try {
            $client->management()->manifest()->plan($manifest);
            self::fail('expected a ManifestException');
        } catch (ManifestException) {
            $this->addToAssertionCount(1);
        }
        self::assertCount($before, $this->server->requests, 'zero wire calls');
    }

    public function testTwoPoliciesAndTwoProfilesForOneSegmentAreRefusedWithZeroWireCalls(): void
    {
        $before = \count($this->server->requests);
        foreach ([
            fn () => ManagementManifest::builder()->networkPolicy(600)->networkPolicy(900)->build(),
            fn () => ManagementManifest::builder()
                ->networkSegment('staff', 'hq', 'access', 'staff', 20, rank: 1)
                ->networkProfile('staff', 600)->networkProfile('staff', 900)->build(),
        ] as $build) {
            try {
                $build();
                self::fail('expected a ManifestException');
            } catch (ManifestException) {
                $this->addToAssertionCount(1);
            }
        }
        self::assertCount($before, $this->server->requests);
    }

    public function testAKindThatIsNotTheWireSpellingIsRefusedAndNoZonesValueExistsAnywhere(): void
    {
        foreach (['zones', 'Access', 'transit', ''] as $kind) {
            try {
                ManagementManifest::builder()->networkSegment('s', 'hq', $kind, 'staff', 20);
                self::fail("expected a ManifestException for '$kind'");
            } catch (ManifestException $e) {
                self::assertStringContainsString('the wire spelling', $e->getMessage());
            }
        }
        $unknown = Models\NetworkSegmentKind::Unknown;
        $this->expectException(ManifestException::class);
        ManagementManifest::builder()->networkSegment('s', 'hq', $unknown, 'staff', 20);
    }

    public function testASegmentStatedAsAccessIsNoChangeAgainstARead_AndItsCreateBodyCarriesTheString(): void
    {
        $this->server->seedSegment('hq', 'access', 'staff', 20, 1);
        $manifest = ManagementManifest::builder()
            ->networkSegment('staff', 'hq', 'access', 'staff', 20, rank: 1)
            ->build();
        self::assertConverged($this->plan($manifest));

        $created = ManagementManifest::builder()->networkSegment('lab', 'hq', 'access', 'lab', 50, rank: 5)->build();
        self::assertTrue($this->apply($created)->isComplete());
        $body = $this->server->bodies('POST', self::SEGMENTS)[0];
        self::assertSame('access', $body['kind']);
        foreach ($this->server->requests as $request) {
            self::assertStringNotContainsString('zones', (string) $request->getBody(), 'no zones spelling in anything the SDK sends');
            self::assertStringNotContainsString('zones', $request->getUri()->getQuery());
        }
    }

    // -- filter_ids is a set -------------------------------------------------------------------

    public function testFilterIdsInAnotherOrderAreNoChangeAndApplyMakesNoWriteForThem(): void
    {
        $this->server->seedSegment('hq', 'access', 'staff', 20, 1, ['b', 'a']);
        $manifest = ManagementManifest::builder()
            ->networkSegment('staff', 'hq', 'access', 'staff', 20, rank: 1, filterIds: ['a', 'b'])
            ->build();

        self::assertConverged($this->plan($manifest));
        self::assertTrue($this->apply($manifest)->isComplete());
        self::assertSame([], $this->server->writes());
    }

    public function testAnUpdateForAnotherMemberAndACreateSendFilterIdsInTheOrderTheManifestStates(): void
    {
        $id = $this->server->seedSegment('hq', 'access', 'staff', 20, 1, ['b', 'a']);
        $manifest = ManagementManifest::builder()
            ->networkSegment('staff', 'hq', 'access', 'staff', 21, rank: 1, filterIds: ['c', 'a', 'b'])
            ->networkSegment('lab', 'hq', 'access', 'lab', 50, rank: 5, filterIds: ['z', 'y', 'x'])
            ->build();

        self::assertTrue($this->apply($manifest)->isComplete());
        self::assertSame(['c', 'a', 'b'], $this->server->bodies('PUT', self::SEGMENTS . '/' . $id)[0]['filter_ids']);
        self::assertSame(['z', 'y', 'x'], $this->server->bodies('POST', self::SEGMENTS)[0]['filter_ids']);
        self::assertConverged($this->plan($manifest));
    }

    public function testASegmentWhoseFilterIdsRepeatANameIsRefusedAtPlanAndApplyWithZeroWireCalls(): void
    {
        $client = $this->client();
        $before = \count($this->server->requests);
        try {
            ManagementManifest::builder()
                ->networkSegment('staff', 'hq', 'access', 'staff', 20, rank: 1, filterIds: ['a', 'b', 'a'])
                ->build();
            self::fail('expected a ManifestException');
        } catch (ManifestException $e) {
            self::assertStringContainsString('more than once', $e->getMessage());
        }
        $manifest = new ManagementManifest([
            new ManifestEntity(
                ManifestKind::NetworkSegment,
                'staff',
                '["hq","access","staff"]',
                ['site_key' => 'hq', 'kind' => 'access', 'name' => 'staff', 'vlan_id' => 20, 'filter_ids' => ['a', 'b', 'a']],
                setFields: ['filter_ids'],
            ),
        ]);
        foreach ([fn () => $client->management()->manifest()->plan($manifest), fn () => $client->management()->manifest()->apply($manifest)] as $call) {
            try {
                $call();
                self::fail('expected a ManifestException');
            } catch (ManifestException) {
                $this->addToAssertionCount(1);
            }
        }
        self::assertCount($before, $this->server->requests, 'zero wire calls');
    }

    // -- judged on the read ----------------------------------------------------------------

    public function testAClampedProfileStatingTheCapIsNoChangeAndOneStatingMoreIsAnUpdateInPlan(): void
    {
        $id = $this->server->seedSegment('hq', 'access', 'staff', 20, 1);
        $this->server->seedProfile($id, 7200); // stored above the cap of 3600: reads as 3600, clamped

        $read = $this->server->readProfile($id);
        self::assertTrue($read['session_timeout_clamped']);
        self::assertSame(3600, $read['session_timeout_secs']);

        // Stating the cap: NoChange. The stored 7200 is neither restored nor rewritten.
        $atCap = ManagementManifest::builder()
            ->networkSegment('staff', 'hq', 'access', 'staff', 20, rank: 1)
            ->networkProfile('staff', 3600)
            ->build();
        self::assertConverged($this->plan($atCap));
        self::assertTrue($this->apply($atCap)->isComplete());
        self::assertSame([], $this->server->writes());
        self::assertSame(7200, $this->server->profiles[$id]['session_timeout_secs']);

        // Stating more than the cap: the value differs from the read, so plan shows an Update.
        $above = ManagementManifest::builder()
            ->networkSegment('staff', 'hq', 'access', 'staff', 20, rank: 1)
            ->networkProfile('staff', 5400)
            ->build();
        self::assertSame(['update network_profile:staff'], $this->plan($above)->describe());
    }

    public function testTheOneThatIsAboveTheCapIsRefusedWith403AndNothingFollowsIt(): void
    {
        $first = $this->server->seedSegment('hq', 'access', 'a', 20, 1);
        $this->server->seedProfile($first, 7200);
        $second = $this->server->seedSegment('hq', 'access', 'b', 30, 2);
        $this->server->seedProfile($second, 600);
        $manifest = ManagementManifest::builder()
            ->networkSegment('a', 'hq', 'access', 'a', 20, rank: 1)
            ->networkSegment('b', 'hq', 'access', 'b', 30, rank: 2)
            ->networkProfile('a', 5400)  // above the cap of 3600: refused
            ->networkProfile('b', 300)   // would be fine, but must not be attempted
            ->build();

        self::assertSame(['update network_profile:a', 'update network_profile:b'], $this->plan($manifest)->describe());
        $this->server->requests = [];
        $report = $this->apply($manifest, $this->client(retry: true));

        self::assertFalse($report->isComplete());
        $failure = $report->failure;
        self::assertInstanceOf(AuthzError::class, $failure);
        self::assertNotInstanceOf(ConflictError::class, $failure);
        self::assertStringContainsString("session_timeout_secs is above the tenant's cap of 3600", $failure->getMessage(), 'the outcome carries the server\'s message');
        self::assertNull($failure->getAction());
        self::assertSame(['PUT ' . self::PROFILES . '/' . $first], $this->server->writes(), 'exactly one replace_profile, no retry, nothing after it');
        self::assertSame(['update network_profile:b'], array_map(static fn ($c) => $c->describe(), $report->remaining));
        self::assertSame(600, $this->server->profiles[$second]['session_timeout_secs']);
    }

    public function testARaisedCapAndAProfileAboveTheOldOneWorkBecauseThePolicyIsWrittenFirst(): void
    {
        $id = $this->server->seedSegment('hq', 'access', 'staff', 20, 1);
        $this->server->seedProfile($id, 600);
        $manifest = ManagementManifest::builder()
            ->networkProfile('staff', 5400)
            ->networkSegment('staff', 'hq', 'access', 'staff', 20, rank: 1)
            ->networkPolicy(7200)
            ->build();

        $report = $this->apply($manifest);

        self::assertTrue($report->isComplete(), implode("\n", $report->describe()));
        self::assertSame(['PUT ' . self::POLICY, 'PUT ' . self::PROFILES . '/' . $id], $this->server->writes());
        self::assertConverged($this->plan($manifest));
    }

    public function testAMemberStatedAsNoneClearsItAndThenPlansNoChange(): void
    {
        $id = $this->server->seedSegment('hq', 'access', 'staff', 20, 1);
        $this->server->seedProfile($id, 1800, ['idle_timeout_secs' => 300, 'service_type' => 'framed_user']);
        $manifest = ManagementManifest::builder()
            ->networkSegment('staff', 'hq', 'access', 'staff', 20, rank: 1)
            ->networkProfile('staff', 1800, idleTimeoutSecs: JsonNull::Null, serviceType: JsonNull::Null)
            ->build();

        self::assertSame(['update network_profile:staff'], $this->plan($manifest)->describe());
        self::assertTrue($this->apply($manifest)->isComplete());
        $profile = $this->server->bodies('PUT', self::PROFILES . '/' . $id)[0]['profile'];
        self::assertArrayNotHasKey('idle_timeout_secs', $profile);
        self::assertArrayNotHasKey('service_type', $profile);
        self::assertConverged($this->plan($manifest));
    }

    // -- a manifest without a network section plans exactly as it did --------------------------

    public function testAManifestWithoutANetworkSectionTouchesNoNetworkRoute(): void
    {
        $manifest = ManagementManifest::builder()
            ->permission('read', 'documents:read', 'Read documents')
            ->build();
        $this->server->failNext('GET', '#/permissions$#', new Response(200, ['Content-Type' => 'application/json'], (string) json_encode(['items' => [], 'total' => 0, 'offset' => 0, 'limit' => 50])));

        try {
            $this->plan($manifest);
        } catch (\Throwable) {
            // The fake knows no permissions route; what matters is where the SDK looked.
        }
        foreach ($this->server->calls() as $call) {
            self::assertStringNotContainsString('/network/', $call);
        }
    }
}
