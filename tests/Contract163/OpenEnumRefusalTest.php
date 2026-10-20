<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract163;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Management\Manifest\ManagementManifest;
use Axiam\Sdk\Management\Models;
use Axiam\Sdk\Management\ValidationError;
use Axiam\Sdk\Tests\Contract162\FakeNetworkServer;
use PHPUnit\Framework\TestCase;

/**
 * Contract 1.63 follow-ups to the 1.62 review (issue #84): an open-enum value this SDK has no
 * name for is never sent (C162-04, §34.2 P12.2(a)), and `plan` refuses to carry one it did not
 * read for a member the manifest leaves unstated (C162-07, §27.6.2 item 4).
 */
final class OpenEnumRefusalTest extends TestCase
{
    private FakeNetworkServer $server;

    protected function setUp(): void
    {
        $this->server = new FakeNetworkServer();
    }

    private function client(): AxiamClient
    {
        $client = new AxiamClient(
            'https://iam.example.test',
            'acme',
            orgId: '11111111-1111-4111-8111-111111111111',
            oidcTenantId: FakeNetworkServer::TENANT_ID,
            transportHandler: $this->server,
        );
        $client->login('admin@example.test', bin2hex(random_bytes(8)));

        return $client;
    }

    /** @return iterable<string,array{class-string<\BackedEnum>}> */
    public static function openEnums(): iterable
    {
        foreach (glob(__DIR__ . '/../../src/Management/Models/*.php') ?: [] as $file) {
            $class = 'Axiam\\Sdk\\Management\\Models\\' . basename($file, '.php');
            if (enum_exists($class) && \defined($class . '::Unknown')) {
                yield $class => [$class];
            }
        }
    }

    /**
     * @param class-string<\BackedEnum> $enum
     *
     * @dataProvider openEnums
     */
    public function testEveryOpenEnumRefusesToEncodeItsUnknownCase(string $enum): void
    {
        $unknown = $enum::fromWire('a_value_from_2027'); // @phpstan-ignore-line
        self::assertSame($enum::Unknown, $unknown); // @phpstan-ignore-line
        $this->expectException(ValidationError::class);
        $unknown->toWire(); // @phpstan-ignore-line
    }

    public function testARequestModelHoldingUnknownRefusesToEncodeButStillRendersForALog(): void
    {
        $body = new Models\ReplaceNetworkReplyProfileRequest(
            profile: new Models\NetworkReplyProfileInput(
                sessionTimeoutSecs: 3600,
                terminationAction: Models\RadiusTerminationAction::Unknown,
            ),
            segmentVersion: 1,
            version: 1,
        );

        self::assertSame('', $body->jsonSerialize()['profile']['termination_action'] ?? null);
        $this->expectException(ValidationError::class);
        $body->toArray();
    }

    public function testSendingAnUnknownThroughTheApiMakesZeroRequests(): void
    {
        $client = $this->client();
        $before = \count($this->server->calls());

        try {
            $client->management()->network()->replaceProfile('33333333-3333-4333-8333-333333333333', new Models\ReplaceNetworkReplyProfileRequest(
                profile: new Models\NetworkReplyProfileInput(
                    sessionTimeoutSecs: 3600,
                    serviceType: Models\RadiusServiceType::Unknown,
                ),
                segmentVersion: 1,
                version: 1,
            ));
            self::fail('an unknown open-enum value must be refused locally');
        } catch (ValidationError $e) {
            self::assertStringContainsString('RadiusServiceType', $e->getMessage());
        }

        self::assertCount($before, $this->server->calls(), 'no request was made');
    }

    // -- C162-07 -------------------------------------------------------------------------

    private function seedFuture(): void
    {
        $id = $this->server->seedSegment('hq', 'access', 'staff', 20, 1);
        $this->server->seedProfile($id, 3600, ['termination_action' => 'future']);
    }

    private function segmentOnly(): \Axiam\Sdk\Management\Manifest\ManifestBuilder
    {
        return ManagementManifest::builder()
            ->networkSegment('staff', 'hq', 'access', 'staff', 20, rank: 1);
    }

    public function testPlanRefusesAnUnknownOnAnUnstatedMemberWithNoWrite(): void
    {
        $this->seedFuture();
        $manifest = $this->segmentOnly()->networkProfile('staff', 1800)->build(); // changes another member

        try {
            $this->client()->management()->manifest()->plan($manifest);
            self::fail('plan must refuse');
        } catch (ValidationError $e) {
            self::assertStringContainsString('termination_action', $e->getMessage());
        }

        self::assertSame([], $this->server->writes(), 'plan sends no write, and so no PUT');
    }

    public function testApplyRefusesTheSameWayBeforeAnyWrite(): void
    {
        $this->seedFuture();
        $manifest = $this->segmentOnly()->networkProfile('staff', 1800)->build();

        try {
            $this->client()->management()->manifest()->apply($manifest);
            self::fail('apply plans first and must refuse');
        } catch (ValidationError) {
        }

        self::assertSame([], $this->server->writes());
    }

    public function testAManifestThatStatesTheMemberResolvesItAndTheBodyNeverCarriesTheUnknown(): void
    {
        $this->seedFuture();
        $manifest = $this->segmentOnly()
            ->networkProfile('staff', 1800, Models\RadiusTerminationAction::Default)
            ->build();

        $report = $this->client()->management()->manifest()->apply($manifest);

        self::assertTrue($report->isComplete(), implode("\n", $report->describe()));
        $put = $this->server->writes();
        self::assertCount(1, $put);
        $segmentId = $this->server->segmentId('hq', 'access', 'staff');
        $body = $this->server->bodies('PUT', '/api/v1/network/profiles/' . $segmentId)[0];
        self::assertSame('default', $body['profile']['termination_action']);
    }

    public function testAProfileThatDiffersInNothingIsNoChangeEvenWithAnUnknownMember(): void
    {
        $this->seedFuture();
        $plan = $this->client()->management()->manifest()->plan(
            $this->segmentOnly()->networkProfile('staff', 3600)->build(),
        );

        self::assertSame([], $plan->describe());
        self::assertSame([], $this->server->writes());
    }
}
