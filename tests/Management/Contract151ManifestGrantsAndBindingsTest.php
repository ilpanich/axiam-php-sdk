<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Management;

use Axiam\Sdk\Management\Manifest\ChangeAction;
use Axiam\Sdk\Management\Manifest\ManagementManifest;

/**
 * §13 row 17 defect (a): PHP stored role grants and group role keys in the manifest but
 * never granted or assigned anything — `applyRole()`'s own docblock claimed it
 * "reconciles its permission grants" while doing nothing of the kind.
 *
 * `apply()` now reconciles both, ADDITIVELY (never revoking/unassigning something the
 * manifest simply does not mention — §27.6 rule 4's "omission is never deletion",
 * applied to edges): for every role the manifest grants at least one permission to, and
 * every group the manifest assigns at least one role to, whether or not that role/group
 * itself needed its own Create or Update.
 */
final class Contract151ManifestGrantsAndBindingsTest extends ManagementTestCase
{
    private const PERMISSION_ID = '11111111-1111-4111-8111-111111111111';
    private const ROLE_ID = '22222222-2222-4222-8222-222222222222';
    private const GROUP_ID = '33333333-3333-4333-8333-333333333333';

    /** @return array<string,mixed> */
    private static function permissionRow(string $action, string $id = self::PERMISSION_ID): array
    {
        return [
            'action' => $action,
            'created_at' => '2026-08-26T00:00:00Z',
            'description' => 'Read documents',
            'id' => $id,
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    /** @return array<string,mixed> */
    private static function roleRow(string $name, string $id = self::ROLE_ID): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'description' => 'Read-only',
            'id' => $id,
            'is_global' => false,
            'name' => $name,
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    /** @return array<string,mixed> */
    private static function groupRow(string $name, string $id = self::GROUP_ID): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'description' => 'Engineering',
            'id' => $id,
            'metadata' => [],
            'name' => $name,
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    private static function manifestWithGrantsAndBindings(): ManagementManifest
    {
        return ManagementManifest::builder()
            ->permission('read', 'documents:read', 'Read documents')
            ->role('auditor', 'auditor', 'Read-only', grants: ['read' => 'allow'])
            ->group('engineers', 'engineers', 'Engineering', roleKeys: ['auditor'])
            ->build();
    }

    /**
     * The first apply(): everything is created, AND the grant + the binding actually
     * reach the wire — the defect this test exists for is that they never did.
     */
    public function testFirstApplyGrantsThePermissionAndBindsTheRole(): void
    {
        $client = $this->signedInWith(
            self::page([], 0), // permissions
            self::page([], 0), // roles
            self::page([], 0), // groups
            self::json(200, self::permissionRow('documents:read')), // create permission
            self::json(200, self::roleRow('auditor')), // create role
            self::json(200, self::groupRow('engineers')), // create group
            self::json(200, []), // reconcile: roles()->listPermissions(ROLE_ID) -> none yet (bare array, not a Page)
            new \GuzzleHttp\Psr7\Response(204), // grantPermission
            self::json(200, []), // reconcile: groups()->listRoles(GROUP_ID) -> none yet (bare array, not a Page)
            new \GuzzleHttp\Psr7\Response(204), // assignToGroup
        );

        $report = $client->management()->manifest()->apply(self::manifestWithGrantsAndBindings());

        self::assertTrue($report->isComplete(), $report->failure?->getMessage() ?? '');
        // 3 entity creates + 2 edge reconciliations (grant, bind) = 5 applied changes.
        self::assertCount(5, $report->applied);

        // login(0), perm-list(1), role-list(2), group-list(3), create x3(4-6),
        // listPermissions(7), grantPermission(8), listRoles(9), assignToGroup(10).
        $grantRequest = $this->requests[8];
        self::assertStringContainsString('/roles/' . self::ROLE_ID . '/permissions', (string) $grantRequest->getUri());
        $grantBody = json_decode((string) $grantRequest->getBody(), true);
        self::assertSame(self::PERMISSION_ID, $grantBody['permission_id']);

        $assignRequest = $this->requests[10];
        self::assertStringContainsString('/roles/' . self::ROLE_ID . '/groups', (string) $assignRequest->getUri());
        $assignBody = json_decode((string) $assignRequest->getBody(), true);
        self::assertSame(self::GROUP_ID, $assignBody['group_id']);
    }

    /**
     * Idempotence: a SECOND apply() against a tenant that already has the grant/binding
     * sends NO grant/assign call — reconciliation reads current state first and only
     * adds what is missing.
     *
     * `roles()->listPermissions()` and `groups()->listRoles()` are bare-array reads
     * (§27.4 rule 4), never `Page`s, so their fixtures here are plain JSON arrays —
     * `self::json(200, [...])`, not `self::page(...)`.
     */
    public function testASecondApplyGrantsNothingAlreadyPresent(): void
    {
        $manifest = self::manifestWithGrantsAndBindings();

        $client = $this->signedInWith(
            // Everything already exists, matching the manifest exactly.
            self::page([self::permissionRow('documents:read')], 1),
            self::page([self::roleRow('auditor')], 1),
            self::page([self::groupRow('engineers')], 1),
            // Reconciliation reads: the grant and the binding are ALREADY present.
            self::json(200, [[
                'effect' => 'allow',
                'permission' => self::permissionRow('documents:read'),
                'scope_ids' => [],
                'scopes' => [],
            ]]),
            self::json(200, [[
                'role' => self::roleRow('auditor'),
                'resource_id' => null,
            ]]),
        );

        $report = $client->management()->manifest()->apply($manifest);

        self::assertTrue($report->isComplete(), $report->failure?->getMessage() ?? '');
        self::assertSame(
            [],
            $report->applied,
            'nothing to create/update AND nothing to grant/assign -- both already match',
        );
        // login + 3 entity reads + 2 reconciliation reads = 6 requests, zero writes.
        foreach ($this->sentMethods() as $method) {
            self::assertSame('GET', $method, 'a fully converged apply() must issue reads only');
        }
    }

    /**
     * The manifest attribute reader wires grants/roleKeys through the SAME builder
     * this whole file exercises, so its own round trip needs no separate reconciliation
     * test — {@see \Axiam\Sdk\Tests\Management\ManagementManifestTest::testAManifestCanBeDeclaredWithAttributes()}
     * already pins that `#[ManagedRole(grants: …)]` / `#[ManagedGroup(roleKeys: …)]`
     * produce the identical `ManifestEntity` this test's builder-built manifest does.
     */
    public function testPlanStillTreatsGrantsAndRolesAsEdgesNotFieldDrift(): void
    {
        $client = $this->signedInWith(
            self::page([self::permissionRow('documents:read')], 1),
            self::page([self::roleRow('auditor')], 1),
        );

        $plan = $client->management()->manifest()->plan(
            ManagementManifest::builder()
                ->permission('read', 'documents:read', 'Read documents')
                ->role('auditor', 'auditor', 'Read-only', grants: ['read' => 'allow'])
                ->build(),
        );

        self::assertTrue($plan->isConverged(), 'grants must not surface as field drift on the role itself');
        foreach ($plan->changes as $change) {
            self::assertSame(ChangeAction::Unchanged, $change->action);
        }
    }
}
