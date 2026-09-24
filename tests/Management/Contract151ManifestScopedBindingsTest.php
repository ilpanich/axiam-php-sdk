<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Management;

use Axiam\Sdk\Management\Manifest\BindingRebindFailed;
use Axiam\Sdk\Management\Manifest\ManagementManifest;
use Axiam\Sdk\Management\Manifest\ManifestException;
use Axiam\Sdk\Management\Manifest\RoleBinding;
use GuzzleHttp\Psr7\Response;
use Psr\Http\Message\RequestInterface;

/**
 * CONTRACT.md §27.6.1 addition 2 (contract 1.51): the resource-scoped role binding shape,
 * `{role, resource, inherit}`, on group and service-account bindings.
 *
 * Orchestrator review finding on C-6: this addition was declined — wrongly, per §8 rule 7
 * and §6's own "full" scope for this port — and is implemented here to match the
 * reference (`axiam-rust-sdk` `tests/manifest_additions_test.rs`).
 */
final class Contract151ManifestScopedBindingsTest extends ManagementTestCase
{
    private const ROLE_ID = '22222222-2222-4222-8222-222222222222';
    private const GLOBAL_ROLE_ID = '99999999-9999-4999-8999-999999999999';
    private const GROUP_ID = '33333333-3333-4333-8333-333333333333';
    private const SA_ID = '44444444-4444-4444-8444-444444444444';
    private const FOLDER_ID = '55555555-5555-4555-8555-555555555555';
    private const TENANT_SCOPE_TENANT = '66666666-6666-4666-8666-666666666666';

    /** @return array<string,mixed> */
    private static function roleRow(string $name, string $id = self::ROLE_ID, bool $isGlobal = false): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'description' => 'Editor role',
            'id' => $id,
            'is_global' => $isGlobal,
            'name' => $name,
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    /** @return array<string,mixed> */
    private static function resourceRow(string $name, string $id = self::FOLDER_ID): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'id' => $id,
            'metadata' => [],
            'name' => $name,
            'parent_id' => null,
            'resource_type' => 'folder_type',
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    /** @return array<string,mixed> */
    private static function groupRow(string $name, string $id = self::GROUP_ID): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'description' => 'desc',
            'id' => $id,
            'metadata' => [],
            'name' => $name,
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    /** @return array<string,mixed> */
    private static function serviceAccountRow(string $name, string $id = self::SA_ID): array
    {
        return [
            'client_id' => 'client-' . $id,
            'created_at' => '2026-08-26T00:00:00Z',
            'id' => $id,
            'name' => $name,
            'status' => 'Active',
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    /**
     * A `RoleAssignment` row, as returned by `groups()->listRoles()` /
     * `serviceAccounts()->listRoles()` — a BARE array (§27.4 rule 4), never a `Page`.
     *
     * @param array<string,mixed> $role
     * @param list<string>|null $tenantScope
     * @return array<string,mixed>
     */
    private static function assignmentRow(
        array $role,
        ?bool $inherit = null,
        ?string $resourceId = null,
        ?array $tenantScope = null,
    ): array {
        $row = ['role' => $role];
        if ($inherit !== null) {
            $row['inherit'] = $inherit;
        }
        if ($resourceId !== null) {
            $row['resource_id'] = $resourceId;
        }
        if ($tenantScope !== null) {
            $row['tenant_scope'] = $tenantScope;
        }

        return $row;
    }

    private static function scopedGroupManifest(RoleBinding|string $binding): ManagementManifest
    {
        return ManagementManifest::builder()
            ->resource('folder', 'Folder', 'folder_type')
            ->role('editor', 'editor', 'Editor role')
            ->group('eng', 'Engineering', 'desc', roleKeys: [$binding])
            ->build();
    }

    private function requestsFor(string $method, string $uriContains): int
    {
        return \count(array_filter(
            $this->requests,
            static fn (RequestInterface $r): bool => $r->getMethod() === $method
                && str_contains((string) $r->getUri(), $uriContains),
        ));
    }

    // -- inherit reaches the wire only as false ------------------------------

    /**
     * I4 twin of {@see self::testAtOnlyBindingSendsInheritFalseOnTheWire()}: the DEFAULT
     * (reaching descendants) never puts `inherit` on the wire at all — an inheritable
     * binding's body stays byte-for-byte what it was before contract 1.51.
     */
    public function testDefaultInheritScopedBindingOmitsTheFlagFromTheWire(): void
    {
        $client = $this->signedInWith(
            self::page([self::resourceRow('Folder')], 1),
            self::page([self::roleRow('editor')], 1),
            self::page([self::groupRow('Engineering')], 1),
            self::json(200, []), // groups()->listRoles: nothing bound yet
            new Response(204),   // assign
        );

        $report = $client->management()->manifest()->apply(
            self::scopedGroupManifest(RoleBinding::at('editor', 'folder')),
        );

        self::assertTrue($report->isComplete(), $report->failure?->getMessage() ?? '');
        $assignRequest = $this->lastRequest();
        $body = json_decode((string) $assignRequest->getBody(), true);
        self::assertArrayNotHasKey('inherit', $body, 'inherit:true must never reach the wire explicitly');
        self::assertSame(self::FOLDER_ID, $body['resource_id']);
    }

    /** §27.6.1 addition 2: `inherit: false` DOES reach the wire — "here and no further". */
    public function testAtOnlyBindingSendsInheritFalseOnTheWire(): void
    {
        $client = $this->signedInWith(
            self::page([self::resourceRow('Folder')], 1),
            self::page([self::roleRow('editor')], 1),
            self::page([self::groupRow('Engineering')], 1),
            self::json(200, []),
            new Response(204),
        );

        $report = $client->management()->manifest()->apply(
            self::scopedGroupManifest(RoleBinding::atOnly('editor', 'folder')),
        );

        self::assertTrue($report->isComplete(), $report->failure?->getMessage() ?? '');
        $body = json_decode((string) $this->lastRequest()->getBody(), true);
        self::assertFalse($body['inherit'] ?? null, 'atOnly() must send inherit: false explicitly');
    }

    // -- a changed binding is unassign then assign, tenant_scope carried across ----

    public function testChangedBindingIsUnassignThenAssignAndKeepsTenantScope(): void
    {
        $client = $this->signedInWith(
            self::page([self::resourceRow('Folder')], 1),
            self::page([self::roleRow('editor')], 1),
            self::page([self::groupRow('Engineering')], 1),
            // Currently bound PLAIN (no resource), with a tenant_scope the manifest never states.
            self::json(200, [
                self::assignmentRow(self::roleRow('editor'), tenantScope: [self::TENANT_SCOPE_TENANT]),
            ]),
            new Response(204), // unassign
            new Response(204), // assign
        );

        $report = $client->management()->manifest()->apply(
            self::scopedGroupManifest(RoleBinding::at('editor', 'folder')),
        );

        self::assertTrue($report->isComplete(), $report->failure?->getMessage() ?? '');
        self::assertCount(1, $report->applied);

        self::assertSame(1, $this->requestsFor('DELETE', '/roles/' . self::ROLE_ID . '/groups/' . self::GROUP_ID));
        self::assertSame(1, $this->requestsFor('POST', '/roles/' . self::ROLE_ID . '/groups'));

        // The unassign must precede the assign.
        $deleteIndex = null;
        $postIndex = null;
        foreach ($this->requests as $i => $r) {
            if ($r->getMethod() === 'DELETE' && str_contains((string) $r->getUri(), '/groups/' . self::GROUP_ID)) {
                $deleteIndex = $i;
            }
            if ($r->getMethod() === 'POST' && str_contains((string) $r->getUri(), '/roles/' . self::ROLE_ID . '/groups')) {
                $postIndex = $i;
            }
        }
        self::assertNotNull($deleteIndex);
        self::assertNotNull($postIndex);
        self::assertLessThan($postIndex, $deleteIndex, 'unassign must run before assign');

        $assignBody = json_decode((string) $this->lastRequest()->getBody(), true);
        self::assertSame(self::FOLDER_ID, $assignBody['resource_id']);
        self::assertSame(
            [self::TENANT_SCOPE_TENANT],
            $assignBody['tenant_scope'] ?? null,
            'the server assignment\'s tenant_scope must be carried across the rebind unchanged',
        );
    }

    /**
     * I4 twin: when the existing assignment ALREADY matches the declared resource and
     * inherit exactly, nothing is sent — not even a re-assign.
     */
    public function testUnchangedScopedBindingSendsNoWireCallAtAll(): void
    {
        $client = $this->signedInWith(
            self::page([self::resourceRow('Folder')], 1),
            self::page([self::roleRow('editor')], 1),
            self::page([self::groupRow('Engineering')], 1),
            self::json(200, [
                self::assignmentRow(self::roleRow('editor'), inherit: true, resourceId: self::FOLDER_ID),
            ]),
        );

        $report = $client->management()->manifest()->apply(
            self::scopedGroupManifest(RoleBinding::at('editor', 'folder')),
        );

        self::assertTrue($report->isComplete(), $report->failure?->getMessage() ?? '');
        self::assertSame([], $report->applied, 'an already-converged binding is never re-sent');
        foreach ($this->sentMethods() as $method) {
            self::assertSame('GET', $method, 'a fully converged apply() must issue reads only');
        }
    }

    /** A plain binding over a SCOPED server assignment is an Update (§27.6.1 addition 2). */
    public function testAPlainBindingOverAScopedServerAssignmentIsAnUpdate(): void
    {
        $client = $this->signedInWith(
            self::page([self::resourceRow('Folder')], 1),
            self::page([self::roleRow('editor')], 1),
            self::page([self::groupRow('Engineering')], 1),
            self::json(200, [
                self::assignmentRow(self::roleRow('editor'), inherit: true, resourceId: self::FOLDER_ID),
            ]),
            new Response(204), // unassign (at the OLD resource)
            new Response(204), // assign (plain — no resource)
        );

        $report = $client->management()->manifest()->apply(
            self::scopedGroupManifest(RoleBinding::role('editor')),
        );

        self::assertTrue($report->isComplete(), $report->failure?->getMessage() ?? '');
        self::assertCount(1, $report->applied);

        $unassignRequests = array_values(array_filter(
            $this->requests,
            static fn (RequestInterface $r): bool => $r->getMethod() === 'DELETE',
        ));
        self::assertCount(1, $unassignRequests);
        self::assertStringContainsString('resource_id=' . self::FOLDER_ID, (string) $unassignRequests[0]->getUri());

        $assignBody = json_decode((string) $this->lastRequest()->getBody(), true);
        self::assertArrayNotHasKey('resource_id', $assignBody, 'the plain binding names no resource');
    }

    // -- a failed reassignment restores the previous binding -----------------

    /**
     * When the new assignment fails, `apply()` puts the previous one back and the report
     * carries BOTH outcomes (C-12 question 7): the failure, and that the restore
     * succeeded.
     */
    public function testFailedReassignmentRestoresThePreviousBindingAndReportsBothOutcomes(): void
    {
        $client = $this->signedInWith(
            self::page([self::resourceRow('Folder')], 1),
            self::page([self::roleRow('editor')], 1),
            self::page([self::groupRow('Engineering')], 1),
            self::json(200, [self::assignmentRow(self::roleRow('editor'))]), // plain, existing
            new Response(204), // unassign
            new Response(400), // assign the NEW binding -> refused
            new Response(204), // restore the PREVIOUS binding -> succeeds
        );

        $report = $client->management()->manifest()->apply(
            self::scopedGroupManifest(RoleBinding::at('editor', 'folder')),
        );

        self::assertFalse($report->isComplete());
        self::assertInstanceOf(BindingRebindFailed::class, $report->failure);
        self::assertTrue($report->failure->restored, 'the previous binding must be reported as restored');
        self::assertNull($report->failure->restoreError);
        self::assertSame('group', $report->failed?->entity->kind->value);
        self::assertSame('eng', $report->failed?->entity->key);
    }

    /** When the restore ALSO fails, the report says so instead of claiming success. */
    public function testFailedReassignmentWhoseRestoreAlsoFailsReportsBothFailures(): void
    {
        $client = $this->signedInWith(
            self::page([self::resourceRow('Folder')], 1),
            self::page([self::roleRow('editor')], 1),
            self::page([self::groupRow('Engineering')], 1),
            self::json(200, [self::assignmentRow(self::roleRow('editor'))]),
            new Response(204), // unassign
            new Response(400), // assign -> refused
            new Response(500), // restore -> ALSO refused
        );

        $report = $client->management()->manifest()->apply(
            self::scopedGroupManifest(RoleBinding::at('editor', 'folder')),
        );

        self::assertFalse($report->isComplete());
        self::assertInstanceOf(BindingRebindFailed::class, $report->failure);
        self::assertFalse($report->failure->restored, 'a failed restore must never be reported as succeeding');
        self::assertNotNull($report->failure->restoreError);
    }

    // -- one role bound twice is refused before any request -------------------

    /**
     * The server keys an assignment on (subject, role): binding one role twice to one
     * group — plain and scoped alike — is refused while the manifest is BUILT, before a
     * client even exists to send a request.
     */
    public function testARoleBoundTwiceToOneGroupIsRefusedBeforeAnyRequest(): void
    {
        $this->expectException(ManifestException::class);
        $this->expectExceptionMessageMatches('/more than once/');

        ManagementManifest::builder()
            ->resource('folder', 'Folder', 'folder_type')
            ->role('editor', 'editor', 'Editor role')
            ->group('eng', 'Engineering', 'desc', roleKeys: [
                RoleBinding::role('editor'),
                RoleBinding::at('editor', 'folder'),
            ])
            ->build();
    }

    /** I4 twin: a role bound exactly ONCE builds without complaint. */
    public function testARoleBoundOnceBuildsWithoutComplaint(): void
    {
        $manifest = ManagementManifest::builder()
            ->resource('folder', 'Folder', 'folder_type')
            ->role('editor', 'editor', 'Editor role')
            ->group('eng', 'Engineering', 'desc', roleKeys: [RoleBinding::at('editor', 'folder')])
            ->build();

        self::assertCount(3, $manifest->entities);
    }

    // -- a global role bound with inherit: false is refused before any request ----

    public function testAGlobalRoleBoundWithInheritFalseIsRefusedBeforeAnyRequest(): void
    {
        $this->expectException(ManifestException::class);
        $this->expectExceptionMessageMatches('/global/');

        ManagementManifest::builder()
            ->resource('folder', 'Folder', 'folder_type')
            ->role('admin', 'admin', 'Admin role', isGlobal: true)
            ->group('eng', 'Engineering', 'desc', roleKeys: [RoleBinding::atOnly('admin', 'folder')])
            ->build();
    }

    /** I4 twin: the SAME global role, bound with the default (inheriting) flag, is fine. */
    public function testAGlobalRoleBoundWithDefaultInheritIsAccepted(): void
    {
        $manifest = ManagementManifest::builder()
            ->role('admin', 'admin', 'Admin role', isGlobal: true)
            ->group('eng', 'Engineering', 'desc', roleKeys: ['admin'])
            ->build();

        self::assertCount(2, $manifest->entities);
    }

    /** Control: a NON-global role bound `inherit: false` is accepted — the check is global-only. */
    public function testANonGlobalRoleBoundWithInheritFalseIsAccepted(): void
    {
        $manifest = ManagementManifest::builder()
            ->resource('folder', 'Folder', 'folder_type')
            ->role('editor', 'editor', 'Editor role')
            ->group('eng', 'Engineering', 'desc', roleKeys: [RoleBinding::atOnly('editor', 'folder')])
            ->build();

        self::assertCount(3, $manifest->entities);
    }

    // -- the same engine, exercised through a service account ------------------

    /**
     * Role bindings reconcile identically for a service account (CONTRACT.md §27.6.1
     * addition 3) — the same rebind-and-carry-tenant_scope path, through
     * `serviceAccounts()->listRoles()` / `roles()->assignToServiceAccount()`.
     */
    public function testServiceAccountScopedBindingRebindsAndKeepsTenantScope(): void
    {
        $client = $this->signedInWith(
            self::page([self::resourceRow('Folder')], 1),
            self::page([self::roleRow('editor')], 1),
            self::page([self::serviceAccountRow('device-fleet')], 1),
            self::json(200, [
                self::assignmentRow(self::roleRow('editor'), tenantScope: [self::TENANT_SCOPE_TENANT]),
            ]),
            new Response(204), // unassign
            new Response(204), // assign
        );

        $manifest = ManagementManifest::builder()
            ->resource('folder', 'Folder', 'folder_type')
            ->role('editor', 'editor', 'Editor role')
            ->serviceAccount('fleet', 'device-fleet', roleKeys: [RoleBinding::at('editor', 'folder')])
            ->build();

        $report = $client->management()->manifest()->apply($manifest);

        self::assertTrue($report->isComplete(), $report->failure?->getMessage() ?? '');
        self::assertSame(
            1,
            $this->requestsFor('DELETE', '/roles/' . self::ROLE_ID . '/service-accounts/' . self::SA_ID),
        );
        $assignBody = json_decode((string) $this->lastRequest()->getBody(), true);
        self::assertSame(self::FOLDER_ID, $assignBody['resource_id']);
        self::assertSame([self::TENANT_SCOPE_TENANT], $assignBody['tenant_scope'] ?? null);
    }
}
