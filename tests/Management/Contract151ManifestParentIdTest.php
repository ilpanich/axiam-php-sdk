<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Management;

use Axiam\Sdk\Management\Manifest\ChangeAction;
use Axiam\Sdk\Management\Manifest\ManagementManifest;

/**
 * §13 row 17 defect (b): PHP never sent a resource's `parent_id` on `Create`, although
 * `CreateResourceRequest` has always had the field — a nested manifest was created FLAT.
 *
 * `apply()` now resolves a child resource's parent to the parent's SERVER id (§27.6
 * rule 5 already creates parents before children; the fix is carrying that id onto the
 * wire, not the ordering, which was already correct) and sends it as `parent_id`.
 */
final class Contract151ManifestParentIdTest extends ManagementTestCase
{
    private const PARENT_ID = '55555555-5555-4555-8555-555555555555';
    private const CHILD_ID = '66666666-6666-4666-8666-666666666666';

    /** @return array<string,mixed> */
    private static function resourceRow(string $name, string $id, ?string $parentId = null): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'id' => $id,
            'metadata' => [],
            'name' => $name,
            'parent_id' => $parentId,
            'resource_type' => 'folder',
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    private static function nestedManifest(): ManagementManifest
    {
        return ManagementManifest::builder()
            ->resource('root', 'engineering', 'folder')
            ->resource('child', 'backend-team', 'folder', parentKey: 'root')
            ->build();
    }

    /** The create body for the CHILD resource carries `parent_id` of the created parent. */
    public function testCreateBodyCarriesParentIdOfTheCreatedParent(): void
    {
        $client = $this->signedInWith(
            self::page([], 0), // plan/apply read: no resources exist yet
            self::json(200, self::resourceRow('engineering', self::PARENT_ID)), // create parent
            self::json(200, self::resourceRow('backend-team', self::CHILD_ID, self::PARENT_ID)), // create child
        );

        $report = $client->management()->manifest()->apply(self::nestedManifest());

        self::assertTrue($report->isComplete());
        self::assertCount(2, $report->applied);

        // requests[0] = login, [1] = the plan/apply read, [2] = create parent, [3] = create child
        $childCreateBody = json_decode((string) $this->requests[3]->getBody(), true);
        self::assertSame('backend-team', $childCreateBody['name']);
        self::assertSame(
            self::PARENT_ID,
            $childCreateBody['parent_id'] ?? null,
            'the child resource create body must carry the PARENT resource\'s real server id',
        );

        // And the parent's own create body carries NO parent_id (it has none).
        $parentCreateBody = json_decode((string) $this->requests[2]->getBody(), true);
        self::assertArrayNotHasKey('parent_id', $parentCreateBody);
    }

    /**
     * Idempotence: apply(), then plan() against the now-nested tenant reports both
     * resources Unchanged — converged, nothing pending.
     */
    public function testApplyThenPlanIsEmptyOverTheNestedManifest(): void
    {
        $manifest = self::nestedManifest();

        $client = $this->signedInWith(
            self::page([], 0),
            self::json(200, self::resourceRow('engineering', self::PARENT_ID)),
            self::json(200, self::resourceRow('backend-team', self::CHILD_ID, self::PARENT_ID)),
            // The second read, for plan(): both resources now exist, parent already linked.
            self::page([
                self::resourceRow('engineering', self::PARENT_ID),
                self::resourceRow('backend-team', self::CHILD_ID, self::PARENT_ID),
            ], 2),
        );

        $report = $client->management()->manifest()->apply($manifest);
        self::assertTrue($report->isComplete());

        $plan = $client->management()->manifest()->plan($manifest);

        self::assertTrue($plan->isConverged(), 'a second plan() over the now-nested tenant must be empty');
        foreach ($plan->changes as $change) {
            self::assertSame(ChangeAction::Unchanged, $change->action);
        }
    }

    /** A three-level tree: the grandchild's create body carries the CHILD's id, not the root's. */
    public function testAThreeLevelTreeCarriesTheImmediateParentNotTheRoot(): void
    {
        $grandchildId = '77777777-7777-4777-8777-777777777777';
        $manifest = ManagementManifest::builder()
            ->resource('root', 'org', 'folder')
            ->resource('child', 'engineering', 'folder', parentKey: 'root')
            ->resource('grandchild', 'backend', 'folder', parentKey: 'child')
            ->build();

        $client = $this->signedInWith(
            self::page([], 0),
            self::json(200, self::resourceRow('org', self::PARENT_ID)),
            self::json(200, self::resourceRow('engineering', self::CHILD_ID, self::PARENT_ID)),
            self::json(200, self::resourceRow('backend', $grandchildId, self::CHILD_ID)),
        );

        $report = $client->management()->manifest()->apply($manifest);

        self::assertTrue($report->isComplete());
        $grandchildBody = json_decode((string) $this->requests[4]->getBody(), true);
        self::assertSame(self::CHILD_ID, $grandchildBody['parent_id'], 'the grandchild names its IMMEDIATE parent, not the root');
    }
}
