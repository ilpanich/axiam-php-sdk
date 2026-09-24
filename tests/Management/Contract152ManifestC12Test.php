<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Management;

use Axiam\Sdk\Management\Manifest\ManagementManifest;
use Axiam\Sdk\Management\Manifest\ManifestEntity;
use Axiam\Sdk\Management\Manifest\ManifestException;
use Axiam\Sdk\Management\Manifest\ManifestKind;

/**
 * CONTRACT 1.52 (C-12), two manifest defects independent of the grant/binding-Update
 * fix in {@see Contract151ManifestGrantsAndBindingsTest}:
 *
 * - N6.5 — metadata. A stated `{}` was inexpressible (indistinguishable from an
 *   unstated field), and drift compared it with a strict `!==` that depends on key
 *   order, so a server echoing the SAME object back with its keys reordered read as
 *   drift.
 * - N6.6 — references resolve by kind. A role binding's `role`/`resource`, and a
 *   resource's `parent`, are checked for EXISTENCE only, not kind, so a role key that
 *   happens to collide with a group's key (legal: keys are unique only within their own
 *   kind) passed validation and would fail mid-`apply()` instead of being refused
 *   up front.
 */
final class Contract152ManifestC12Test extends ManagementTestCase
{
    // -----------------------------------------------------------------
    // N6.5a — a stated {} must be sent, distinct from an unstated field
    // -----------------------------------------------------------------

    private static function entityByKey(ManagementManifest $manifest, string $key): ManifestEntity
    {
        foreach ($manifest->entities as $entity) {
            if ($entity->key === $key) {
                return $entity;
            }
        }

        self::fail(sprintf('manifest has no entity under key "%s"', $key));
    }

    public function testResourceStatedEmptyMetadataIsDistinctFromUnstated(): void
    {
        $manifest = ManagementManifest::builder()
            ->resource('withEmpty', 'With Empty', 'site_type', metadata: [])
            ->resource('unstated', 'Unstated', 'site_type')
            ->build();

        $withEmpty = self::entityByKey($manifest, 'withEmpty');
        $unstated = self::entityByKey($manifest, 'unstated');

        self::assertArrayHasKey(
            'metadata',
            $withEmpty->fields,
            'a stated {} must be sent, CONTRACT 1.52 N6.5 (C-12)',
        );
        self::assertSame([], $withEmpty->fields['metadata']);
        self::assertArrayNotHasKey(
            'metadata',
            $unstated->fields,
            'an unstated metadata must never be sent or checked for drift',
        );
    }

    public function testGroupStatedEmptyMetadataIsDistinctFromUnstated(): void
    {
        $manifest = ManagementManifest::builder()
            ->group('withEmpty', 'With Empty', 'desc', metadata: [])
            ->group('unstated', 'Unstated', 'desc')
            ->build();

        self::assertArrayHasKey('metadata', self::entityByKey($manifest, 'withEmpty')->fields);
        self::assertSame([], self::entityByKey($manifest, 'withEmpty')->fields['metadata']);
        self::assertArrayNotHasKey('metadata', self::entityByKey($manifest, 'unstated')->fields);
    }

    /** A stated, NON-empty metadata is unaffected — the existing, already-correct case. */
    public function testResourceStatedNonEmptyMetadataStillWorks(): void
    {
        $manifest = ManagementManifest::builder()
            ->resource('r', 'R', 'site_type', metadata: ['env' => 'prod'])
            ->build();

        self::assertSame(['env' => 'prod'], self::entityByKey($manifest, 'r')->fields['metadata']);
    }

    // -----------------------------------------------------------------
    // N6.5b — drift() is JSON value equality, independent of key order
    // -----------------------------------------------------------------

    public function testDriftIgnoresAnObjectsKeyOrder(): void
    {
        $entity = new ManifestEntity(
            ManifestKind::Resource,
            'r',
            'R',
            ['metadata' => ['a' => 1, 'b' => 2]],
        );

        self::assertSame(
            [],
            $entity->drift(['metadata' => ['b' => 2, 'a' => 1]]),
            'CONTRACT 1.52 N6.5 (C-12): key order must not read as drift',
        );
    }

    public function testDriftStillDetectsARealValueDifference(): void
    {
        $entity = new ManifestEntity(
            ManifestKind::Resource,
            'r',
            'R',
            ['metadata' => ['a' => 1, 'b' => 2]],
        );

        self::assertSame(
            ['metadata' => ['a' => 1, 'b' => 2]],
            $entity->drift(['metadata' => ['a' => 1, 'b' => 99]]),
            'a genuine value difference must still be reported',
        );
    }

    /** Nested objects: key order must not matter at any depth. */
    public function testDriftIgnoresKeyOrderInNestedObjects(): void
    {
        $entity = new ManifestEntity(
            ManifestKind::Resource,
            'r',
            'R',
            ['metadata' => ['outer' => ['x' => 1, 'y' => 2]]],
        );

        self::assertSame(
            [],
            $entity->drift(['metadata' => ['outer' => ['y' => 2, 'x' => 1]]]),
        );
    }

    /** The I4 twin: a JSON ARRAY's element order is still significant. */
    public function testDriftStillTreatsListOrderAsSignificant(): void
    {
        $entity = new ManifestEntity(
            ManifestKind::Resource,
            'r',
            'R',
            ['tags' => ['first', 'second']],
        );

        self::assertNotSame(
            [],
            $entity->drift(['tags' => ['second', 'first']]),
            'list order is meaningful for a JSON array — this is NOT the same drift',
        );
        self::assertSame(
            [],
            $entity->drift(['tags' => ['first', 'second']]),
        );
    }

    // -----------------------------------------------------------------
    // N6.6 — references resolve by kind
    // -----------------------------------------------------------------

    /** A role binding naming a GROUP's key (not a Role's) is a dangling reference. */
    public function testARoleBindingNamingAGroupsKeyIsADanglingReference(): void
    {
        $this->expectException(ManifestException::class);
        $this->expectExceptionMessageMatches('/does not declare/');

        ManagementManifest::builder()
            ->group('shared-key', 'Group Named Shared', 'desc')
            ->group('team', 'Team', 'desc', roleKeys: ['shared-key'])
            ->build();
    }

    /** A resource's parentKey naming a ROLE's key (not a Resource's) is dangling too. */
    public function testAResourcesParentNamingANonResourceKeyIsADanglingReference(): void
    {
        $this->expectException(ManifestException::class);
        $this->expectExceptionMessageMatches('/does not declare/');

        ManagementManifest::builder()
            ->role('site', 'Site-named-role', 'desc')
            ->resource('child', 'Child', 'site_type', parentKey: 'site')
            ->build();
    }

    /** A scoped binding's resource key naming a ROLE's key (not a Resource's) is dangling. */
    public function testAScopedBindingsResourceNamingANonResourceKeyIsADanglingReference(): void
    {
        $this->expectException(ManifestException::class);

        ManagementManifest::builder()
            ->role('editor', 'editor', 'desc')
            ->role('not-a-resource', 'not-a-resource', 'desc')
            ->group('team', 'Team', 'desc', roleKeys: [
                \Axiam\Sdk\Management\Manifest\RoleBinding::at('editor', 'not-a-resource'),
            ])
            ->build();
    }

    /**
     * The I4 twin: the SAME key used for a Role and a Group (legal — keys are unique
     * only within their own kind) must not be confused. A binding naming that key must
     * resolve to the ROLE, and building must succeed.
     */
    public function testSameKeyAcrossDifferentKindsIsNotADanglingReference(): void
    {
        $manifest = ManagementManifest::builder()
            ->role('shared', 'Auditor', 'desc')
            ->group('shared', 'Some Group', 'desc')
            ->group('team', 'Team', 'desc', roleKeys: ['shared'])
            ->build();

        self::assertNotNull($manifest);
    }

    /** A resource's parent naming a REAL resource key is unaffected — the ordinary case. */
    public function testAResourcesParentNamingARealResourceKeyStillWorks(): void
    {
        $manifest = ManagementManifest::builder()
            ->resource('root', 'Root', 'site_type')
            ->resource('child', 'Child', 'site_type', parentKey: 'root')
            ->build();

        self::assertNotNull($manifest);
    }
}
