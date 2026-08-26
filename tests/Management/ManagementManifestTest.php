<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Management;

use Axiam\Sdk\Attributes\ManagedGroup;
use Axiam\Sdk\Attributes\ManagedPermission;
use Axiam\Sdk\Attributes\ManagedResource;
use Axiam\Sdk\Attributes\ManagedRole;
use Axiam\Sdk\Management\Manifest\ChangeAction;
use Axiam\Sdk\Management\Manifest\ManagementManifest;
use Axiam\Sdk\Management\Manifest\ManifestAttributeReader;
use Axiam\Sdk\Management\Manifest\ManifestException;
use Axiam\Sdk\Management\Manifest\ManifestKind;
use GuzzleHttp\Psr7\Response;

/**
 * The §27.6/§27.7 declarative layer.
 *
 * Everything here is about the properties that make a manifest safe to run more than
 * once against a live tenant: plan writes nothing, ordering is derived and stable,
 * incoherence is refused before the first request, apply stops at the first failure
 * without rolling back, and omission is never deletion.
 */
final class ManagementManifestTest extends ManagementTestCase
{
    // -- plan writes nothing ----------------------------------------------

    /** `plan()` issues reads only — no request that could change anything (§27.6). */
    public function testPlanSendsNoWrites(): void
    {
        $client = $this->signedInWith(self::page([], 0), self::page([], 0));

        $client->management()->manifest()->plan(
            ManagementManifest::builder()
                ->permission('read', 'documents:read', 'Read documents')
                ->role('auditor', 'auditor', 'Read-only auditor', grants: ['read' => 'allow'])
                ->build(),
        );

        foreach ($this->sentMethods() as $method) {
            self::assertSame('GET', $method, 'plan() must not issue a write');
        }
    }

    /** A plan over an empty tenant is all creates. */
    public function testPlanOverAnEmptyTenantIsAllCreates(): void
    {
        $client = $this->signedInWith(self::page([], 0), self::page([], 0));

        $plan = $client->management()->manifest()->plan(
            ManagementManifest::builder()
                ->permission('read', 'documents:read', 'Read documents')
                ->role('auditor', 'auditor', 'Read-only auditor', grants: ['read' => 'allow'])
                ->build(),
        );

        self::assertCount(2, $plan->pending());
        foreach ($plan->pending() as $change) {
            self::assertSame(ChangeAction::Create, $change->action);
        }
    }

    /** A tenant that already matches plans nothing at all (§27.6). */
    public function testAConvergedTenantPlansNothing(): void
    {
        $client = $this->signedInWith(
            self::page([self::permission('documents:read', 'Read documents')], 1),
        );

        $plan = $client->management()->manifest()->plan(
            ManagementManifest::builder()
                ->permission('read', 'documents:read', 'Read documents')
                ->build(),
        );

        self::assertTrue($plan->isConverged());
        self::assertSame([], $plan->describe());
    }

    /** ...and applying it sends nothing either. */
    public function testAConvergedTenantAppliesNothing(): void
    {
        $client = $this->signedInWith(
            self::page([self::permission('documents:read', 'Read documents')], 1),
        );

        $report = $client->management()->manifest()->apply(
            ManagementManifest::builder()
                ->permission('read', 'documents:read', 'Read documents')
                ->build(),
        );

        self::assertTrue($report->isComplete());
        self::assertSame([], $report->applied);
        self::assertSame(2, $this->requestCount(), 'login + the one read plan() needed');
    }

    /** Drift produces an update carrying ONLY the drifted field (§27.4 rule 5). */
    public function testDriftIsUpdatedInPlaceWithOnlyTheDriftedField(): void
    {
        $client = $this->signedInWith(
            self::page([self::permission('documents:read', 'stale description')], 1),
            self::json(200, self::permission('documents:read', 'Read documents')),
        );

        $report = $client->management()->manifest()->apply(
            ManagementManifest::builder()
                ->permission('read', 'documents:read', 'Read documents')
                ->build(),
        );

        self::assertTrue($report->isComplete());
        self::assertCount(1, $report->applied);
        self::assertSame(ChangeAction::Update, $report->applied[0]->action);
        self::assertSame(['description' => 'Read documents'], $this->lastBody());
    }

    /** Applying the same manifest twice writes nothing the second time (§27.6). */
    public function testASecondApplyWritesNothing(): void
    {
        $created = self::permission('documents:read', 'Read documents');
        $client = $this->signedInWith(
            self::page([], 0),
            self::json(200, $created),
            self::page([$created], 1),
        );

        $manifest = ManagementManifest::builder()
            ->permission('read', 'documents:read', 'Read documents')
            ->build();

        $manifestApi = $client->management()->manifest();
        self::assertTrue($manifestApi->apply($manifest)->isComplete());

        $second = $manifestApi->apply($manifest);
        self::assertTrue($second->isComplete());
        self::assertSame([], $second->applied, 'the second apply must be a no-op');
    }

    // -- ordering is derived and stable ------------------------------------

    /** Apply order is derived from kind, never from declaration order (§27.6). */
    public function testOrderingIsDerivedNotDeclared(): void
    {
        // Declared backwards on purpose: group, role, permission, resource.
        $manifest = ManagementManifest::builder()
            ->group('g', 'engineers', '', ['r'])
            ->role('r', 'auditor', '', grants: ['p' => 'allow'])
            ->permission('p', 'documents:read', '')
            ->resource('res', 'root', 'folder')
            ->build();

        $kinds = array_map(
            static fn ($e): string => $e->kind->value,
            $manifest->ordered(),
        );

        self::assertSame(['resource', 'permission', 'role', 'group'], $kinds);
    }

    /** A resource parent is applied before its child. */
    public function testAParentResourceIsOrderedBeforeItsChild(): void
    {
        $manifest = ManagementManifest::builder()
            ->resource('child', 'child', 'folder', parentKey: 'parent')
            ->resource('parent', 'parent', 'folder')
            ->build();

        $keys = array_map(static fn ($e): string => $e->key, $manifest->ordered());

        self::assertSame(['parent', 'child'], $keys);
    }

    /** The same manifest produces the same order every time (§27.6: stable across runs). */
    public function testOrderingIsStableAcrossRuns(): void
    {
        $build = static fn (): ManagementManifest => ManagementManifest::builder()
            ->permission('zeta', 'z:read', '')
            ->permission('alpha', 'a:read', '')
            ->permission('mid', 'm:read', '')
            ->build();

        $first = array_map(static fn ($e): string => $e->key, $build()->ordered());
        $second = array_map(static fn ($e): string => $e->key, $build()->ordered());

        self::assertSame($first, $second);
        self::assertSame(['alpha', 'mid', 'zeta'], $first, 'ties break on key, deterministically');
    }

    // -- incoherence is refused BEFORE any request -------------------------

    /** A dangling reference is refused, and nothing is sent (§27.6). */
    public function testADanglingReferenceIsRefusedBeforeAnyRequest(): void
    {
        $client = $this->signedInClientNoResponse();

        $manifest = new ManagementManifest([
            new \Axiam\Sdk\Management\Manifest\ManifestEntity(
                ManifestKind::Role,
                'auditor',
                'auditor',
                [],
                ['a-permission-nobody-declared'],
            ),
        ]);

        try {
            $client->management()->manifest()->plan($manifest);
            self::fail('expected a ManifestException');
        } catch (ManifestException $e) {
            self::assertStringContainsString('does not declare', $e->getMessage());
            self::assertSame(1, $this->requestCount(), 'only the login; no manifest read');
        }
    }

    /** A dependency cycle is refused, and nothing is sent (§27.6). */
    public function testACycleIsRefusedBeforeAnyRequest(): void
    {
        $client = $this->signedInClientNoResponse();

        $manifest = new ManagementManifest([
            new \Axiam\Sdk\Management\Manifest\ManifestEntity(
                ManifestKind::Resource, 'a', 'a', [], ['b'],
            ),
            new \Axiam\Sdk\Management\Manifest\ManifestEntity(
                ManifestKind::Resource, 'b', 'b', [], ['a'],
            ),
        ]);

        try {
            $client->management()->manifest()->plan($manifest);
            self::fail('expected a ManifestException');
        } catch (ManifestException $e) {
            self::assertStringContainsString('cycle', $e->getMessage());
            self::assertSame(1, $this->requestCount());
        }
    }

    /** A duplicate key within one kind is refused — one would silently win otherwise. */
    public function testADuplicateKeyIsRefused(): void
    {
        $this->expectException(ManifestException::class);
        $this->expectExceptionMessageMatches('/twice/');

        ManagementManifest::builder()
            ->permission('read', 'documents:read', '')
            ->permission('read', 'documents:write', '')
            ->build();
    }

    // -- apply stops at the first failure, without rolling back -------------

    /** Apply stops at the first failure and does NOT undo what landed (§27.7). */
    public function testApplyStopsAtTheFirstFailureAndDoesNotRollBack(): void
    {
        $client = $this->signedInWith(
            self::page([], 0),                                        // plan: permissions
            self::json(200, self::permission('a:read', 'A')),         // create #1 -> ok
            new Response(500),                                        // create #2 -> boom
        );

        $report = $client->management()->manifest()->apply(
            ManagementManifest::builder()
                ->permission('a', 'a:read', 'A')
                ->permission('b', 'b:read', 'B')
                ->permission('c', 'c:read', 'C')
                ->build(),
        );

        self::assertFalse($report->isComplete());
        self::assertCount(1, $report->applied, 'the first create landed and stays landed');
        self::assertNotNull($report->failed);
        self::assertSame('b', $report->failed->entity->key);
        self::assertCount(1, $report->remaining, 'the third was never attempted');
        self::assertSame('c', $report->remaining[0]->entity->key);

        self::assertSame(4, $this->requestCount(), 'login + 1 read + 2 creates; no rollback traffic');
    }

    /** The report reads as a recovery instruction, not just a boolean. */
    public function testTheApplyReportDescribesWhatLandedAndWhatDidNot(): void
    {
        $client = $this->signedInWith(
            self::page([], 0),
            self::json(200, self::permission('a:read', 'A')),
            new Response(500),
        );

        $report = $client->management()->manifest()->apply(
            ManagementManifest::builder()
                ->permission('a', 'a:read', 'A')
                ->permission('b', 'b:read', 'B')
                ->permission('c', 'c:read', 'C')
                ->build(),
        );

        $lines = $report->describe();

        self::assertStringStartsWith('applied  create permission:a', $lines[0]);
        self::assertStringStartsWith('FAILED   create permission:b', $lines[1]);
        self::assertStringStartsWith('skipped  create permission:c', $lines[2]);
    }

    // -- omission is never deletion ----------------------------------------

    /**
     * An object the manifest does not mention is left strictly alone (§27.6).
     *
     * There is no `ChangeAction::Delete` at all, which is the structural version of this
     * guarantee: a manifest cannot express deletion, so an incomplete manifest cannot
     * become a destructive one.
     */
    public function testOmissionIsNeverDeletion(): void
    {
        $client = $this->signedInWith(
            self::page([
                self::permission('documents:read', 'Read documents'),
                self::permission('secrets:read', 'Something nobody declared'),
            ], 2),
        );

        $plan = $client->management()->manifest()->plan(
            ManagementManifest::builder()
                ->permission('read', 'documents:read', 'Read documents')
                ->build(),
        );

        self::assertTrue($plan->isConverged());
        self::assertSame(
            [],
            array_filter(ChangeAction::cases(), static fn (ChangeAction $a): bool => $a->name === 'Delete'),
            'ChangeAction must not have a Delete case',
        );
    }

    // -- the PHP attribute face --------------------------------------------

    /** A manifest can be declared with attributes and read back identically. */
    public function testAManifestCanBeDeclaredWithAttributes(): void
    {
        $manifest = ManifestAttributeReader::read(ExampleTenantManifest::class);

        $keys = array_map(static fn ($e): string => $e->key, $manifest->ordered());

        self::assertSame(['root', 'read', 'auditor', 'engineers'], $keys);
    }

    /** The attribute reader refuses an incoherent declaration, like the builder does. */
    public function testTheAttributeReaderRefusesADanglingRoleReference(): void
    {
        $this->expectException(ManifestException::class);
        ManifestAttributeReader::read(BrokenTenantManifest::class);
    }

    /** Reading a class that does not exist fails with a manifest error, not a PHP one. */
    public function testReadingAMissingClassFailsCleanly(): void
    {
        $this->expectException(ManifestException::class);
        $this->expectExceptionMessageMatches('/does not exist/');
        /** @phpstan-ignore-next-line intentionally a non-existent class */
        ManifestAttributeReader::read('Axiam\\Sdk\\Tests\\Management\\NoSuchManifest');
    }

    // -- helpers ------------------------------------------------------------

    /**
     * A minimal `Permission` object as the server would send it.
     *
     * @return array<string,mixed>
     */
    private static function permission(string $action, string $description): array
    {
        return [
            'action' => $action,
            'created_at' => '2026-08-26T00:00:00Z',
            'description' => $description,
            'id' => self::ORG_ID,
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }
}

/**
 * A tenant shape declared with §27.6 attributes — the fixture for the reader tests.
 *
 * Never instantiated; only its attributes are read.
 */
#[ManagedResource(key: 'root', name: 'root', type: 'folder')]
#[ManagedPermission(key: 'read', action: 'documents:read', description: 'Read documents')]
#[ManagedRole(key: 'auditor', name: 'auditor', description: 'Read-only', grants: ['read' => 'allow'])]
#[ManagedGroup(key: 'engineers', name: 'engineers', description: 'Engineering', roleKeys: ['auditor'])]
final class ExampleTenantManifest
{
}

/** A declaration whose group names a role nobody declares. */
#[ManagedGroup(key: 'engineers', name: 'engineers', roleKeys: ['a-role-nobody-declared'])]
final class BrokenTenantManifest
{
}
