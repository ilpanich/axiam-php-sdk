<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Management;

use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Management\FieldError;
use Axiam\Sdk\Management\ManagementTransport;
use Axiam\Sdk\Management\Manifest\ChangeAction;
use Axiam\Sdk\Management\Manifest\ManagementManifest;
use Axiam\Sdk\Management\Manifest\ManifestEntity;
use Axiam\Sdk\Management\Manifest\ManifestKind;
use Axiam\Sdk\Management\Models;
use Axiam\Sdk\Management\NamespaceScope;
use Axiam\Sdk\Management\Page;
use Axiam\Sdk\Management\PageRequest;
use GuzzleHttp\Psr7\Response;

/**
 * The §27 hand-written core: paging arithmetic, scope resolution, transport error paths,
 * and the manifest apply branches the higher-level suites do not reach.
 *
 * Where {@see ManagementSemanticsTest} asserts the §27.4 rules end to end, these are the
 * unit-level edges underneath them — the odd response body, the second kind of manifest
 * entity, the arithmetic that decides whether auto-paging re-reads a row.
 */
final class ManagementCoreTest extends ManagementTestCase
{
    // -- paging arithmetic -------------------------------------------------

    /** `next()` advances by the page SIZE, not by how many items came back. */
    public function testPageRequestAdvancesByLimit(): void
    {
        $first = new PageRequest(0, 25);
        $second = $first->next();

        self::assertSame(25, $second->offset);
        self::assertSame(25, $second->limit);
        self::assertSame(50, $second->next()->offset);
    }

    /** Nonsense paging values are clamped rather than sent to the server. */
    public function testPageRequestClampsNonsenseValues(): void
    {
        self::assertSame(['offset' => 0, 'limit' => 1], (new PageRequest(-5, 0))->toQuery());
    }

    /** A Page reports its own item count, and separately the server's total. */
    public function testPageCountsItemsNotTotal(): void
    {
        $page = new Page(['a', 'b'], 400, new PageRequest());

        self::assertCount(2, $page);
        self::assertSame(400, $page->total);
        self::assertFalse($page->isEmpty());
        self::assertSame(['a', 'b'], iterator_to_array($page));
        self::assertSame(50, $page->nextRequest()->offset);
    }

    /** An empty page is what ends an auto-paging walk. */
    public function testAnEmptyPageIsEmpty(): void
    {
        self::assertTrue((new Page([], 0, new PageRequest()))->isEmpty());
    }

    /** A walk over an immediately-empty collection yields nothing and stops. */
    public function testWalkOverAnEmptyCollectionYieldsNothing(): void
    {
        $calls = 0;
        $items = iterator_to_array(ManagementTransport::walk(
            static function (PageRequest $p) use (&$calls): Page {
                ++$calls;

                return new Page([], 0, $p);
            },
        ), false);

        self::assertSame([], $items);
        self::assertSame(1, $calls);
    }

    // -- scope resolution ---------------------------------------------------

    /** A scope override replaces one id and leaves the other alone. */
    public function testNamespaceScopeOverridesOneIdAtATime(): void
    {
        $scope = new NamespaceScope();

        self::assertSame('org', $scope->withOrg('org')->orgId);
        self::assertNull($scope->withOrg('org')->tenantId);
        self::assertSame('ten', $scope->withOrg('org')->withTenant('ten')->tenantId);
        self::assertSame('org', $scope->withOrg('org')->withTenant('ten')->orgId);
    }

    /** `->forTenant()` re-scopes a tenant-implicit handle and returns a copy. */
    public function testForTenantOverridesTheImplicitTenantId(): void
    {
        $other = '33333333-3333-4333-8333-333333333333';
        $client = $this->signedInWith(
            self::json(200, self::emailConfigOverride()),
            self::json(200, self::emailConfigOverride()),
        );

        $handle = $client->management()->emailConfig();
        $handle->forTenant($other)->getTenant();
        self::assertStringContainsString($other, $this->lastRequest()->getUri()->getPath());

        $handle->getTenant();
        self::assertStringContainsString(self::TENANT_ID, $this->lastRequest()->getUri()->getPath());
    }

    /** A tenant-scoped route with no tenant id refuses rather than sending `//`. */
    public function testAMissingTenantIdRefuses(): void
    {
        $client = new \Axiam\Sdk\AxiamClient(
            self::BASE_URL,
            self::TENANT,
            orgId: self::ORG_ID,
            transportHandler: new \GuzzleHttp\Handler\MockHandler([
                new Response(200, ['Set-Cookie' => 'axiam_access=t0ken; Path=/'], '{"user":{"id":"u"}}'),
            ]),
        );
        $client->login('admin@axiam.test', 'pw');

        $this->expectException(\Axiam\Sdk\Core\AxiamException::class);
        $this->expectExceptionMessageMatches('/tenant id/');
        $client->management()->emailConfig()->getTenant();
    }

    // -- transport error paths ----------------------------------------------

    /** A transport failure with no response becomes a NetworkError naming the operation. */
    public function testATransportFailureIsWrapped(): void
    {
        $client = $this->signedInWith(
            new \GuzzleHttp\Exception\ConnectException(
                'connection refused',
                new \GuzzleHttp\Psr7\Request('GET', '/'),
            ),
        );

        try {
            $client->management()->roles()->create(new Models\CreateRoleRequest('d', false, 'n'));
            self::fail('expected a NetworkError');
        } catch (NetworkError $e) {
            self::assertStringContainsString('roles.create', $e->getMessage());
        }
    }

    /** A success body that is not JSON is a NetworkError, not a decode crash. */
    public function testANonJsonSuccessBodyIsANetworkError(): void
    {
        $client = $this->signedInWith(new Response(200, [], 'not json at all'));

        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/expected a JSON/');
        $client->management()->roles()->get(self::ORG_ID);
    }

    /** A 204 decodes to nothing rather than failing on an empty body. */
    public function testA204DecodesToNothing(): void
    {
        $client = $this->signedInWith(new Response(204));

        $client->management()->roles()->delete(self::ORG_ID);

        self::assertSame('DELETE', $this->lastRequest()->getMethod());
    }

    /** A 200 with an empty body is treated the same way as a 204. */
    public function testAnEmptyBodyOn200DecodesToNothing(): void
    {
        $client = $this->signedInWith(new Response(200, [], ''));

        $client->management()->roles()->delete(self::ORG_ID);

        self::assertSame('DELETE', $this->lastRequest()->getMethod());
    }

    /** A response missing a required field names the field and the model. */
    public function testAShortResponseBodyNamesWhatIsMissing(): void
    {
        $client = $this->signedInWith(self::json(200, ['id' => self::ORG_ID]));

        try {
            $client->management()->roles()->get(self::ORG_ID);
            self::fail('expected a NetworkError');
        } catch (NetworkError $e) {
            self::assertStringContainsString('is missing', $e->getMessage());
            self::assertStringContainsString('Role', $e->getMessage());
        }
    }

    /** A validation body keyed by field name (rather than a list) is also understood. */
    public function testValidationFieldsKeyedByNameAreParsed(): void
    {
        $client = $this->signedInWith(self::json(400, [
            'errors' => ['name' => 'must not be blank'],
        ]));

        try {
            $client->management()->roles()->get(self::ORG_ID);
            self::fail('expected a ValidationError');
        } catch (\Axiam\Sdk\Management\ValidationError $e) {
            self::assertEquals([new FieldError('name', 'must not be blank')], $e->fields);
        }
    }

    // -- manifest: the kinds the other suite does not apply ------------------

    /** A resource is created from its declaration. */
    public function testAResourceIsCreated(): void
    {
        $client = $this->signedInWith(
            self::page([], 0),
            self::json(200, self::resourceRow('root')),
        );

        $report = $client->management()->manifest()->apply(
            ManagementManifest::builder()->resource('root', 'root', 'folder')->build(),
        );

        self::assertTrue($report->isComplete());
        self::assertSame('POST', $this->lastRequest()->getMethod());
        self::assertSame(['name' => 'root', 'resource_type' => 'folder'], $this->lastBody());
    }

    /** A drifted resource is updated in place, carrying only the drifted field. */
    public function testADriftedResourceIsUpdated(): void
    {
        $client = $this->signedInWith(
            self::page([self::resourceRow('root', 'bucket')], 1),
            self::json(200, self::resourceRow('root')),
        );

        $report = $client->management()->manifest()->apply(
            ManagementManifest::builder()->resource('root', 'root', 'folder')->build(),
        );

        self::assertTrue($report->isComplete());
        self::assertSame(['resource_type' => 'folder'], $this->lastBody());
    }

    /** A role is created from its declaration. */
    public function testARoleIsCreated(): void
    {
        $client = $this->signedInWith(
            self::page([], 0),
            self::json(200, self::roleRow('auditor')),
        );

        $report = $client->management()->manifest()->apply(
            ManagementManifest::builder()->role('auditor', 'auditor', 'Read-only')->build(),
        );

        self::assertTrue($report->isComplete());
        self::assertSame(
            ['description' => 'Read-only', 'is_global' => false, 'name' => 'auditor'],
            $this->lastBody(),
        );
    }

    /** A drifted role is updated in place. */
    public function testADriftedRoleIsUpdated(): void
    {
        $client = $this->signedInWith(
            self::page([self::roleRow('auditor', 'stale')], 1),
            self::json(200, self::roleRow('auditor')),
        );

        $client->management()->manifest()->apply(
            ManagementManifest::builder()->role('auditor', 'auditor', 'Read-only')->build(),
        );

        self::assertSame(['description' => 'Read-only'], $this->lastBody());
    }

    /** A group is created from its declaration. */
    public function testAGroupIsCreated(): void
    {
        $client = $this->signedInWith(
            self::page([], 0),
            self::json(200, self::groupRow('engineers')),
        );

        $report = $client->management()->manifest()->apply(
            ManagementManifest::builder()->group('g', 'engineers', 'Engineering')->build(),
        );

        self::assertTrue($report->isComplete());
        self::assertSame(['description' => 'Engineering', 'name' => 'engineers'], $this->lastBody());
    }

    /** A drifted group is updated in place. */
    public function testADriftedGroupIsUpdated(): void
    {
        $client = $this->signedInWith(
            self::page([self::groupRow('engineers', 'stale')], 1),
            self::json(200, self::groupRow('engineers')),
        );

        $client->management()->manifest()->apply(
            ManagementManifest::builder()->group('g', 'engineers', 'Engineering')->build(),
        );

        self::assertSame(['description' => 'Engineering'], $this->lastBody());
    }

    /** `grants` and `roles` describe edges, not columns, so they never count as drift. */
    public function testEdgeFieldsAreNotFieldDrift(): void
    {
        $client = $this->signedInWith(self::page([self::roleRow('auditor')], 1));

        $plan = $client->management()->manifest()->plan(
            ManagementManifest::builder()
                ->role('auditor', 'auditor', 'Read-only', grants: [])
                ->build(),
        );

        self::assertTrue($plan->isConverged());
    }

    /** A change describes itself as `action kind:key`. */
    public function testAPlannedChangeDescribesItself(): void
    {
        $entity = new ManifestEntity(ManifestKind::Role, 'auditor', 'auditor');
        $change = new \Axiam\Sdk\Management\Manifest\PlannedChange($entity, ChangeAction::Create);

        self::assertSame('create role:auditor', $change->describe());
    }

    /** Drift compares only the fields the manifest names. */
    public function testDriftIgnoresFieldsTheManifestDoesNotName(): void
    {
        $entity = new ManifestEntity(ManifestKind::Role, 'r', 'auditor', ['name' => 'auditor']);

        self::assertSame([], $entity->drift(['name' => 'auditor', 'created_at' => 'whenever']));
        self::assertSame(['name' => 'auditor'], $entity->drift(['name' => 'other']));
        self::assertSame(['name' => 'auditor'], $entity->drift([]));
    }

    /** A manifest field of the wrong type is refused with a manifest error. */
    public function testANonStringManifestFieldIsRefused(): void
    {
        $client = $this->signedInWith(self::page([], 0));

        $manifest = new ManagementManifest([
            new ManifestEntity(ManifestKind::Role, 'r', 'auditor', ['name' => 42]),
        ]);

        $report = $client->management()->manifest()->apply($manifest);

        self::assertFalse($report->isComplete());
        self::assertInstanceOf(
            \Axiam\Sdk\Management\Manifest\ManifestException::class,
            $report->failure,
        );
    }

    /** A validation body whose `fields` is not a list yields no field errors, not a crash. */
    public function testANonArrayFieldsMemberYieldsNoFieldErrors(): void
    {
        $client = $this->signedInWith(self::json(422, ['fields' => 'everything']));

        try {
            $client->management()->roles()->get(self::ORG_ID);
            self::fail('expected a ValidationError');
        } catch (\Axiam\Sdk\Management\ValidationError $e) {
            self::assertSame([], $e->fields);
        }
    }

    /**
     * A body that cannot be encoded as JSON fails with a NetworkError naming the operation.
     *
     * Reachable through the ordinary API: a caller can put an invalid UTF-8 byte sequence
     * in any string field, and `json_encode` refuses it. Without this branch the request
     * would go out with an empty body.
     */
    public function testABodyThatCannotBeEncodedFailsClearly(): void
    {
        $client = $this->signedInClientNoResponse();

        try {
            $client->management()->roles()->update(
                self::ORG_ID,
                new Models\UpdateRole(name: "invalid \xB1\x31 utf8"),
            );
            self::fail('expected a NetworkError');
        } catch (NetworkError $e) {
            self::assertStringContainsString('roles.update', $e->getMessage());
            self::assertStringContainsString('could not be encoded', $e->getMessage());
        }
    }

    /** Resource metadata reaches the create body when the declaration carries it. */
    public function testResourceMetadataIsDeclared(): void
    {
        $client = $this->signedInWith(
            self::page([], 0),
            self::json(200, self::resourceRow('root')),
        );

        $client->management()->manifest()->apply(
            ManagementManifest::builder()
                ->resource('root', 'root', 'folder', metadata: ['owner' => 'platform'])
                ->build(),
        );

        self::assertSame(
            ['name' => 'root', 'resource_type' => 'folder', 'metadata' => ['owner' => 'platform']],
            $this->lastBody(),
        );
    }

    /** Group metadata reaches the create body when the declaration carries it. */
    public function testGroupMetadataIsDeclared(): void
    {
        $client = $this->signedInWith(
            self::page([], 0),
            self::json(200, self::groupRow('engineers')),
        );

        $client->management()->manifest()->apply(
            ManagementManifest::builder()
                ->group('g', 'engineers', 'Engineering', metadata: ['cost_centre' => 'r&d'])
                ->build(),
        );

        self::assertSame(
            ['description' => 'Engineering', 'name' => 'engineers', 'metadata' => ['cost_centre' => 'r&d']],
            $this->lastBody(),
        );
    }

    // -- fixtures ------------------------------------------------------------

    /**
     * @return array<string,mixed>
     */
    private static function roleRow(string $name, string $description = 'Read-only'): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'description' => $description,
            'id' => self::ORG_ID,
            'is_global' => false,
            'name' => $name,
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    /**
     * @return array<string,mixed>
     */
    private static function groupRow(string $name, string $description = 'Engineering'): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'description' => $description,
            'id' => self::ORG_ID,
            'metadata' => [],
            'name' => $name,
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    /**
     * @return array<string,mixed>
     */
    private static function resourceRow(string $name, string $type = 'folder'): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'id' => self::ORG_ID,
            'metadata' => [],
            'name' => $name,
            'resource_type' => $type,
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    /**
     * @return array<string,mixed>
     */
    private static function emailConfigOverride(): array
    {
        return ['inherit' => true];
    }
}
