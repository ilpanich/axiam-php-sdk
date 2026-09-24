<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Management;

use Axiam\Sdk\Management\Manifest\ManagementManifest;
use Axiam\Sdk\Management\Manifest\ManifestException;
use Axiam\Sdk\Management\Manifest\RoleBinding;
use GuzzleHttp\Psr7\Response;

/**
 * CONTRACT.md §27.6.1 addition 3 (contract 1.51): `service_accounts` in the manifest.
 *
 * Orchestrator review finding on C-6: this addition was declined — wrongly, per §8 rule 7
 * and §6's own "full" scope for this port — and is implemented here to match the
 * reference (`axiam-rust-sdk` `tests/manifest_additions_test.rs`).
 */
final class Contract151ManifestServiceAccountsTest extends ManagementTestCase
{
    private const ROLE_ID = '22222222-2222-4222-8222-222222222222';
    private const GROUP_ID = '33333333-3333-4333-8333-333333333333';
    private const SITE_ID = '55555555-5555-4555-8555-555555555555';

    /** @return array<string,mixed> */
    private static function roleRow(string $name = 'editor', string $id = self::ROLE_ID): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'description' => 'Editor role',
            'id' => $id,
            'is_global' => false,
            'name' => $name,
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    /** @return array<string,mixed> */
    private static function resourceRow(array $metadata = ['env' => 'prod']): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'id' => self::SITE_ID,
            'metadata' => $metadata,
            'name' => 'Site',
            'parent_id' => null,
            'resource_type' => 'site_type',
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    /** @return array<string,mixed> */
    private static function groupRow(): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'description' => 'desc',
            'id' => self::GROUP_ID,
            'metadata' => [],
            'name' => 'Engineering',
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    /** @return array<string,mixed> */
    private static function serviceAccountRow(
        string $name,
        string $id,
        ?string $description = null,
    ): array {
        $row = [
            'client_id' => 'client-' . $id,
            'created_at' => '2026-08-26T00:00:00Z',
            'id' => $id,
            'name' => $name,
            'status' => 'Active',
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
        if ($description !== null) {
            $row['description'] = $description;
        }

        return $row;
    }

    /** The `ServiceAccountCreatedResponse` a `create()` call returns — secret included. */
    private static function createdResponse(string $name, string $id, string $secret): Response
    {
        return self::json(200, [
            ...self::serviceAccountRow($name, $id),
            'client_secret' => $secret,
        ]);
    }

    /** @return array<string,mixed> */
    private static function assignmentRow(array $role, ?bool $inherit = null, ?string $resourceId = null): array
    {
        $row = ['role' => $role];
        if ($inherit !== null) {
            $row['inherit'] = $inherit;
        }
        if ($resourceId !== null) {
            $row['resource_id'] = $resourceId;
        }

        return $row;
    }

    // -- the one-time secret survives a later failure, and apply() never rotates -----

    public function testCreatedAccountSecretSurvivesALaterFailureAndIsNeverRotated(): void
    {
        $client = $this->signedInWith(
            self::page([], 0), // service_accounts read
            self::createdResponse('alpha-corp', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 's3cr3t-alpha'),
            new Response(500), // 'beta' create fails
        );

        $manifest = ManagementManifest::builder()
            ->serviceAccount('alpha', 'alpha-corp')
            ->serviceAccount('beta', 'beta-corp')
            ->build();

        $report = $client->management()->manifest()->apply($manifest);

        self::assertFalse($report->isComplete());
        self::assertSame('beta', $report->failed?->entity->key);

        $created = $report->createdServiceAccounts();
        self::assertCount(1, $created, 'the FIRST account\'s secret must survive the SECOND\'s failure');
        self::assertSame('alpha-corp', $created[0]->name);
        self::assertSame('s3cr3t-alpha', $created[0]->clientSecret->reveal());

        foreach ($this->requests as $request) {
            self::assertStringNotContainsString(
                'rotate-secret',
                (string) $request->getUri(),
                'apply() must never rotate a secret to reconcile anything',
            );
        }
    }

    /** I4 twin: the secret is reported exactly the same way on a fully SUCCESSFUL apply. */
    public function testCreatedAccountSecretIsAlsoReportedOnASuccessfulApply(): void
    {
        $client = $this->signedInWith(
            self::page([], 0),
            self::createdResponse('alpha-corp', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 's3cr3t-alpha'),
        );

        $report = $client->management()->manifest()->apply(
            ManagementManifest::builder()->serviceAccount('alpha', 'alpha-corp')->build(),
        );

        self::assertTrue($report->isComplete(), $report->failure?->getMessage() ?? '');
        self::assertCount(1, $report->createdServiceAccounts());
        self::assertSame('s3cr3t-alpha', $report->createdServiceAccounts()[0]->clientSecret->reveal());
    }

    // -- an ambiguous name fails plan before any write -----------------------------

    /**
     * The server does not keep a service account's `name` unique. `plan()` (which
     * issues no writes at all) refuses rather than guessing which of the two existing
     * accounts the manifest describes.
     */
    public function testAnAmbiguousServiceAccountNameFailsPlanBeforeAnyWrite(): void
    {
        $client = $this->signedInWith(
            self::page([
                self::serviceAccountRow('shared-name', '11111111-1111-4111-9111-111111111111'),
                self::serviceAccountRow('shared-name', '22222222-2222-4222-9222-222222222222'),
            ], 2),
        );

        try {
            $client->management()->manifest()->plan(
                ManagementManifest::builder()->serviceAccount('svc', 'shared-name')->build(),
            );
            self::fail('expected a ManifestException');
        } catch (ManifestException $e) {
            self::assertStringContainsString('ambiguous', $e->getMessage());
        }

        foreach ($this->sentMethods() as $method) {
            self::assertSame('GET', $method, 'plan() must never write, ambiguous or not');
        }
    }

    /** I4 twin: a single match is not ambiguous — reconciliation proceeds normally. */
    public function testASingleMatchingNameIsNotAmbiguous(): void
    {
        $client = $this->signedInWith(
            self::page([self::serviceAccountRow('solo-corp', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa')], 1),
        );

        $plan = $client->management()->manifest()->plan(
            ManagementManifest::builder()->serviceAccount('svc', 'solo-corp')->build(),
        );

        self::assertTrue($plan->isConverged());
    }

    // -- description is the only field an Update reconciles -------------------------

    public function testOnlyAStatedDescriptionIsReconciled(): void
    {
        $client = $this->signedInWith(
            self::page([self::serviceAccountRow('fleet', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'old desc')], 1),
            self::json(200, self::serviceAccountRow('fleet', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'new desc')),
        );

        $report = $client->management()->manifest()->apply(
            ManagementManifest::builder()->serviceAccount('svc', 'fleet', description: 'new desc')->build(),
        );

        self::assertTrue($report->isComplete(), $report->failure?->getMessage() ?? '');
        self::assertCount(1, $report->applied);

        $body = json_decode((string) $this->lastRequest()->getBody(), true);
        self::assertSame(['description' => 'new desc'], $body, 'only description may reach the wire');
        self::assertSame('PUT', $this->lastRequest()->getMethod());
    }

    /** I4 twin: an UNSTATED description sends no update at all, however the server's differs. */
    public function testUnstatedDescriptionSendsNoUpdate(): void
    {
        $client = $this->signedInWith(
            self::page([self::serviceAccountRow('fleet', 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', 'server desc')], 1),
        );

        $report = $client->management()->manifest()->apply(
            ManagementManifest::builder()->serviceAccount('svc', 'fleet')->build(),
        );

        self::assertTrue($report->isComplete(), $report->failure?->getMessage() ?? '');
        self::assertSame([], $report->applied, 'an unstated field is silent, not a drift');
        foreach ($this->sentMethods() as $method) {
            self::assertSame('GET', $method);
        }
    }

    // -- apply-then-plan convergence over all three additions together --------------

    /**
     * The combined idempotence proof the orchestrator finding asked for: a resource's
     * `metadata`, a group's resource-scoped role binding, and a service account, all in
     * one manifest.
     *
     * `plan()` alone is not the whole story for the BINDING: {@see
     * \Axiam\Sdk\Tests\Management\Contract151ManifestGrantsAndBindingsTest::testPlanStillTreatsGrantsAndRolesAsEdgesNotFieldDrift()}
     * already establishes that `plan()` never treats an entity's edges as field drift —
     * by design, so a role added to the manifest for an otherwise-unchanged group still
     * gets granted (§13 row 17 defect a's fix). So this test proves convergence the way
     * that guarantees actually compose: `plan()` for the three ENTITIES' own fields
     * (`isConverged()`), and a SECOND `apply()` for the BINDING (`applied === []`, reads
     * only) — together, "nothing left to do" end to end.
     */
    public function testApplyThenPlanConvergesOverMetadataAScopedBindingAndAServiceAccount(): void
    {
        $manifest = ManagementManifest::builder()
            ->resource('site', 'Site', 'site_type', metadata: ['env' => 'prod'])
            ->role('editor', 'editor', 'Editor role')
            ->group('eng', 'Engineering', 'desc', roleKeys: [RoleBinding::at('editor', 'site')])
            ->serviceAccount('fleet', 'device-fleet')
            ->build();

        $client = $this->signedInWith(
            // -- first apply(): everything is created --
            self::page([], 0), // resources
            self::page([], 0), // roles
            self::page([], 0), // groups
            self::page([], 0), // service_accounts
            self::json(200, self::resourceRow()),                              // create resource
            self::json(200, self::roleRow()),                                  // create role
            self::json(200, self::groupRow()),                                 // create group
            self::createdResponse('device-fleet', 'ffffffff-ffff-4fff-8fff-ffffffffffff', 'fleet-secret'),
            self::json(200, []),                                               // groups()->listRoles: none yet
            new Response(204),                                                 // assign

            // -- plan(): every entity now matches exactly --
            self::page([self::resourceRow()], 1),
            self::page([self::roleRow()], 1),
            self::page([self::groupRow()], 1),
            self::page([self::serviceAccountRow('device-fleet', 'ffffffff-ffff-4fff-8fff-ffffffffffff')], 1),

            // -- second apply(): entities unchanged, binding already reconciled --
            self::page([self::resourceRow()], 1),
            self::page([self::roleRow()], 1),
            self::page([self::groupRow()], 1),
            self::page([self::serviceAccountRow('device-fleet', 'ffffffff-ffff-4fff-8fff-ffffffffffff')], 1),
            self::json(200, [self::assignmentRow(self::roleRow(), inherit: true, resourceId: self::SITE_ID)]),
        );

        $firstReport = $client->management()->manifest()->apply($manifest);
        self::assertTrue($firstReport->isComplete(), $firstReport->failure?->getMessage() ?? '');
        self::assertCount(5, $firstReport->applied, '4 entity creates + 1 binding');
        self::assertCount(1, $firstReport->createdServiceAccounts());

        $plan = $client->management()->manifest()->plan($manifest);
        self::assertTrue($plan->isConverged(), 'every entity\'s OWN fields must already match');

        $beforeSecondApply = \count($this->requests);
        $secondReport = $client->management()->manifest()->apply($manifest);
        self::assertTrue($secondReport->isComplete(), $secondReport->failure?->getMessage() ?? '');
        self::assertSame([], $secondReport->applied, 'the binding is already reconciled -- nothing left to send');
        foreach (\array_slice($this->requests, $beforeSecondApply) as $request) {
            self::assertSame(
                'GET',
                $request->getMethod(),
                'a fully converged manifest issues reads only, on EVERY subsequent run',
            );
        }
    }
}
