<?php

declare(strict_types=1);

/**
 * examples/management_manifest.php — the CONTRACT.md §27.6 declarative layer: describe
 * the tenant you want, plan the difference, apply it.
 *
 * The imperative surface is fine for one change. It is a poor way to describe a TENANT,
 * because re-running it either fails on the second run or makes you hand-write "does this
 * exist already?" for every object. A manifest is re-runnable by construction: apply it
 * twice and the second run sends nothing.
 *
 * Both ways of writing one are shown. The fluent builder is here; the attribute form is
 * in examples/management_manifest_attributes.php.
 *
 * Run: php examples/management_manifest.php
 * (requires a reachable AXIAM server and an administrator account — a failure here is
 * expected in a sandbox with no live server.)
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Management\Manifest\ManagementManifest;
use Axiam\Sdk\Management\Manifest\ManifestException;

/** Reads an environment variable, falling back to a placeholder for illustration. */
function env(string $key, string $fallback): string
{
    $value = getenv($key);

    return $value === false || $value === '' ? $fallback : $value;
}

// The desired shape of the tenant. Nothing here talks to a server: this is a
// description, and describing a tenant is not the same act as changing one.
//
// Note the `deny` grant. AXIAM's RBAC is DENY-OVERRIDE, not most-specific-wins: an
// explicit deny beats every allow, at any depth of the resource hierarchy and at equal
// specificity. Writing one here is a strong statement — no narrower allow anywhere will
// reverse it — which is exactly why contractors cannot read the payroll folder no matter
// what else they are granted.
$manifest = ManagementManifest::builder()
    ->resource('root', 'acme', 'organization')
    ->resource('payroll', 'payroll', 'folder', parentKey: 'root')
    ->permission('docs.read', 'documents:read', 'Read documents')
    ->permission('docs.write', 'documents:write', 'Create and edit documents')
    ->role('auditor', 'auditor', 'Read-only access for audit', grants: [
        'docs.read' => 'allow',
    ])
    ->role('contractor', 'contractor', 'External contributor', grants: [
        'docs.read' => 'allow',
        'docs.write' => 'deny',
    ])
    ->group('auditors', 'auditors', 'Internal audit', roleKeys: ['auditor'])
    ->group('externals', 'externals', 'Contractors', roleKeys: ['contractor'])
    ->build();

$client = new AxiamClient(
    env('AXIAM_BASE_URL', 'https://axiam.example.com'),
    env('AXIAM_TENANT', 'acme'),
    orgId: env('AXIAM_ORG_ID', '11111111-1111-4111-8111-111111111111'),
    oidcTenantId: env('AXIAM_TENANT_ID', '22222222-2222-4222-8222-222222222222'),
);

try {
    $client->login(env('AXIAM_ADMIN', 'admin@example.com'), env('AXIAM_PASSWORD', 'secret'));
    $manifestApi = $client->management()->manifest();

    // ---- plan --------------------------------------------------------------
    //
    // §27.6: plan() WRITES NOTHING. It reads the tenant and reports the difference, so it
    // is safe against production, safe in CI, and safe on a schedule. Print it and let a
    // human approve before anything changes.
    $plan = $manifestApi->plan($manifest);

    if ($plan->isConverged()) {
        echo "tenant already matches the manifest; nothing to do\n";

        return;
    }

    echo "planned changes:\n";
    foreach ($plan->describe() as $line) {
        printf("  %s\n", $line);
    }

    if (env('AXIAM_APPLY', 'no') !== 'yes') {
        echo "\n(set AXIAM_APPLY=yes to apply)\n";

        return;
    }

    // ---- apply -------------------------------------------------------------
    //
    // §27.7: apply STOPS AT THE FIRST FAILURE and DOES NOT ROLL BACK. That is a feature.
    // A partial apply against a live IAM tenant is a state an operator must be able to
    // inspect and resume from, and an automatic rollback would fire a second wave of
    // writes at exactly the moment the server is telling you something is wrong.
    //
    // The report is the recovery tool: what landed, what failed, what was never tried.
    $report = $manifestApi->apply($manifest);

    echo "\napply:\n";
    foreach ($report->describe() as $line) {
        printf("  %s\n", $line);
    }

    if (!$report->isComplete()) {
        // Fix the cause and re-run: the changes that already landed will plan as
        // Unchanged next time, so a resumed apply picks up where this one stopped.
        exit(1);
    }
} catch (ManifestException $e) {
    // Refused BEFORE any request: a dangling reference, a cycle, or a duplicate key.
    // Discovering that halfway through an apply — with no rollback — is strictly worse.
    fprintf(STDERR, "manifest is not applicable: %s\n", $e->getMessage());
    exit(2);
} catch (AxiamException $e) {
    fprintf(STDERR, "apply failed: %s\n", $e->getMessage());
    exit(2);
} finally {
    $client->close();
}
