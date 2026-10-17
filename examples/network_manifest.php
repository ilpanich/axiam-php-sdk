<?php

declare(strict_types=1);

/**
 * examples/network_manifest.php — the `network` namespace in a manifest (CONTRACT.md §27.6.2,
 * contract 1.62): a tenant's `Session-Timeout` cap, its network segments and the RADIUS reply
 * profile of each, declared once, planned, then applied.
 *
 * A segment is identified by site + kind + name (`kind` is the wire spelling, `access` or
 * `quarantine`), a profile by its segment, and the policy is a singleton. The policy is
 * written first, so a profile above the OLD cap works in the same apply as the cap that
 * raises it; segments follow, then profiles.
 *
 * `plan()` writes nothing. `apply()` sends version-conditional `replace*` bodies built from the
 * read, never retries one, and stops at the first failure — a `409` carries its `reason_code`.
 * The namespace is human-only: run it as an administrator, not as a service account.
 *
 * Run: php examples/network_manifest.php
 * (requires a reachable AXIAM server — a failure here is expected in a sandbox with none.)
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Management\ConflictError;
use Axiam\Sdk\Management\JsonNull;
use Axiam\Sdk\Management\Manifest\ManagementManifest;
use Axiam\Sdk\Management\Manifest\ManifestException;

/** Reads an environment variable, falling back to a placeholder for illustration. */
function env(string $key, string $fallback): string
{
    $value = getenv($key);

    return $value === false || $value === '' ? $fallback : $value;
}

$manifest = ManagementManifest::builder()
    // The cap. A profile's timeout is checked against it at the write, hence "first".
    ->networkPolicy(7200)
    // Two access segments at one site; the lowest rank is placed first.
    ->networkSegment('staff', 'hq', 'access', 'staff', 20, rank: 1, filterIds: ['staff-in', 'staff-out'])
    ->networkSegment('guest', 'hq', 'access', 'guest', 30, rank: 2)
    // Where a device that fails its checks lands. A quarantine segment has no rank.
    ->networkSegment('jail', 'hq', 'quarantine', 'jail', 99, enabled: true)
    // The reply each segment's devices are given. `JsonNull::Null` states a member as NONE.
    ->networkProfile('staff', 3600, idleTimeoutSecs: 600, filterId: 'staff-in')
    ->networkProfile('guest', 900, filterId: JsonNull::Null)
    ->networkProfile('jail', 300)
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

    // Judged on the READ: a profile whose stored timeout is above a lowered cap reads as the
    // cap, so stating the cap is NoChange and stating more is an Update the server refuses.
    $plan = $manifestApi->plan($manifest);
    if ($plan->isConverged()) {
        echo "the network already matches the manifest; nothing to do\n";

        return;
    }
    foreach ($plan->describe() as $line) {
        printf("  %s\n", $line);
    }
    if (env('AXIAM_APPLY', 'no') !== 'yes') {
        echo "\n(set AXIAM_APPLY=yes to apply)\n";

        return;
    }

    $report = $manifestApi->apply($manifest);
    foreach ($report->describe() as $line) {
        printf("  %s\n", $line);
    }
    if (!$report->isComplete()) {
        // A 409 is that action's failure: another administrator wrote after plan() read.
        // Branch on the reason code, never on the message — then run apply() again, which re-reads.
        if ($report->failure instanceof ConflictError) {
            fprintf(STDERR, "conflict: %s\n", $report->failureReasonCode() ?? 'no reason code');
        }
        exit(1);
    }
} catch (ManifestException $e) {
    // Refused BEFORE any request: a duplicate natural key, a profile naming no segment, a
    // repeated Filter-Id, a kind that is not access or quarantine.
    fprintf(STDERR, "manifest is not applicable: %s\n", $e->getMessage());
    exit(2);
} catch (AxiamException $e) {
    fprintf(STDERR, "failed: %s\n", $e->getMessage());
    exit(2);
} finally {
    $client->close();
}
