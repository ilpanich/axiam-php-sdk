<?php

declare(strict_types=1);

/**
 * examples/telemetry_hook.php — telemetry hooks (CONTRACT.md §19): wiring metrics to an
 * AXIAM client WITHOUT this package depending on any metrics library.
 *
 * Demonstrates the whole D5 surface in one run: §16 bounded read-only retry, §17 the
 * opt-in decision memo and its clamp, §18 `close()`, and §19 the hook itself. The sink
 * aggregates in-process, so the example runs with no extra dependencies and needs no
 * reachable server — the failure path emits exactly the same events as the success path,
 * which is the property that makes the telemetry worth having.
 *
 * Run: php examples/telemetry_hook.php
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Core\ConfigClampedEvent;
use Axiam\Sdk\Core\RefreshEvent;
use Axiam\Sdk\Core\RequestEndEvent;
use Axiam\Sdk\Core\RetryEvent;
use Axiam\Sdk\Core\TelemetryEvent;

function envOr(string $key, string $fallback): string
{
    $value = getenv($key);

    return $value === false ? $fallback : $value;
}

/**
 * In-process aggregation. Replace this body — and nothing else — to publish to a real
 * backend; the mapping is at the bottom of this file.
 *
 * @var array<string, array{count: int, totalMs: float}> $requests
 */
$requests = [];
/** @var array<string, int> $retries */
$retries = [];
$refreshes = 0;

$sink = static function (TelemetryEvent $event) use (&$requests, &$retries, &$refreshes): void {
    // One pair per ATTEMPT, not per logical call (§19.2 rule 5), so counting these gives
    // the real number of wire calls — including the ones a retry made on your behalf.
    //
    // RequestStartEvent is deliberately not handled: RequestEndEvent carries the same
    // identity plus the outcome, so counting both double-counts.
    if ($event instanceof RequestEndEvent) {
        $key = $event->operation . '/' . $event->outcome;
        $requests[$key] ??= ['count' => 0, 'totalMs' => 0.0];
        $requests[$key]['count']++;
        $requests[$key]['totalMs'] += $event->durationMs;

        return;
    }

    // §16.5 — the reason this event exists. A retried-then-succeeded operation is
    // otherwise invisible: the caller sees a slow success and no signal that the server
    // is failing. Alert on THIS rate, not on the error rate, or a degrading server looks
    // healthy right up until the retries stop being enough.
    if ($event instanceof RetryEvent) {
        $retries[$event->operation] = ($retries[$event->operation] ?? 0) + 1;

        return;
    }

    if ($event instanceof RefreshEvent) {
        $refreshes++;

        return;
    }

    // §19.2 rule 6 — fired at most once per clamped setting, at construction. Worth
    // logging loudly rather than counting: it means a value in your configuration is not
    // the value in force, and the gap is silent everywhere else.
    if ($event instanceof ConfigClampedEvent) {
        fwrite(
            STDERR,
            sprintf(
                "WARN: %s=%s was clamped to %s (%s)\n",
                $event->setting,
                $event->requested,
                $event->effective,
                $event->contractReference,
            ),
        );
    }
};

$client = new AxiamClient(
    baseUrl: envOr('AXIAM_BASE_URL', 'https://127.0.0.1:59999'),
    tenant: envOr('AXIAM_TENANT', 'acme'),
    restOnly: true,
    // Deliberately above the §17.1 rule 2 ceiling, so the run demonstrates the
    // ConfigClampedEvent warning above rather than leaving it theoretical.
    decisionMemoTtlMs: 60_000.0,
    telemetryHook: $sink,
);

try {
    $allowed = $client->checkAccess('documents:read', envOr('AXIAM_RESOURCE_ID', 'doc-1'));
    printf("allowed=%s\n", $allowed ? 'true' : 'false');
} catch (AxiamException $e) {
    // Expected without a reachable server. The point of this example is the telemetry
    // below, which is emitted on this path exactly as it would be on the success path.
    printf("check failed: %s\n", $e->getMessage());
}

echo "--- telemetry ---\n";
ksort($requests);
foreach ($requests as $key => $stat) {
    printf(
        "  %s: count=%d mean=%.0fms\n",
        $key,
        $stat['count'],
        $stat['count'] === 0 ? 0.0 : $stat['totalMs'] / $stat['count'],
    );
}
if ($retries === []) {
    echo "  retries: (none)\n";
}
ksort($retries);
foreach ($retries as $operation => $count) {
    printf("  retries %s: %d\n", $operation, $count);
}
printf("  refreshes: %d\n", $refreshes);

// §18: releases the transport and clears the session state. It issues NO request — it
// does not log out, because the server-side session deliberately outlives the client
// object. Idempotent, and any call afterwards throws rather than silently reconnecting.
$client->close();

/*
 * Mapping onto a real backend — replace $sink's body, nothing else:
 *
 *   RequestEndEvent    → histogram "axiam.request.duration"
 *                        labels: operation, pathTemplate, status, outcome, attempt
 *   RetryEvent         → counter   "axiam.request.retries"   labels: operation
 *   RefreshEvent       → counter   "axiam.token.refresh"     labels: role
 *   ConfigClampedEvent → a log line at WARNING, not a metric: it fires once at
 *                        construction and its whole value is being READ.
 *
 * Label with pathTemplate, never with the request URL: a metric label carrying a UUID is
 * a cardinality bomb. The hook runs inline on the calling path, so it must not block —
 * every mature metrics library already buffers, which is why §19.2 rule 4 leaves that
 * choice to you rather than making it here.
 */
