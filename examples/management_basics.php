<?php

declare(strict_types=1);

/**
 * examples/management_basics.php — the CONTRACT.md §27 management surface: namespace
 * handles, paging, sparse updates, and the three error classifications.
 *
 * §27.2 gives the surface namespace HANDLES rather than 146 flat methods:
 * `$client->management()->users()->listItems()`. Every handle goes through one
 * transport, so §3 CSRF, the §4 cookie jar, the §5 tenant header, §6 TLS, §16 retry and
 * §19 telemetry apply to all 146 operations without any of them opting in (§27.8).
 *
 * Run: php examples/management_basics.php
 * (requires a reachable AXIAM server at AXIAM_BASE_URL and an administrator account —
 * a failure here is expected in a sandbox with no live server; this example is
 * illustrative and compile-checked, not a live-server smoke test.)
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Management\ConflictError;
use Axiam\Sdk\Management\ManagementTransport;
use Axiam\Sdk\Management\Models;
use Axiam\Sdk\Management\NotFoundError;
use Axiam\Sdk\Management\Page;
use Axiam\Sdk\Management\PageRequest;
use Axiam\Sdk\Management\ValidationError;

/** Reads an environment variable, falling back to a placeholder for illustration. */
function env(string $key, string $fallback): string
{
    $value = getenv($key);

    return $value === false || $value === '' ? $fallback : $value;
}

$client = new AxiamClient(
    env('AXIAM_BASE_URL', 'https://axiam.example.com'),
    env('AXIAM_TENANT', 'acme'),
    orgId: env('AXIAM_ORG_ID', '11111111-1111-4111-8111-111111111111'),
    oidcTenantId: env('AXIAM_TENANT_ID', '22222222-2222-4222-8222-222222222222'),
);

try {
    // §27.4 rule 1: without a session, a management call never reaches the server.
    $client->login(env('AXIAM_ADMIN', 'admin@example.com'), env('AXIAM_PASSWORD', 'secret'));

    $management = $client->management();

    // ---- one page ---------------------------------------------------------
    //
    // §27.4 rule 4: `total` is the SERVER's count across all pages. It is not
    // count($page), and treating the two as interchangeable is how a management script
    // silently processes the first fifty of four hundred users.
    $page = $management->users()->listItems(new PageRequest(0, 50));
    printf("users on this page: %d, users in total: %d\n", count($page), $page->total);

    // ---- every page -------------------------------------------------------
    //
    // The walk stops on the first EMPTY page, never on a short one: a server may return
    // fewer rows than asked for without the collection having ended.
    $users = $management->users();
    foreach (ManagementTransport::walk(
        static fn (PageRequest $p): Page => $users->listItems($p),
    ) as $user) {
        printf("  %s\n", $user->id);
    }

    // ---- a sparse update --------------------------------------------------
    //
    // §27.4 rule 5: name the fields you mean to change and nothing else. What you leave
    // unset is OMITTED from the request, not sent as null — on a sparse update those two
    // say opposite things, and only omission means "leave it alone".
    $management->users()->update(
        env('AXIAM_USER_ID', '33333333-3333-4333-8333-333333333333'),
        new Models\UpdateUserRequest(status: Models\UserStatus::Locked),
    );

    // ---- scoping one handle ------------------------------------------------
    //
    // §27.4 rule 3: `{org_id}` and `{tenant_id}` come from the client. A handle can be
    // re-scoped for one call, and doing so returns a COPY — the handle you called it on
    // still points where it did.
    $otherOrg = $management->caCertificates()->inOrg(env('AXIAM_OTHER_ORG', $client->resolvedOrgId() ?? ''));
    printf("CA certificates in the other org: %d\n", count($otherOrg->listItems()));
} catch (NotFoundError $e) {
    // §27.4 rule 7: 404 is an AuthzError sub-type, and deliberately so. On a multi-tenant
    // surface the server answers 404 for another tenant's object PRECISELY SO a probing
    // caller cannot tell "does not exist" from "exists, not yours".
    fprintf(STDERR, "not found (or not visible to you): %s\n", $e->getMessage());
} catch (ConflictError $e) {
    // 409 — also an AuthzError sub-type, keeping the mapping §2 already gave it.
    fprintf(STDERR, "conflict: %s\n", $e->getMessage());
} catch (ValidationError $e) {
    // 400/422 — a NetworkError sub-type, inherited from §2's 400 row. It carries the
    // server's per-field complaints so you can point at the offending input.
    fprintf(STDERR, "rejected: %s\n", $e->getMessage());
    foreach ($e->fields as $field) {
        fprintf(STDERR, "  %s: %s\n", $field->field, $field->message);
    }
} catch (AxiamException $e) {
    fprintf(STDERR, "management call failed: %s\n", $e->getMessage());
} finally {
    $client->close();
}
