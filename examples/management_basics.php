<?php

declare(strict_types=1);

/**
 * examples/management_basics.php — the CONTRACT.md §27 management surface: namespace
 * handles, paging, searching, sparse updates, open enums, and the three error
 * classifications.
 *
 * §27.2 gives the surface namespace HANDLES rather than 147 flat methods:
 * `$client->management()->users()->listItems()`. Every handle goes through one
 * transport, so §3 CSRF, the §4 cookie jar, the §5 tenant header, §6 TLS, §16 retry and
 * §19 telemetry apply to all 147 operations without any of them opting in (§27.8).
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

    // ---- searching a list --------------------------------------------------
    //
    // §27.4 rule 4: the term rides on the PAGE REQUEST, not as a third argument on each
    // of the twenty generated list methods. That is what lets the walk below carry it —
    // a per-method argument has nowhere to live between one request and the next, and a
    // walk that filtered only its first request would return the matches followed by the
    // unfiltered tail.
    //
    // The server does the matching, case-insensitively, against the identifying fields of
    // whatever is being listed — a name or username, plus the record id, so a UUID pasted
    // out of a log line finds its row. `total` then counts MATCHES, not rows, which is
    // what lets a pager built on it show a page count belonging to the set it is paging.
    $matches = $management->users()->listItems(new PageRequest(0, 50, 'ada'));
    printf("matching users on this page: %d, matches in total: %d\n", count($matches), $matches->total);

    // The whole filtered set. Passing the term to the FIRST request is enough: `next()`
    // carries it, so every request of the walk asks the same question.
    foreach (ManagementTransport::walk(
        static fn (PageRequest $p): Page => $users->listItems($p),
        new PageRequest(0, 50, 'ada'),
    ) as $match) {
        printf("  match: %s\n", $match->id);
    }

    // An empty or whitespace-only term is the SAME request as none: no `search` parameter
    // is sent at all. A search box that fires on every keystroke sends one the moment it
    // is cleared, and "rows containing the empty string" is a different question from
    // "all rows".
    $everyone = $management->users()->listItems(new PageRequest(0, 50, '   '));
    printf("unfiltered after clearing the box: %d\n", $everyone->total);

    // ---- open enums, and the list-only projection (§27.11) -----------------
    //
    // Rule 1: a value this SDK's copy of the spec does not list decodes to `Unknown`
    // rather than throwing. Throwing would fail the WHOLE response, so one field of one
    // tenant would take down the page it was on — including the tenants you did ask for.
    // `Unknown` is never confused with a known case, so a `match` needs an arm for it.
    foreach ($management->tenants()->listItems() as $tenant) {
        printf("  %s: %s\n", $tenant->slug, match ($tenant->kind) {
            Models\TenantKind::Organization => 'the organization\'s own scope',
            Models\TenantKind::Standard, null => 'an ordinary tenant',
            Models\TenantKind::Unknown => 'a kind this SDK predates — upgrade to name it',
        });
    }

    // Rule 4: `boundServiceAccountId` is a PROJECTION, not a property of the certificate.
    // The server resolves it for a whole page in one query, so `listItems()` populates it
    // and `get()` leaves it null. Null there means "this read does not carry it", not
    // "there is nothing bound" — and this SDK does not go and fetch it, because a `get`
    // that silently costs two round trips is the thing §27.4 rule 3 forbids elsewhere.
    foreach ($management->certificates()->listItems() as $certificate) {
        printf(
            "  %s -> %s\n",
            $certificate->subject,
            $certificate->boundServiceAccountId ?? 'not bound to a service account',
        );
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
