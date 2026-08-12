<?php

declare(strict_types=1);

/**
 * examples/uma_resource_server.php — UMA 2.0 (CONTRACT.md §20), the RESOURCE-SERVER half
 * of the pair.
 *
 * The situation: this service holds invoices that belong to *users*, not to itself. When
 * someone asks for one, the useful answer is not just "no" — it is "not with what you're
 * carrying, and here is where to go and get better". That actionable refusal is what UMA
 * adds over plain RBAC.
 *
 * What this shows, in order:
 *
 *   1. Mint a PAT — a client-credentials token carrying `uma_protection`. §20.2 rule 1
 *      requires a *client* token: a minted ticket is bound to the `client_id` that
 *      minted it, so a user token cannot stand in.
 *   2. Register the resource this service guards. The returned id IS the AXIAM resource
 *      id — there is no parallel resource store to keep in sync.
 *   3. Build the {@see \Axiam\Sdk\AccessEnforcer} with a {@see \Axiam\Sdk\UmaChallenger},
 *      so a `#[RequireAccess]` denial carries `WWW-Authenticate: UMA` with a fresh
 *      ticket. Because both framework bridges delegate to that one enforcer, this covers
 *      Laravel and Symfony alike — see examples/laravel_app/routes.php and
 *      examples/symfony_app/services.yaml for how each wires the enforcer it builds.
 *
 * Its counterpart is examples/uma_client.php, which consumes that header.
 *
 * Run: php examples/uma_resource_server.php
 * (requires a reachable AXIAM server at AXIAM_BASE_URL and a confidential client — the
 * PAT is a client-credentials grant. A failure here is expected in a sandbox with no
 * live server: this example is illustrative, not a smoke test.)
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\AccessEnforcer;
use Axiam\Sdk\Attributes\RequireAccess;
use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Oidc\OidcClient;
use Axiam\Sdk\UmaChallenger;

function envOr(string $key, string $fallback): string
{
    $value = getenv($key);

    return $value === false ? $fallback : $value;
}

$client = new AxiamClient(
    baseUrl: envOr('AXIAM_BASE_URL', 'https://localhost:8443'),
    tenant: envOr('AXIAM_TENANT', 'acme'),
    oidcClientId: envOr('AXIAM_OIDC_CLIENT_ID', 'invoices-resource-server'),
    oidcClientSecret: envOr('AXIAM_OIDC_CLIENT_SECRET', 'resource-server-secret'),
    oidcTenantId: envOr('AXIAM_TENANT_ID', '00000000-0000-0000-0000-000000000000'),
);

// ---- 1. The PAT ----
//
// §20.2 rule 1: a client-credentials token carrying `uma_protection`. Not a user token,
// and not this client's ambient session — the SDK will not substitute either, and the
// Protection API would refuse them anyway.
$session = $client->loginClientCredentials(scope: OidcClient::UMA_PROTECTION_SCOPE);
$pat = $session->accessToken;

// ---- 2. Registration ----
//
// Registering the same name twice creates two resources, so a real service registers
// once at provisioning time and stores the id, or reconciles by listing. Inline here
// because it is the step that shows the returned id is the AXIAM resource id.
$registered = $client->umaRegisterResource(
    $pat,
    'invoice-7',
    'invoice',
    // The declared scopes are the allow-list the permission endpoint validates a ticket
    // request against. A resource registered with none can never appear in a ticket.
    ['invoices:read', 'invoices:approve'],
);

// ---- 3. The challenger ----
//
// `asUri` names where the caller should redeem the ticket. Read it from the discovery
// document rather than assembling it by hand — a deployment is free to move its
// endpoints, which is why §12.3 rule 6 forbids hardcoding them.
$configuration = $client->oidcDiscover();
$challenger = new UmaChallenger('invoices', $configuration->issuer, $pat, $client);

// The load-bearing third argument. Without it this is an ordinary §11 enforcer and a
// denial is a bare 403; with it, the denial carries a ticket and the caller can act on
// it. In a framework app this is the enforcer the service container hands to
// AxiamAccessMiddleware (Laravel) or AxiamAccessAttributeListener (Symfony).
$enforcer = new AccessEnforcer($client, null, $challenger);

printf("registered invoice-7 as %s\n", (string) $registered->id);

// What a guarded route does, without a framework in the way: the enforcer returns null
// on an allow, or the response to send on a refusal — and on a resource denial that
// response now carries the challenge.
$identity = [
    'user_id' => envOr('AXIAM_USER_ID', '11111111-1111-1111-1111-111111111111'),
    'tenant_id' => envOr('AXIAM_TENANT', 'acme'),
    'roles' => [],
];
$refusal = $enforcer->enforceAccess(
    $identity,
    new RequireAccess(action: 'invoices:read', resourceParam: 'id'),
    ['id' => (string) $registered->id],
);

if ($refusal === null) {
    // Reached only when the engine allowed it — including honouring any deny rule, which
    // UMA does not bypass: the ticket minted on a refusal asks for the same action this
    // check just evaluated, so the same grants and denies apply to whatever RPT comes
    // back.
    echo "allowed: the caller may read invoice-7\n";

    return;
}

printf("refused with %d\n", $refusal->getStatusCode());
// The header itself is NOT echoed: it carries a live ticket (§20.6), and a credential in
// a log line is a credential in a log line, 60-second life or not.
printf("challenge present: %s\n", $refusal->headers->has('WWW-Authenticate') ? 'yes' : 'no');
