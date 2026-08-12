<?php

declare(strict_types=1);

/**
 * examples/uma_client.php — UMA 2.0 (CONTRACT.md §20), the CLIENT half of the pair.
 *
 * Run examples/uma_resource_server.php first; this program talks to it.
 *
 * The flow, which is the whole reason UMA exists:
 *
 *   1. Ask for the invoice with the user's ordinary token. The resource server refuses —
 *      but its 403 carries `WWW-Authenticate: UMA` naming a ticket and an authorization
 *      server.
 *   2. PARSE the challenge. Note what happens next, and what does not: parsing performs
 *      no exchange (§20.3). The `as_uri` in that header is a host the *server we just
 *      failed against* chose; auto-redeeming would send the user's token wherever a 403
 *      pointed.
 *   3. Decide to trust it, then EXCHANGE the ticket for an RPT.
 *   4. Retry with the RPT.
 *
 * Step 3 is a decision, not a formality — this example makes it explicitly, by comparing
 * the nominated `as_uri` against the issuer this client already trusts, and refusing when
 * they differ.
 *
 * Run: php examples/uma_client.php
 * (illustrative: needs both a reachable AXIAM server and the resource-server example
 * running.)
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Oidc\UmaChallenge;
use GuzzleHttp\Client as HttpClient;
use GuzzleHttp\Exception\RequestException;

function envOr(string $key, string $fallback): string
{
    $value = getenv($key);

    return $value === false ? $fallback : $value;
}

$resourceServer = envOr('AXIAM_RESOURCE_SERVER', 'http://127.0.0.1:8081');
// The resource server printed this id when it registered.
$invoiceId = envOr('AXIAM_INVOICE_ID', '00000000-0000-0000-0000-000000000000');
// The requesting party's own token — what this program would normally send and, in step
// 3, the `claim_token` that names *who* is asking.
$userToken = envOr('AXIAM_USER_TOKEN', 'the-requesting-partys-access-token');

$url = $resourceServer . '/invoices/' . $invoiceId;
// Plain Guzzle, not the SDK client: the resource server is this program's own peer, not
// the AXIAM deployment.
$http = new HttpClient(['http_errors' => false]);

// The exchange is a token-endpoint grant, so this client is confidential.
$client = new AxiamClient(
    baseUrl: envOr('AXIAM_BASE_URL', 'https://localhost:8443'),
    tenant: envOr('AXIAM_TENANT', 'acme'),
    oidcClientId: envOr('AXIAM_OIDC_CLIENT_ID', 'invoices-client'),
    oidcClientSecret: envOr('AXIAM_OIDC_CLIENT_SECRET', 'client-secret'),
    oidcTenantId: envOr('AXIAM_TENANT_ID', '00000000-0000-0000-0000-000000000000'),
);

// ---- 1. The refusal ----
$refused = $http->get($url, ['headers' => ['Authorization' => 'Bearer ' . $userToken]]);
printf("first attempt: %d\n", $refused->getStatusCode());

$header = $refused->getHeaderLine('WWW-Authenticate');
if ($header === '') {
    // A resource server that refuses without a challenge is telling you it has nothing to
    // offer — there is no ticket to redeem, and retrying the same request would be
    // pointless.
    echo "no WWW-Authenticate header: this refusal is not actionable.\n";

    return;
}

// ---- 2. Parse, and only parse ----
$challenge = UmaChallenge::parse($header);
if ($challenge === null || $challenge->ticket === null) {
    echo "the challenge names no ticket; nothing to redeem.\n";

    return;
}

// Nothing from the challenge is echoed, and there are two separate reasons for that.
//
// The ticket, because §20.6 says so: its 60-second life does not make it harmless — for
// those 60 seconds it IS the credential that converts into an RPT, so a header in a log
// line is a live credential in a log line.
//
// The realm and as_uri, because they are strings a *remote* server chose. They are not
// secrets, but echoing attacker-controlled text into a terminal or a log file is its own
// small hazard (escape sequences, log forging), and an example is the last place to teach
// the habit. What matters here is the shape of the challenge, not its contents.
printf(
    "challenge parsed: as_uri present=%s, ticket present=yes\n",
    $challenge->asUri !== null ? 'yes' : 'no',
);

// ---- 3. The trust decision ----
//
// This is the step §20.3 exists to keep in the caller's hands. The SDK parsed the header
// and stopped; deciding whether to send the user's token to the host it names is this
// program's call, and it is a real one — a compromised or merely misconfigured resource
// server could nominate anything here.
$configuration = $client->oidcDiscover();
if ($challenge->asUri !== null
    && rtrim($challenge->asUri, '/') !== rtrim($configuration->issuer, '/')) {
    // Neither side of the comparison is echoed. The nominated value for the reasons
    // above; our own issuer because it is reached through a client constructed with a
    // client secret, and an example that prints values derived from that object is
    // teaching a habit that is fine here and wrong three refactors later. The decision
    // and its outcome are what a reader needs; the values are two lines away in a
    // debugger.
    echo "refusing to redeem: the challenge nominates an authorization server\n";
    echo "that is not the issuer this client already trusts.\n";
    echo "this is the auto-exchange §20.3 forbids, and why it forbids it.\n";

    return;
}

echo "as_uri matches the issuer we already trust; redeeming.\n";

// ---- 4. Exchange, then retry ----
//
// One request. A ticket is spent whether or not this succeeds (§20.2 rule 6), so on
// failure the next step is a *new* ticket — which means going back to step 1, not
// resending this one.
try {
    $rpt = $client->umaExchangeTicket($challenge->ticket, new Sensitive($userToken));
} catch (AxiamException $error) {
    printf("exchange failed: %s\n", $error::class);
    echo "the ticket is spent either way — request a new one by retrying.\n";

    return;
}

printf("got an RPT, valid for %ds\n", $rpt->expiresIn);

$allowed = $http->get($url, [
    'headers' => ['Authorization' => 'Bearer ' . $rpt->accessToken->reveal()],
]);
printf("second attempt: %d\n", $allowed->getStatusCode());
