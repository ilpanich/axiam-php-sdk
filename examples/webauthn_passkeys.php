<?php

declare(strict_types=1);

/**
 * examples/webauthn_passkeys.php — CONTRACT.md §24, WebAuthn / passkeys.
 *
 * PHP runs on a server, which has no authenticator, so §24.6b's linked-API helper is
 * deliberately absent from this SDK: rule 2 forbids emulating one in software, and a
 * "credential" held in process memory is not a second factor. What is here is the half
 * that talks to AXIAM, plus §24.6a's JSON bridge — the seam that carries the challenge out
 * to a browser and the response back, which is what makes "no platform ceremony" a
 * statement about convenience rather than capability.
 *
 * Uses ONLY the public `AxiamClient` API.
 *
 * Run: php examples/webauthn_passkeys.php
 * (illustrative/compilable — a failure here is expected in a sandbox with no live server.)
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Webauthn\WebauthnFailure;

function envOr(string $key, string $fallback): string
{
    $value = getenv($key);

    return $value === false ? $fallback : $value;
}

$client = new AxiamClient(
    baseUrl: envOr('AXIAM_BASE_URL', 'https://localhost:8443'),
    tenant: envOr('AXIAM_TENANT', 'acme'),
    orgSlug: envOr('AXIAM_ORG_SLUG', 'acme'),
);

// ---------------------------------------------------------------------------
// 1. Enrolment — requires a session (§24.1)
// ---------------------------------------------------------------------------

echo "== enrolling a passkey ==\n";
try {
    $client->login(envOr('AXIAM_EMAIL', 'alice@acme.test'), envOr('AXIAM_PASSWORD', 'pw'));

    // The server chooses every option: the challenge, the RP id, the algorithms, the
    // attestation policy, whether a resident key is required. This SDK defaults nothing
    // and validates nothing (§24.0) — a client that "helpfully" filled in a missing field
    // would be overriding a policy decision it cannot see.
    $challenge = $client->webauthnRegisterStart();

    // §24.6a rule 1: this string is what the browser half needs. Send it down as-is,
    // alongside the state token, and take the response JSON back verbatim.
    echo '  options for the browser: ' . $challenge->requestJson() . "\n";

    $authenticatorResponse = <<<'JSON'
        {"id":"Y3JlZC1pZA","rawId":"Y3JlZC1pZA",
         "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
                     "attestationObject":"o2NmbXRkbm9uZQ"},
         "type":"public-key","clientExtensionResults":{}}
        JSON;

    $credential = $client->webauthnRegisterFinish(
        $challenge->stateToken,
        "Alice's laptop",
        $authenticatorResponse,
    );
    echo "  enrolled: {$credential->name} ({$credential->credentialType}), id {$credential->id}\n";
} catch (AuthzError $e) {
    // §24.4 rule 1: a 403 here is the tenant's ATTESTATION POLICY rejecting this
    // particular authenticator, and the server's message is the only place that says which
    // one would be accepted. Printing a generic "forbidden" strands the person holding the
    // key.
    echo '  policy refused this authenticator: ' . $e->getMessage() . "\n";
} catch (AuthError $e) {
    echo '  not signed in — passkey enrolment needs a session: ' . $e->getMessage() . "\n";
} catch (AxiamException $e) {
    // §24.4 rule 2: a 503 from register/start means the tenant's attestation policy needs
    // FIDO metadata the server cannot reach. That is a CONFIGURATION state, not a
    // transient one — the SDK does not retry it, and neither should this loop.
    echo '  enrolment unavailable: ' . $e->getMessage() . "\n";
}

// ---------------------------------------------------------------------------
// 2. Sign-in — the discoverable ceremony (§24.1)
// ---------------------------------------------------------------------------

echo "== signing in with a passkey ==\n";
try {
    // No username. The authenticator already knows which accounts it holds for this
    // relying party, so the workspace — not the user — is what the server needs, and it
    // comes from the client's own configuration when the argument is null.
    $challenge = $client->webauthnDiscoverableStart();

    $assertion = <<<'JSON'
        {"id":"Y3JlZC1pZA","rawId":"Y3JlZC1pZA",
         "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
                     "authenticatorData":"YXV0aC1kYXRh","signature":"c2ln",
                     "userHandle":"dXNlci1oYW5kbGU"},
         "type":"public-key","clientExtensionResults":{}}
        JSON;

    $result = $client->webauthnDiscoverableFinish($challenge->stateToken, $assertion);

    // As of contract 1.28 the server sets the session cookie triple on this response as
    // well, so the client is signed in for every cookie-driven call that follows. Before
    // that fix a completed ceremony left the caller with no session at all.
    echo "  signed in, session {$result->sessionId} valid for {$result->expiresIn}s\n";
} catch (AxiamException $e) {
    echo '  the ceremony did not complete: ' . $e->getMessage() . "\n";
}

// ---------------------------------------------------------------------------
// 3. The browser half — what the §24.6a bridge is for
// ---------------------------------------------------------------------------

echo <<<'JS'
    == the browser half ==
      // Your PHP endpoint sends requestJson down; the browser hands it straight to the
      // platform, and hands the result straight back.
      const options = PublicKeyCredential.parseCreationOptionsFromJSON(requestJson);
      const credential = await navigator.credentials.create({ publicKey: options });
      await fetch('/passkeys/finish', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        // Verbatim: nothing destructured, nothing re-encoded (§24.0).
        body: JSON.stringify({ stateToken, response: credential.toJSON() }),
      });

    JS;

// ---------------------------------------------------------------------------
// 4. Saying something useful when the ceremony fails (§24.6b rule 5)
// ---------------------------------------------------------------------------

echo "== classifying a ceremony failure ==\n";

// The browser catches a DOMException and relays its name. Translating that once beats
// translating it in every caller; this SDK links no platform, so it classifies whatever
// name arrives.
$outcome = WebauthnFailure::classify('InvalidStateError');
echo "  {$outcome->value}: {$outcome->message()}\n";

// The distinction that matters: AlreadyRegistered is the only one whose remedy is "use a
// different device" rather than "try again".
assert($outcome === WebauthnFailure::AlreadyRegistered);

// And the one that must never accuse the user. Cancelled covers both an explicit refusal
// and a silent timeout, because the spec refuses to distinguish them — telling a website
// which happened would leak whether an authenticator was present.
echo '  ' . WebauthnFailure::classify('NotAllowedError')->message() . "\n";
