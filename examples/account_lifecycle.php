<?php

declare(strict_types=1);

/**
 * examples/account_lifecycle.php — CONTRACT.md §25, account lifecycle and MFA enrolment:
 * the calls a user makes about their own account, none of which is administration.
 *
 * Five demonstrations:
 *   1. Forced enrolment — the third `login()` outcome. A tenant that requires MFA meets an
 *      account that has none, and the login is neither a success nor a failure.
 *   2. Voluntary enrolment — the same two calls from inside an existing session.
 *   3. Email verification — unauthenticated, because a user whose address is unverified
 *      may have no session at all.
 *   4. The two resends (§25.7) — one for a caller with no session, one for a caller signed
 *      in to the account it is asking about. They are not alternatives, and neither is
 *      routed to the other.
 *   5. Password reset — including the §23 detour a tenant with OPAQUE enabled forces, and
 *      the enumeration guarantee that makes the first call return nothing useful on
 *      purpose.
 *
 * Run: php examples/account_lifecycle.php
 * (illustrative/compilable — a failure here is expected in a sandbox with no live server.)
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\Account\PasswordResetConfirmation;
use Axiam\Sdk\Account\PasswordResetRequest;
use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Core\NetworkError;

function envOr(string $key, string $fallback): string
{
    $value = getenv($key);

    return $value === false ? $fallback : $value;
}

$tenantId = envOr('AXIAM_TENANT_ID', '00000000-0000-0000-0000-000000000000');

$client = new AxiamClient(
    baseUrl: envOr('AXIAM_BASE_URL', 'https://localhost:8443'),
    tenant: envOr('AXIAM_TENANT', 'acme'),
    orgSlug: envOr('AXIAM_ORG_SLUG', 'acme'),
);

// ---------------------------------------------------------------------------
// 1. The third login outcome (§25.2 rule 1)
// ---------------------------------------------------------------------------

echo "== login ==\n";
try {
    $result = $client->login(envOr('AXIAM_EMAIL', 'alice@acme.test'), envOr('AXIAM_PASSWORD', 'pw'));

    if ($result->mfaSetupRequired) {
        // Not a failure. The tenant requires MFA, this account has none, and the server
        // handed back a setup token to finish with. There is no session yet — the token IS
        // the credential for the next two calls.
        $setupToken = $result->setupToken;

        $enrollment = $client->mfaSetupEnroll($setupToken);
        echo '  scan this: ' . $enrollment->totpUri->reveal() . "\n";

        // mfaSetupConfirm completes the LOGIN, not just the enrolment: it adopts
        // credentials exactly as login() does (§25.2 rule 2), so there is nothing left for
        // the caller to install.
        $completed = $client->mfaSetupConfirm($setupToken, envOr('AXIAM_TOTP_CODE', '123456'));
        echo "  signed in as {$completed->userId}\n";
    } elseif ($result->mfaRequired) {
        // The account already HAS a factor — challenge it, don't enrol.
        $client->verifyMfa($result->challengeToken, envOr('AXIAM_TOTP_CODE', '123456'));
        echo "  signed in after an MFA challenge\n";
    } else {
        echo "  signed in as {$result->userId}\n";
    }
} catch (AxiamException $e) {
    echo '  login unavailable: ' . $e->getMessage() . "\n";
}

// ---------------------------------------------------------------------------
// 2. Voluntary enrolment (§25.1)
// ---------------------------------------------------------------------------

echo "== enrolling TOTP from inside a session ==\n";
try {
    $enrollment = $client->mfaEnroll();

    // Both halves are Sensitive, and the second one matters: the otpauth URI CONTAINS the
    // secret (§25.3). Wrapping the bare secret and then printing the URI into a log leaks
    // exactly the same bytes.
    echo '  secret (redacted when rendered): ' . print_r($enrollment->secretBase32, true) . "\n";
    echo '  [QR code for ' . substr($enrollment->totpUri->reveal(), 0, 20) . "...]\n";

    if ($client->mfaConfirm(envOr('AXIAM_TOTP_CODE', '123456'))) {
        echo "  MFA is live on this account\n";
    }

    // Note what did NOT happen: the §17 decision memo was not cleared. The subject has not
    // changed, and discarding a warm memo on an unrelated profile action costs a round
    // trip on every check that follows (§25.2 rule 3).
} catch (AxiamException $e) {
    echo '  enrolment unavailable: ' . $e->getMessage() . "\n";
}

// ---------------------------------------------------------------------------
// 3. Email verification (§25.1) — no session required
// ---------------------------------------------------------------------------

echo "== verifying an email address ==\n";
try {
    // The tenant is a BODY field here. §12.1 rule 2's ?tenant_id= convention is scoped to
    // the /oauth2 endpoints, and this is not one of those.
    $client->verifyEmail(envOr('AXIAM_VERIFY_TOKEN', 'paste-the-token-from-the-mail'), $tenantId);
    echo "  verified\n";
} catch (AxiamException) {
    echo "  that link has expired — sending another\n";
    try {
        $client->resendVerification('alice@acme.test', $tenantId);
    } catch (AxiamException) {
        // Nothing reachable; the shape is what this example documents.
    }
}

// ---------------------------------------------------------------------------
// 4. The two resends (§25.7) — they look like one operation and are not
// ---------------------------------------------------------------------------

echo "== resending a verification mail ==\n";

// (a) No session. A sign-up screen has an address and nothing else, so the server must
//     answer identically whether that address exists, is already verified, or is over the
//     daily limit: anything else is an oracle for which addresses have accounts (§25.4).
try {
    $client->resendVerification('alice@acme.test', $tenantId);
    echo "  if that address needs verifying, a mail is on its way\n";
} catch (AxiamException) {
    // Nothing reachable; the shape is what this example documents.
}

// (b) Signed in. A profile page's caller is already authenticated to the account it is
//     asking about, so none of the outcomes tells it anything it did not bring with it —
//     and this call therefore says which one happened. It names NO address: a parameter
//     here would let an authenticated session mail an arbitrary one.
try {
    $client->resendOwnVerification();
    echo "  enqueued — delivery is asynchronous and can still fail at the provider\n";
} catch (AuthzError) {
    // 409: already verified, or an account state that must not be sent a live token.
    echo "  nothing to send: that address is already verified\n";
} catch (NetworkError) {
    // 429: the daily resend limit. NOT retried against the unauthenticated endpoint —
    // §25.7 rule 2 forbids that fallback, which would turn this failure back into a
    // silent success and restore the bug this operation exists to fix.
    echo "  the daily resend limit is reached; try again tomorrow\n";
} catch (AxiamException) {
    // Includes "no session at all", which is refused client-side with no wire call.
}

// ---------------------------------------------------------------------------
// 5. Password reset (§25.4)
// ---------------------------------------------------------------------------

echo "== resetting a password ==\n";
try {
    // Returns void, whether or not the address exists, and this SDK exposes no way to tell
    // the two apart. That is not an omission to improve on: a client that surfaced a
    // "no such user" state — even one inferred from timing — would turn the endpoint into
    // the account-enumeration oracle its uniform response exists to prevent.
    $client->requestPasswordReset(new PasswordResetRequest('alice@acme.test'));
    echo "  if that address has an account, a mail is on its way\n";

    $token = envOr('AXIAM_RESET_TOKEN', 'paste-the-token-from-the-mail');

    // Ask the context BEFORE building anything. On a tenant with §23 enabled the client
    // has to construct an OPAQUE registration record, and building one needs parameters it
    // cannot know before it has a token to ask with. Sending a plaintext password to a
    // tenant in opaque_mode: required is refused, and refused late (§25.4 rule 1).
    $context = $client->passwordResetContext($token);

    if ($context->opaque !== null) {
        echo '  this tenant uses OPAQUE: ' . json_encode($context->opaque) . "\n";
        // Build the record with the SDK's §23 helpers, then pass it as the confirmation's
        // `opaque` argument.
    } else {
        $client->confirmPasswordReset(new PasswordResetConfirmation(
            $token,
            'a new correct horse battery staple',
            $tenantId,
        ));
        echo "  password changed\n";
    }
} catch (AxiamException) {
    // A 404 means unknown, expired OR already-consumed, deliberately without
    // distinguishing them (§25.4 rule 3). Neither does this.
    echo "  that reset link is no longer usable\n";
}
