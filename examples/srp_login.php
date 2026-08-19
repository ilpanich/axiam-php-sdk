<?php

declare(strict_types=1);

/**
 * examples/srp_login.php — the SRP-6a login path (CONTRACT.md §23).
 *
 * SRP proves the password to the server without the password — or anything from which it can be
 * cheaply recovered — ever crossing the wire. What the server receives is `A` and a proof, neither
 * of which is useful without the account's verifier, so a TLS-terminating proxy, an accidentally
 * verbose request log or a heap dump cannot capture a plaintext password.
 *
 * It does NOT protect against a compromised AXIAM server. Nothing client-side can.
 *
 * PHP is the one AXIAM SDK where this feature is CONDITIONAL, in two ways (§23.8):
 *
 *   1. It needs `ext-gmp` or `ext-bcmath` for the bignum arithmetic. `srpAvailable()` reports
 *      which — it returns `false` rather than throwing, so an application can choose a login path
 *      before attempting one.
 *   2. It needs the tenant configured for `pbkdf2_sha256`. No PHP runtime offers Argon2id with a
 *      caller-supplied 32-byte salt (libsodium requires exactly 16, `password_hash()` generates
 *      its own), and deriving `x` from a folded salt would produce a value no AXIAM server agrees
 *      with — reported to the user as a wrong password. The SDK refuses instead.
 *
 * Both gaps, and a tenant with SRP switched off entirely, arrive as `NetworkError` and never as
 * `AuthError`: they are facts about this runtime or this tenant, not about the credentials.
 *
 * Uses ONLY the public `AxiamClient` API, exactly as a consuming application would.
 *
 * Run: php examples/srp_login.php
 * (requires a reachable AXIAM server at AXIAM_BASE_URL with SRP enabled for the tenant; this
 * example is illustrative/compilable, not a live-server smoke test.)
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Srp\Srp;
use Axiam\Sdk\Srp\SrpKdfParams;

$baseUrl = getenv('AXIAM_BASE_URL') ?: 'https://localhost:8443';
$tenant = getenv('AXIAM_TENANT_SLUG') ?: 'acme';
$orgSlug = getenv('AXIAM_ORG_SLUG') ?: 'acme';
$username = getenv('AXIAM_USERNAME') ?: 'alice';
$password = getenv('AXIAM_PASSWORD') ?: 'hunter2';

$client = new AxiamClient($baseUrl, $tenant, orgSlug: $orgSlug);

// Ask before attempting. On PHP this genuinely answers `false` on a runtime with neither bignum
// extension, which is why §23.1 puts the probe in every SDK's vocabulary.
if (!$client->srpAvailable()) {
    fwrite(STDERR, "This PHP runtime has neither ext-gmp nor ext-bcmath, so SRP is unavailable.\n");
    fwrite(STDERR, "Install one of them, or use \$client->login() instead.\n");
    exit(1);
}

try {
    $result = $client->loginSrp($username, $password);
} catch (NetworkError $e) {
    // Not a failed login: the tenant has SRP off, or this runtime cannot do the KDF it named.
    // Fall back rather than reporting a credential problem the user does not have.
    fwrite(STDOUT, "SRP unavailable here ({$e->getMessage()}) — falling back to password login\n");
    try {
        $result = $client->login($username, $password);
    } catch (AuthzError $denied) {
        // srp_mode: required. The credentials were never examined.
        fwrite(STDERR, "This tenant refuses password login: {$denied->getMessage()}\n");
        exit(1);
    }
} catch (AuthError $e) {
    fwrite(STDERR, "Authentication failed: {$e->getMessage()}\n");
    exit(1);
}

if ($result->mfaRequired) {
    // Identical to the non-SRP path — that is the point of §23.1's same-result-type requirement.
    $code = getenv('AXIAM_TOTP_CODE');
    if (!\is_string($code) || $code === '') {
        fwrite(STDERR, "MFA required; set AXIAM_TOTP_CODE\n");
        exit(1);
    }
    $result = $client->verifyMfa($result->challengeToken, $code);
}

fwrite(STDOUT, "Authenticated as {$result->user->userId}\n");

// Enrolment, for any request that SETS a password. The server cannot compute a verifier — it never
// sees the plaintext — so it has to arrive with the request or not at all. Read the tenant's
// parameters from GET /api/v1/auth/me (or the reset context) rather than hard-coding them: the
// server dictates the costs per exchange, and a verifier enrolled under different costs stays valid.
$newPassword = getenv('AXIAM_NEW_PASSWORD');
if (\is_string($newPassword) && $newPassword !== '') {
    $enrolment = $client->srpEnrollment(
        // The account's USERNAME, which is the canonical identity the challenge endpoint hands
        // back. An email here produces a verifier no login can ever satisfy.
        $username,
        $newPassword,
        params: new SrpKdfParams(Srp::KDF_PBKDF2_SHA256, 0),
    );
    // Send this as the `srp` member of the change-password body. Never log it: salt and verifier
    // are §23.3 rule 12 material.
    fwrite(STDOUT, "Enrolment ready: group={$enrolment->group} kdf={$enrolment->kdf}\n");
}
