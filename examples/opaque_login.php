<?php

declare(strict_types=1);

/**
 * examples/opaque_login.php — the OPAQUE (RFC 9807) login path (CONTRACT.md §23).
 *
 * OPAQUE proves the password to the server without the password — or anything from which it can
 * be cheaply recovered — ever crossing the wire. What the server receives is a blinded group
 * element and a MAC, neither useful without the account's registration record AND the tenant's
 * OPRF seed. So a TLS-terminating proxy, an accidentally verbose request log or a heap dump
 * cannot capture a plaintext password, and a stolen record database is not offline-crackable on
 * its own — the pre-computation resistance the SRP-6a this replaces could not offer.
 *
 * It does NOT protect against a compromised AXIAM server. Nothing client-side can.
 *
 * PHP is still the AXIAM SDK where this feature is CONDITIONAL — but on ONE condition now,
 * not two. The SRP client needed `ext-gmp` or `ext-bcmath` for bignum arithmetic AND a tenant
 * configured for `pbkdf2_sha256`, because no PHP runtime offers Argon2id with a caller-supplied
 * 32-byte salt: AXIAM's own default was, for PHP, simply unreachable. The key stretching now
 * happens inside `libaxiam_opaque_ffi`, so all that is left is having the library:
 *
 *   1. `ext-ffi`, which is not guaranteed on any runtime and is disabled outright on some
 *      shared hosts.
 *   2. `libaxiam_opaque_ffi` itself — a per-platform asset of the AXIAM release, not a Composer
 *      package, because there is no cross-language registry to put it on. Put it on the system
 *      library path or set AXIAM_OPAQUE_LIBRARY to its full path.
 *
 * `opaqueAvailable()` reports both as one answer, returning `false` rather than throwing so an
 * application can choose a login path before attempting one. And unlike `srpAvailable()`, a
 * `true` here means every tenant works.
 *
 * That gap, and a tenant with OPAQUE switched off entirely, arrive as `NetworkError` and never
 * as `AuthError`: they are facts about this runtime or this tenant, not about the credentials.
 *
 * Uses ONLY the public `AxiamClient` API, exactly as a consuming application would.
 *
 * Run: php examples/opaque_login.php
 * (requires a reachable AXIAM server at AXIAM_BASE_URL with OPAQUE enabled for the tenant; this
 * example is illustrative/compilable, not a live-server smoke test.)
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\NetworkError;

$baseUrl = getenv('AXIAM_BASE_URL') ?: 'https://localhost:8443';
$tenant = getenv('AXIAM_TENANT_SLUG') ?: 'acme';
$org = getenv('AXIAM_ORG_SLUG') ?: 'acme';
$username = getenv('AXIAM_USERNAME') ?: 'alice';
$password = getenv('AXIAM_PASSWORD') ?: '';

$client = new AxiamClient($baseUrl, $tenant, orgSlug: $org);

try {
    // Asked FIRST, not after a failure. PHP is the language where this most
    // genuinely answers false, and an application that has to handle that anyway
    // may as well handle it before spending a round trip.
    if (!$client->opaqueAvailable()) {
        echo "OPAQUE is unavailable on this runtime — using password login\n";
        $result = $client->login($username, $password);
    } else {
        try {
            // OPAQUE first, password second. The reverse order would mean a tenant
            // running `opaque_mode: optional` never sees a single OPAQUE login —
            // which is the mode operators run for the whole of a migration.
            $result = $client->loginOpaque($username, $password);
            echo "signed in over OPAQUE — the password never left this process\n";
        } catch (NetworkError $e) {
            if (!str_contains($e->getMessage(), 'opaque_mode is disabled')) {
                // A key-stretching function this build cannot perform, or a cost
                // outside the accepted band. A configuration problem: falling back
                // would hide it, and the plaintext would go to the server anyway.
                throw $e;
            }
            echo "tenant has OPAQUE disabled ({$e->getMessage()}) — falling back\n";
            $result = $client->login($username, $password);
        } catch (AuthError $e) {
            // This covers BOTH halves of the mutual authentication: the envelope
            // only opens under the right password, and KE2's MAC only verifies if
            // the server actually holds the record. Do NOT retry over login()
            // yourself (§23.4 rule 7): under `opaque_mode: optional` loginOpaque()
            // has ALREADY done so and this is that retry's failure, and under
            // `required` /auth/login refuses every principal in the tenant before
            // it examines a credential, so a retry only puts the plaintext on the
            // wire for nothing.
            fwrite(STDERR, "login failed: {$e->getMessage()}\n");
            fwrite(STDERR, "Not retrying with a password.\n");
            exit(1);
        }
    }

    if ($result->mfaRequired) {
        // Identical to the non-OPAQUE path — that is the point of the
        // same-result-type requirement.
        $code = getenv('AXIAM_TOTP_CODE') ?: '';
        if ($code === '') {
            fwrite(STDERR, "MFA required; set AXIAM_TOTP_CODE\n");
            exit(1);
        }
        $result = $client->verifyMfa($result->challengeToken, $code);
    }

    echo "authenticated\n";

    // Enrolment, for any request that SETS a password. The server cannot build a
    // registration record — it never sees the plaintext — so it has to arrive with
    // the request or not at all.
    //
    // Note what is NOT passed. No identity: a record binds to a credential
    // identifier the server chooses, so unlike the SRP verifier this replaces there
    // is no username/email confusion that can produce a credential no login will
    // ever satisfy — and renaming a user no longer invalidates anything. And no
    // group or KDF: those come from the register/start response.
    $newPassword = getenv('AXIAM_NEW_PASSWORD') ?: '';
    if ($newPassword !== '') {
        $enrolment = $client->opaqueEnrollment($newPassword);
        // Send $enrolment->toWire() as the `opaque` member of the change-password
        // body. Never log the record itself.
        echo "enrolment ready for session {$enrolment->opaqueSession}\n";
    }
} catch (AuthzError $e) {
    // opaque_mode: required, reached through login(). The credentials were never
    // examined — showing "invalid username or password" here would be a lie.
    fwrite(STDERR, "this tenant refuses password login: {$e->getMessage()}\n");
    exit(1);
} catch (AuthError|NetworkError $e) {
    // Illustrative: without a reachable server this is the expected path.
    fwrite(STDERR, get_class($e) . ": {$e->getMessage()}\n");
    exit(1);
}
