<?php

declare(strict_types=1);

/**
 * examples/device_mtls_provisioning.php — provision an IoT device with a certificate from
 * the tenant's signing CA, then authenticate as that device over §6.1 mutual TLS.
 *
 * This is the flow AXIAM exists for at the edge: a device that holds no password, carries
 * no shared secret, and proves who it is with a private key that never left it.
 *
 * There are two actors, and keeping them apart is the point of the example:
 *
 *  1. THE OPERATOR — an administrator, authenticated normally, who mints the certificate
 *     and binds it to a service account. Uses the §27 management surface.
 *  2. THE DEVICE — holds only its own certificate and key, and authenticates with them.
 *     Touches no management operation at all.
 *
 * The private key is a §27.5 ONE-TIME SECRET. The server returns it exactly once, at
 * generation, and will never return it again. A provisioning script that does not persist
 * it here has produced a certificate nobody can use — so the write happens immediately,
 * with 0600 set AT CREATION rather than chmod'ed afterwards (a window where the key is
 * world-readable is a window, however short).
 *
 * Run: php examples/device_mtls_provisioning.php
 * (requires a reachable AXIAM server and an administrator account — a failure here is
 * expected in a sandbox with no live server.)
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Management\Models;
use Axiam\Sdk\Management\NotFoundError;

/** Reads an environment variable, falling back to a placeholder for illustration. */
function env(string $key, string $fallback): string
{
    $value = getenv($key);

    return $value === false || $value === '' ? $fallback : $value;
}

/**
 * Writes a secret to disk readable only by the current user.
 *
 * The mode is passed to fopen's stream context rather than applied with a later chmod:
 * between `file_put_contents()` and `chmod()` the key sits on disk world-readable, and on
 * a shared provisioning host that window is enough.
 */
function writeSecret(string $path, string $contents): void
{
    $handle = fopen($path, 'wb');
    if ($handle === false) {
        throw new RuntimeException("cannot open {$path} for writing");
    }
    // Narrow the mode BEFORE any bytes are written.
    chmod($path, 0600);
    fwrite($handle, $contents);
    fclose($handle);
}

$deviceSerial = env('AXIAM_DEVICE_SERIAL', 'device-001');
$outputDir = env('AXIAM_DEVICE_DIR', sys_get_temp_dir() . '/axiam-' . $deviceSerial);
@mkdir($outputDir, 0700, true);

$certPath = $outputDir . '/device.crt';
$keyPath = $outputDir . '/device.key';
$chainPath = $outputDir . '/chain.pem';

// =====================================================================
// 1. THE OPERATOR
// =====================================================================

$operator = new AxiamClient(
    env('AXIAM_BASE_URL', 'https://axiam.example.com'),
    env('AXIAM_TENANT', 'acme'),
    orgId: env('AXIAM_ORG_ID', '11111111-1111-4111-8111-111111111111'),
    oidcTenantId: env('AXIAM_TENANT_ID', '22222222-2222-4222-8222-222222222222'),
);

try {
    $operator->login(env('AXIAM_ADMIN', 'admin@example.com'), env('AXIAM_PASSWORD', 'secret'));
    $management = $operator->management();

    // ---- the tenant's signing CA -------------------------------------------
    //
    // §27.4 rule 3 has an exception here worth noticing. On most routes `{tenant_id}`
    // names the CALLING CONTEXT and the SDK fills it in. On the signing-CA routes it
    // names the tenant being ADMINISTERED, so it is an ordinary argument — and
    // `resolvedTenantId()` is how you pass the same one the implicit routes would use.
    $tenantId = $operator->resolvedTenantId() ?? '';

    // `{org_id}` is implicit; `{tenant_id}` is the argument, because here it names the
    // tenant being administered rather than the calling context.
    $signingCas = $management->caCertificates()->listSigningCas($tenantId);
    if ($signingCas->isEmpty()) {
        fprintf(STDERR, "tenant has no signing CA; generate one first\n");
        exit(1);
    }
    $signingCa = $signingCas->items[0];
    printf("signing CA: %s (%d in this tenant)\n", $signingCa->id, $signingCas->total);

    // ---- mint the device certificate ---------------------------------------
    //
    // `Device` rather than `User` or `Service`: the certificate type is what the server
    // uses to decide which authentication paths the holder may take.
    //
    // Ed25519 rather than RSA-4096: an IoT device does the handshake signature itself, on
    // whatever CPU it has, and the difference is felt on every reconnect.
    $generated = $management->certificates()->generate(new Models\CreateCertificateRequest(
        certType: Models\CertificateType::Device,
        issuerCaId: $signingCa->id,
        keyAlgorithm: Models\KeyAlgorithm::Ed25519,
        subject: "CN={$deviceSerial}",
        validityDays: 365,
        metadata: ['serial' => $deviceSerial, 'provisioned_by' => 'examples/device_mtls_provisioning.php'],
    ));

    printf("issued certificate %s (%s)\n", $generated->id, $generated->fingerprint);

    // ---- persist the one-time secret ---------------------------------------
    //
    // §27.5: `privateKeyPem` is `Sensitive`. It prints as `[SENSITIVE]` and
    // json_encode()s as `[SENSITIVE]`, so it cannot reach a log line by accident;
    // `reveal()` is the single, explicit way to obtain it, called at the point of use.
    //
    // This is the ONLY moment the key exists outside the server. There is no second
    // chance to fetch it.
    writeSecret($keyPath, $generated->privateKeyPem->reveal());
    writeSecret($certPath, $generated->publicCertPem);
    if ($generated->chainPem !== null) {
        writeSecret($chainPath, $generated->chainPem);
    }
    printf("wrote %s and %s (0600)\n", $certPath, $keyPath);

    // ---- give the device an identity ---------------------------------------
    //
    // The certificate proves WHO connected. A service account is WHAT they may do —
    // binding the two is what turns a valid handshake into an authorization subject.
    $account = $management->serviceAccounts()->create(new Models\CreateServiceAccountRequest(
        name: "device-{$deviceSerial}",
        description: 'Provisioned by the mTLS example',
    ));

    $management->serviceAccounts()->bindCertificate(
        $account->id,
        new Models\BindCertificate(certificateId: $generated->id),
    );
    printf("bound certificate to service account %s\n", $account->id);
} catch (NotFoundError $e) {
    fprintf(STDERR, "not found (or not visible to you): %s\n", $e->getMessage());
    exit(1);
} catch (AxiamException $e) {
    fprintf(STDERR, "provisioning failed: %s\n", $e->getMessage());
    exit(1);
} finally {
    $operator->close();
}

// =====================================================================
// 2. THE DEVICE
// =====================================================================
//
// A separate client, built the way the device itself would build it: certificate and key,
// no password, no client secret, no management surface. §6.1 mutual TLS — the private key
// is used for the handshake and never transmitted.

$device = new AxiamClient(
    env('AXIAM_BASE_URL', 'https://axiam.example.com'),
    env('AXIAM_TENANT', 'acme'),
    clientCert: $certPath,
    clientKey: $keyPath,
);

try {
    // No login() call: the TLS handshake IS the authentication. What the device can do
    // from here is whatever its service account was granted — checked the same way any
    // other subject's access is checked.
    $allowed = $device->can('telemetry:publish', env('AXIAM_RESOURCE_ID', $deviceSerial));
    printf("device may publish telemetry: %s\n", $allowed ? 'yes' : 'no');
} catch (AxiamException $e) {
    fprintf(STDERR, "device authentication failed: %s\n", $e->getMessage());
    exit(1);
} finally {
    $device->close();
}
