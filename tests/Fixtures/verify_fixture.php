#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Standalone fixture self-check (22-02 Task 1).
 *
 * Confirms empirically (mirroring the Java/C# siblings' "confirm before committing"
 * approach) that a token signed with the committed `ed25519_keypair.json` verifies against the
 * committed `ed25519_jwks.json` via firebase/php-jwt. The token is minted here, the same way
 * `AccessTokenFixtureTrait` mints it, rather than read from a committed file (a signed JWT in
 * the tree reads as a leaked credential to secret scanners). Then: parses the JWKS with `JWK::parseKeySet`,
 * decodes the JWT, and prints the `tenant_id` claim. Exits non-zero on any failure.
 *
 * Run: `php tests/Fixtures/verify_fixture.php`
 */

require __DIR__ . '/../../vendor/autoload.php';

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

$fixturesDir = __DIR__;

$jwks = json_decode(
    (string) file_get_contents($fixturesDir . '/ed25519_jwks.json'),
    true
);
$keypair = json_decode((string) file_get_contents($fixturesDir . '/ed25519_keypair.json'), true);
if (!is_array($keypair)) {
    fwrite(STDERR, "FAIL: ed25519_keypair.json did not decode to an array\n");
    exit(1);
}
$b64 = static fn (string $bin): string => rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
$signingInput = $b64((string) json_encode(['typ' => 'at+jwt', 'alg' => 'EdDSA', 'kid' => $keypair['kid']]))
    . '.' . $b64((string) json_encode(['sub' => 'user-fixture-0001', 'tenant_id' => 'acme-tenant', 'iat' => 1751500000, 'exp' => 4102444800]));
$secretKey = (string) base64_decode(strtr($keypair['secret_key_b64url'], '-_', '+/'), true);
$jwt = $signingInput . '.' . $b64(sodium_crypto_sign_detached($signingInput, $secretKey));

if (!is_array($jwks)) {
    fwrite(STDERR, "FAIL: ed25519_jwks.json did not decode to an array\n");
    exit(1);
}

$keys = JWK::parseKeySet($jwks);
$decoded = JWT::decode($jwt, $keys);
$claims = (array) $decoded;

if (!isset($claims['tenant_id'])) {
    fwrite(STDERR, "FAIL: decoded claims missing tenant_id\n");
    exit(1);
}

echo "OK: fixture-key JWT verifies against fixture JWKS via firebase/php-jwt\n";
echo "tenant_id: " . $claims['tenant_id'] . "\n";
echo "sub: " . ($claims['sub'] ?? '(none)') . "\n";

exit(0);
