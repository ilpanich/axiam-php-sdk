<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Fixtures;

use Firebase\JWT\JWT;

/**
 * Mints real, verifiable EdDSA ACCESS tokens against the committed Ed25519 fixture key
 * (`ed25519_keypair.json` / `ed25519_jwks.json`) — the way the server types them from contract
 * 1.67 (`typ: at+jwt`, a `kid`) — with the header and claims of the caller's choosing, so the
 * §10.1 rule 10–12 and §11.2 rule 11 tests can vary exactly one thing each.
 */
trait AccessTokenFixtureTrait
{
    /**
     * @param array<string,mixed> $claims          merged over the defaults (a `null` value is kept: `purpose: null` is a `purpose` member)
     * @param array<string,mixed> $headerOverrides merged over `typ: at+jwt`, `alg: EdDSA`, the fixture `kid`;
     *                                              a `null` value removes the member
     * @param list<string>        $removeClaims    default claims to drop
     */
    private function mintAccessToken(array $claims = [], array $headerOverrides = [], string $tenant = 'acme-tenant', array $removeClaims = []): string
    {
        $keypair = json_decode((string) file_get_contents(__DIR__ . '/ed25519_keypair.json'), true);
        self::assertIsArray($keypair);
        $secretKey = (string) base64_decode(strtr($keypair['secret_key_b64url'], '-_', '+/'), true);

        $payload = array_merge([
            'sub' => 'user-fixture-0001',
            'tenant_id' => $tenant,
            'iat' => time(),
            'exp' => time() + 900,
        ], $claims);
        foreach ($removeClaims as $name) {
            unset($payload[$name]);
        }

        $header = array_merge(['typ' => 'at+jwt', 'alg' => 'EdDSA', 'kid' => $keypair['kid']], $headerOverrides);
        $header = array_filter($header, static fn (mixed $v): bool => $v !== null);

        $b64 = static fn (string $bin): string => rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
        $signingInput = $b64((string) json_encode($header)) . '.' . $b64((string) json_encode($payload));

        return $signingInput . '.' . $b64(sodium_crypto_sign_detached($signingInput, $secretKey));
    }
}
