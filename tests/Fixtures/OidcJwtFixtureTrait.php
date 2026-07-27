<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Fixtures;

use Firebase\JWT\JWT;

/**
 * Shared helpers for building/tampering EdDSA ID tokens against the SAME committed
 * Ed25519 keypair/JWKS fixtures {@see \Axiam\Sdk\Tests\JwtVerifyTest} already uses
 * (`tests/Fixtures/ed25519_keypair.json` / `ed25519_jwks.json`), so the OIDC §12 test
 * suite verifies against real, previously-audited fixtures rather than a second
 * throwaway keypair.
 */
trait OidcJwtFixtureTrait
{
    private const FIXTURES_DIR = __DIR__;

    /** @return array<string,mixed> */
    private function fixtureJwks(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURES_DIR . '/ed25519_jwks.json'), true);
        self::assertIsArray($decoded);

        return $decoded;
    }

    /** @return array{0:string,1:string} [base64url secret key, kid] */
    private function fixtureKeypair(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURES_DIR . '/ed25519_keypair.json'), true);
        self::assertIsArray($decoded);

        return [$decoded['secret_key_b64url'], $decoded['kid']];
    }

    private function fixtureKid(): string
    {
        return $this->fixtureKeypair()[1];
    }

    /**
     * Sign `$claims` as a valid EdDSA ID token with the fixture keypair (real
     * signature, real `kid` — verifiable against the fixture JWKS).
     *
     * @param array<string,mixed> $claims
     */
    private function signIdToken(array $claims): string
    {
        [$secretKeyB64Url, $kid] = $this->fixtureKeypair();
        $secretKey = (string) base64_decode(strtr($secretKeyB64Url, '-_', '+/'), true);

        return JWT::encode($claims, base64_encode($secretKey), 'EdDSA', $kid);
    }

    /** Base64url-encode (unpadded) a JSON-encodable value, mirroring a JWT segment. */
    private function b64Segment(mixed $value): string
    {
        return rtrim(strtr(base64_encode((string) json_encode($value)), '+/', '-_'), '=');
    }

    /**
     * Hand-build a 3-segment token whose HEADER carries `$headerOverrides` verbatim —
     * used for the `invalid_alg` (`alg: none` / `alg: RS256`) and the
     * missing/unknown-`kid` §12.4 failure-mode tests, where a REAL signature is
     * irrelevant (rejection must happen before, or independently of, any signature
     * check).
     *
     * @param array<string,mixed> $headerOverrides
     * @param array<string,mixed> $claims
     */
    private function tokenWithHeader(array $headerOverrides, array $claims): string
    {
        $header = array_merge(['typ' => 'JWT', 'alg' => 'EdDSA'], $headerOverrides);

        return $this->b64Segment($header) . '.' . $this->b64Segment($claims) . '.signature-not-checked';
    }

    /**
     * Sign `$claims` with the fixture key but then corrupt the signature bytes —
     * used for the `invalid_signature` failure-mode test (a well-formed token, known
     * `kid`, but a signature that does not verify).
     *
     * @param array<string,mixed> $claims
     */
    private function signIdTokenWithBadSignature(array $claims): string
    {
        $valid = $this->signIdToken($claims);
        [$header, $payload] = explode('.', $valid);
        // A syntactically-plausible (86-char, Ed25519-signature-length) but entirely
        // fabricated base64url signature — guaranteed not to verify against any key.
        $bogusSignature = rtrim(strtr(base64_encode(str_repeat("\x00\x11\x22\x33", 16)), '+/', '-_'), '=');

        return $header . '.' . $payload . '.' . $bogusSignature;
    }
}
