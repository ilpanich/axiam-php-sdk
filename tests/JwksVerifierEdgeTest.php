<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Auth\JwksVerifier;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * Fail-closed edge coverage for {@see JwksVerifier} (CONTRACT.md D-08): the four
 * security-critical behaviors are proven by {@see JwtVerifyTest}; this drives the
 * remaining "never throws on attacker input" branches — an empty `kid`, a header that is
 * not valid base64url, a header that decodes but is not JSON, and a known-`kid` token
 * whose signature does not verify (the `JWT::decode` throw is swallowed and mapped to a
 * null result). Every case must return null, never raise.
 */
final class JwksVerifierEdgeTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/Fixtures';
    private const FIXTURE_TENANT = 'acme-tenant';
    private const BASE_URL = 'https://api.test';

    /** @return array<string,mixed> */
    private function jwks(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_jwks.json'), true);
        self::assertIsArray($decoded);

        return $decoded;
    }

    private function fixtureJwt(): string
    {
        return trim((string) file_get_contents(self::FIXTURES . '/ed25519_signed_jwt.txt'));
    }

    /** @param list<Response> $queue */
    private function verifier(array $queue): JwksVerifier
    {
        $client = new Client(['handler' => HandlerStack::create(new MockHandler($queue))]);

        return new JwksVerifier($client, self::BASE_URL);
    }

    private function base64url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    public function testEmptyKidHeaderReturnsNullWithoutKeyLookup(): void
    {
        // Empty mock queue: an empty kid must be rejected before any JWKS fetch.
        [$headerB64, $payloadB64, $sigB64] = explode('.', $this->fixtureJwt());
        $header = json_decode((string) base64_decode(strtr($headerB64, '-_', '+/'), true), true);
        self::assertIsArray($header);
        $header['kid'] = '';
        $tampered = $this->base64url((string) json_encode($header)) . '.' . $payloadB64 . '.' . $sigB64;

        self::assertNull($this->verifier([])->verify($tampered, self::FIXTURE_TENANT));
    }

    public function testNonBase64HeaderReturnsNull(): void
    {
        // The header segment contains characters outside the base64url alphabet.
        $token = '@@@.' . $this->base64url('{}') . '.signature';

        self::assertNull($this->verifier([])->verify($token, self::FIXTURE_TENANT));
    }

    public function testNonJsonHeaderReturnsNull(): void
    {
        // The header segment is valid base64url but does not decode to JSON.
        $token = $this->base64url('not-json-at-all{') . '.' . $this->base64url('{}') . '.signature';

        self::assertNull($this->verifier([])->verify($token, self::FIXTURE_TENANT));
    }

    public function testKnownKidWithBadSignatureReturnsNull(): void
    {
        // Header + payload are the genuine fixture (valid EdDSA alg, known kid), so key
        // lookup succeeds and JWT::decode is actually attempted — but the signature
        // segment is corrupted, so decode throws and the verifier fails closed.
        [$headerB64, $payloadB64] = explode('.', $this->fixtureJwt());
        $tampered = $headerB64 . '.' . $payloadB64 . '.' . $this->base64url('corrupted-signature-bytes');

        $verifier = $this->verifier([
            new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks'])),
            new Response(200, [], (string) json_encode($this->jwks())),
        ]);

        self::assertNull($verifier->verify($tampered, self::FIXTURE_TENANT));
    }
}
