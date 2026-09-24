<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Auth\PresentedProofs;
use Axiam\Sdk\AxiamClient;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * CONTRACT.md §10.1 rule 9, at the level `AxiamClient::verifyLocally()` /
 * `verifyWithProofs()` — the SAME default entry point the Laravel/Symfony guards and
 * {@see Sec085GuardCredentialSubstitutionTest} exercise, with a REAL Ed25519-signed
 * token (the fixture {@see Sec085GuardCredentialSubstitutionTest} already uses),
 * rather than only at the {@see \Axiam\Sdk\Auth\JwksVerifier} unit level.
 *
 * `verifyLocally()` is the default guard entry point the framework bridges call, and it
 * has no transport to ask for a peer certificate — so a device token lifted off a
 * device and presented to it must be refused, not admitted as an ordinary bearer
 * credential.
 */
final class Contract151Rule9AtAxiamClientTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/Fixtures';
    private const TENANT = 'acme-tenant';
    private const BASE_URL = 'https://api.test';
    private const THUMBPRINT = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
    private const OTHER_THUMBPRINT = 'bWluZS1ub3QteW91cnMtdGhpcy1pcy00My1jaGFyc18';

    private function client(): AxiamClient
    {
        $jwks = new Response(200, [], (string) file_get_contents(self::FIXTURES . '/ed25519_jwks.json'));
        $discovery = new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks']));

        $handler = function ($request) use ($jwks, $discovery) {
            $path = $request->getUri()->getPath();
            $response = match (true) {
                str_contains($path, 'openid-configuration'), str_contains($path, 'oauth2-authorization-server') => $discovery,
                str_contains($path, '/jwks') => $jwks,
                default => new Response(404, [], '{}'),
            };

            return \GuzzleHttp\Promise\Create::promiseFor($response);
        };

        return new AxiamClient(self::BASE_URL, self::TENANT, transportHandler: $handler);
    }

    private static function signedFixture(array $overrides): string
    {
        $keypair = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_keypair.json'), true);
        \assert(\is_array($keypair));

        $header = ['typ' => 'JWT', 'alg' => 'EdDSA', 'kid' => 'axiam-test-key-2026-07-02'];
        $payload = array_merge([
            'sub' => 'device-fixture-0001',
            'tenant_id' => self::TENANT,
            'iat' => 1751500000,
            'exp' => 4102444800,
        ], $overrides);

        $signingInput = self::b64((string) json_encode($header)) . '.' . self::b64((string) json_encode($payload));
        $secret = base64_decode(strtr((string) $keypair['secret_key_b64url'], '-_', '+/'), true);
        \assert(\is_string($secret));

        return $signingInput . '.' . self::b64(sodium_crypto_sign_detached($signingInput, $secret));
    }

    private static function b64(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    public function testVerifyLocallyRefusesACertificateBoundDeviceTokenWithNoEvidence(): void
    {
        $token = self::signedFixture(['cnf' => ['x5t#S256' => self::THUMBPRINT]]);

        $claims = $this->client()->verifyLocally($token, self::TENANT);

        self::assertNull($claims, 'the default entry point has no evidence and must refuse a bound token');
    }

    public function testVerifyLocallyStillAcceptsAnOrdinaryUnboundToken(): void
    {
        $token = self::signedFixture([]);

        $claims = $this->client()->verifyLocally($token, self::TENANT);

        self::assertIsArray($claims);
        self::assertSame('device-fixture-0001', $claims['sub']);
    }

    public function testVerifyWithProofsAcceptsTheSameTokenWhenTheCertificateMatches(): void
    {
        $token = self::signedFixture(['cnf' => ['x5t#S256' => self::THUMBPRINT]]);

        $claims = $this->client()->verifyWithProofs($token, self::TENANT, PresentedProofs::certificate(self::THUMBPRINT));

        self::assertIsArray($claims);
    }

    public function testVerifyWithProofsRefusesTheSameTokenWithADifferentCertificate(): void
    {
        $token = self::signedFixture(['cnf' => ['x5t#S256' => self::THUMBPRINT]]);

        $claims = $this->client()->verifyWithProofs($token, self::TENANT, PresentedProofs::certificate(self::OTHER_THUMBPRINT));

        self::assertNull($claims);
    }
}
