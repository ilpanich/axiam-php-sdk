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
 * §13.4 observation 6 — slug-vs-UUID tenant comparand.
 *
 * A guard configured with the tenant *slug* rejects 100% of traffic, because AXIAM tokens
 * carry the tenant *UUID*. That is fail-closed and correct, but it presents as "every token
 * is invalid" with nothing pointing at the real cause. These tests pin the diagnostic that
 * closes that gap — and, just as importantly, pin that it stays silent everywhere else.
 */
final class TenantComparandDiagnosticTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/Fixtures';
    private const TENANT_UUID = '11111111-2222-3333-4444-555555555555';

    protected function setUp(): void
    {
        // The emitted-once latch is process-global by design; reset it per test so each case
        // observes its own behaviour rather than the previous test's latch.
        $flag = new \ReflectionProperty(JwksVerifier::class, 'tenantComparandWarningEmitted');
        $flag->setAccessible(true);
        $flag->setValue(null, false);
    }

    private function verifier(): JwksVerifier
    {
        $stack = HandlerStack::create(new MockHandler([
            new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks'])),
            new Response(200, [], (string) file_get_contents(self::FIXTURES . '/ed25519_jwks.json')),
            // The verifier caches the JWKS, but a second fetch must not 500 the test.
            new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks'])),
            new Response(200, [], (string) file_get_contents(self::FIXTURES . '/ed25519_jwks.json')),
        ]));

        return new JwksVerifier(new Client(['handler' => $stack]), 'https://api.test');
    }

    /** @param array<string,mixed> $overrides */
    private function signed(array $overrides = []): string
    {
        $keypair = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_keypair.json'), true);
        \assert(\is_array($keypair));

        $b64 = static fn (string $raw): string => rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
        $header = ['typ' => 'JWT', 'alg' => 'EdDSA', 'kid' => 'axiam-test-key-2026-07-02'];
        $payload = array_merge([
            'sub' => 'user-1',
            'tenant_id' => self::TENANT_UUID,
            'iat' => 1751500000,
            'exp' => 4102444800,
        ], $overrides);

        $input = $b64((string) json_encode($header)) . '.' . $b64((string) json_encode($payload));
        $secret = base64_decode(strtr((string) $keypair['secret_key_b64url'], '-_', '+/'), true);
        \assert(\is_string($secret));

        return $input . '.' . $b64(sodium_crypto_sign_detached($input, $secret));
    }

    /** @return list<string> Warnings raised while running $fn. */
    private function warningsFrom(callable $fn): array
    {
        $seen = [];
        set_error_handler(static function (int $errno, string $msg) use (&$seen): bool {
            $seen[] = $msg;

            return true;
        }, E_USER_WARNING);

        try {
            $fn();
        } finally {
            restore_error_handler();
        }

        return $seen;
    }

    public function testSlugConfiguredGuardWarnsWithAnActionableMessage(): void
    {
        $verifier = $this->verifier();
        $token = $this->signed();

        $warnings = $this->warningsFrom(static function () use ($verifier, $token): void {
            self::assertNull(
                $verifier->verify($token, 'acme-tenant'),
                'the rejection itself must be unchanged — the diagnostic only explains it',
            );
        });

        self::assertCount(1, $warnings);
        self::assertStringContainsString('acme-tenant', $warnings[0]);
        self::assertStringContainsString('not a UUID', $warnings[0]);
        self::assertStringContainsString('reject every request', $warnings[0]);
    }

    public function testWarningIsEmittedOnlyOncePerProcess(): void
    {
        $verifier = $this->verifier();
        $token = $this->signed();

        $warnings = $this->warningsFrom(static function () use ($verifier, $token): void {
            for ($i = 0; $i < 5; $i++) {
                $verifier->verify($token, 'acme-tenant');
            }
        });

        self::assertCount(1, $warnings, 'a repeated bad token must not be a log-flood lever');
    }

    public function testGenuineCrossTenantRejectionIsSilent(): void
    {
        $verifier = $this->verifier();
        // Both sides UUID-shaped: a real cross-tenant rejection, not a misconfiguration.
        $token = $this->signed(['tenant_id' => '99999999-8888-7777-6666-555555555555']);

        $warnings = $this->warningsFrom(static function () use ($verifier, $token): void {
            self::assertNull($verifier->verify($token, self::TENANT_UUID));
        });

        self::assertSame([], $warnings, 'a cross-tenant rejection must never be reported as a config error');
    }

    public function testCorrectlyConfiguredGuardAcceptsAndIsSilent(): void
    {
        $verifier = $this->verifier();
        $token = $this->signed();

        $warnings = $this->warningsFrom(static function () use ($verifier, $token): void {
            self::assertIsArray($verifier->verify($token, self::TENANT_UUID));
        });

        self::assertSame([], $warnings);
    }
}
