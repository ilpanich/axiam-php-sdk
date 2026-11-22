<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract168;

use Axiam\Sdk\Auth\JwksVerifier;
use Axiam\Sdk\Tests\Fixtures\AccessTokenFixtureTrait;
use GuzzleHttp\Client;
use GuzzleHttp\Promise\FulfilledPromise;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * Security audit 2026-11-14, C5 (CONTRACT.md §12.4 rule 2, shared by §10.1 rule 12): an unknown
 * `kid` costs AT MOST ONE JWKS re-fetch per cooldown window, and the resolved `jwks_uri` is
 * cached. Before this, every token naming a `kid` the cache did not hold made the verifier GET
 * discovery and then the JWKS — two outbound requests per forged, unauthenticated token.
 *
 * The HTTP stand-in answers with guzzle's REAL deferred promises (the audit's finding was that
 * the amplification only shows under genuine async settlement), counts what it is asked for,
 * and serves whatever key set the test currently says the server publishes.
 */
final class JwksUnknownKidCooldownTest extends TestCase
{
    use AccessTokenFixtureTrait;

    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';
    /** The window §12.4 rule 2 / the audit remediation name: 60 s. */
    private const WINDOW = 60;

    /** @var list<string> every request path the stand-in server saw */
    private array $requests = [];

    /** @var list<array<string,mixed>> the keys the stand-in server currently publishes */
    private array $publishedKeys = [];

    private int $now = 1_800_000_000;

    protected function setUp(): void
    {
        $this->requests = [];
        $this->now = 1_800_000_000;
        $jwks = json_decode((string) file_get_contents(__DIR__ . '/../Fixtures/ed25519_jwks.json'), true);
        self::assertIsArray($jwks);
        $this->publishedKeys = $jwks['keys'];
    }

    private function verifier(): JwksVerifier
    {
        $handler = function (RequestInterface $request): FulfilledPromise {
            $path = $request->getUri()->getPath();
            $this->requests[] = $path;
            if ($path === '/.well-known/openid-configuration') {
                return new FulfilledPromise(new Response(200, [], (string) json_encode(['jwks_uri' => self::BASE_URL . '/oauth2/jwks'])));
            }
            if ($path === '/oauth2/jwks') {
                return new FulfilledPromise(new Response(200, [], (string) json_encode(['keys' => $this->publishedKeys])));
            }

            return new FulfilledPromise(new Response(404));
        };

        // The 7th argument is the (internal) clock; positional on purpose so the same test also
        // runs, unchanged, against code that predates it.
        return new JwksVerifier(new Client(['handler' => $handler]), self::BASE_URL, 300, null, null, null, fn (): int => $this->now);
    }

    private function requestCount(string $path): int
    {
        return count(array_filter($this->requests, static fn (string $p): bool => $p === $path));
    }

    private function randomKidToken(): string
    {
        return $this->mintAccessToken([], ['kid' => 'forged-' . bin2hex(random_bytes(8))]);
    }

    public function testFiftyRandomKidsCauseAtMostOneJwksFetch(): void
    {
        $verifier = $this->verifier();
        self::assertIsArray($verifier->verify($this->mintAccessToken(), self::TENANT), 'warm-up with the real kid verifies');
        $afterWarmUp = count($this->requests);

        for ($i = 0; $i < 50; $i++) {
            self::assertNull($verifier->verify($this->randomKidToken(), self::TENANT));
        }

        $fetches = count($this->requests) - $afterWarmUp;
        self::assertLessThanOrEqual(1, $fetches, sprintf('50 forged kids inside one window made %d outbound requests; at most 1 is allowed', $fetches));
    }

    public function testAKnownKidNeverTouchesTheNetworkOnceTheCacheIsWarm(): void
    {
        $verifier = $this->verifier();
        $verifier->verify($this->mintAccessToken(), self::TENANT);
        $afterWarmUp = count($this->requests);

        for ($i = 0; $i < 5; $i++) {
            self::assertIsArray($verifier->verify($this->mintAccessToken(), self::TENANT));
        }

        self::assertCount($afterWarmUp, $this->requests);
    }

    public function testARotatedKeyIsRefusedInsideTheWindowAndAcceptedAfterIt(): void
    {
        $verifier = $this->verifier();
        $verifier->verify($this->mintAccessToken(), self::TENANT); // cold fill
        $this->now += 5;
        self::assertNull($verifier->verify($this->randomKidToken(), self::TENANT)); // an unknown kid: the one re-fetch

        // The server now rotates: a second key is published.
        $keypair = sodium_crypto_sign_keypair();
        $b64 = static fn (string $bin): string => rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
        $this->publishedKeys[] = [
            'kty' => 'OKP', 'crv' => 'Ed25519', 'use' => 'sig', 'alg' => 'EdDSA',
            'kid' => 'rotated-2026-11', 'x' => $b64(sodium_crypto_sign_publickey($keypair)),
        ];
        $rotated = $this->signWith(sodium_crypto_sign_secretkey($keypair), 'rotated-2026-11');

        $this->now += 15; // 20 s after cold fill, 15 s after the last unknown-kid re-fetch: inside the window
        $before = count($this->requests);
        self::assertNull($verifier->verify($rotated, self::TENANT), 'inside the window an unknown kid is rejected from the cache');
        self::assertCount($before, $this->requests, 'and costs no network I/O');

        $this->now += self::WINDOW;
        self::assertIsArray($verifier->verify($rotated, self::TENANT), 'after the window the rotated key is picked up');
        self::assertCount($before + 1, $this->requests, 'with exactly one fetch');
    }

    public function testTheResolvedJwksUriIsCachedAcrossRefetches(): void
    {
        $verifier = $this->verifier();
        $verifier->verify($this->mintAccessToken(), self::TENANT); // cold fill: discovery + jwks
        for ($i = 0; $i < 3; $i++) {
            $this->now += self::WINDOW + 1;
            $verifier->verify($this->randomKidToken(), self::TENANT);
        }

        self::assertSame(1, $this->requestCount('/.well-known/openid-configuration'), 'discovery is read once, not once per re-fetch');
        self::assertSame(4, $this->requestCount('/oauth2/jwks'), 'cold fill plus one re-fetch per elapsed window');
    }

    public function testTheCooldownConstantIsSixtySeconds(): void
    {
        self::assertSame(self::WINDOW, JwksVerifier::UNKNOWN_KID_REFETCH_COOLDOWN_SECONDS);
    }

    private function signWith(string $secretKey, string $kid): string
    {
        $b64 = static fn (string $bin): string => rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
        $input = $b64((string) json_encode(['typ' => 'at+jwt', 'alg' => 'EdDSA', 'kid' => $kid])) . '.'
            . $b64((string) json_encode(['sub' => 'user-1', 'tenant_id' => self::TENANT, 'exp' => time() + 900]));

        return $input . '.' . $b64(sodium_crypto_sign_detached($input, $secretKey));
    }
}
