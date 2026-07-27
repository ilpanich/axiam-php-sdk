<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Oidc\OidcClient as OidcEngine;
use Axiam\Sdk\Oidc\OidcConfiguration;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Middleware;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Promise\Utils;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use ReflectionProperty;

/**
 * CONTRACT.md §12.1 `oidcDiscover` / §12.3 rule 6: per-origin cache, ≥5-minute TTL
 * floor, and Guzzle-promise single-flight de-duplication of concurrent callers —
 * mirroring {@see JwksSingleFlightTest}'s own non-vacuous "8 interleaved calls, exactly
 * 1 HTTP request" proof technique (a sequential PHPUnit loop cannot exercise a
 * single-flight guard under classic synchronous PHP-FPM; the guard is only observable by
 * NOT awaiting each call before issuing the next).
 */
final class OidcDiscoveryTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';

    /** @return array<string,mixed> */
    private function discoveryWire(string $issuer = self::BASE_URL): array
    {
        return [
            'issuer' => $issuer,
            'authorization_endpoint' => self::BASE_URL . '/oauth2/authorize',
            'token_endpoint' => self::BASE_URL . '/oauth2/token',
            'userinfo_endpoint' => self::BASE_URL . '/oauth2/userinfo',
            'jwks_uri' => self::BASE_URL . '/oauth2/jwks',
            'revocation_endpoint' => self::BASE_URL . '/oauth2/revoke',
            'introspection_endpoint' => self::BASE_URL . '/oauth2/introspect',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['EdDSA'],
            'scopes_supported' => ['openid', 'profile'],
            'token_endpoint_auth_methods_supported' => ['client_secret_post'],
            'claims_supported' => ['sub', 'iss'],
            'grant_types_supported' => ['authorization_code', 'refresh_token', 'client_credentials'],
        ];
    }

    private function discoveryResponse(string $issuer = self::BASE_URL): Response
    {
        return new Response(200, [], (string) json_encode($this->discoveryWire($issuer)));
    }

    /** @param array<int,Response> $queue */
    private function client(array $queue): AxiamClient
    {
        return new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            oidcClientId: 'my-app',
            transportHandler: new MockHandler($queue),
        );
    }

    private function engineOf(AxiamClient $client): OidcEngine
    {
        $prop = new ReflectionProperty(AxiamClient::class, 'oidc');
        $prop->setAccessible(true);
        /** @var OidcEngine $engine */
        $engine = $prop->getValue($client);

        return $engine;
    }

    // --- basic fetch + type ------------------------------------------------------------

    public function testOidcDiscoverReturnsTypedConfiguration(): void
    {
        $client = $this->client([$this->discoveryResponse()]);

        $configuration = $client->oidcDiscover();

        self::assertInstanceOf(OidcConfiguration::class, $configuration);
        self::assertSame(self::BASE_URL, $configuration->issuer);
        self::assertSame(self::BASE_URL . '/oauth2/token', $configuration->token_endpoint);
        self::assertSame(['openid', 'profile'], $configuration->scopes_supported);
    }

    /** §12.3 rule 6: issuer may legitimately differ from baseUrl (behind a proxy) — never rejected. */
    public function testIssuerMismatchWithBaseUrlIsNotRejected(): void
    {
        $client = $this->client([$this->discoveryResponse(issuer: 'https://issuer.internal:9443')]);

        $configuration = $client->oidcDiscover();

        self::assertSame('https://issuer.internal:9443', $configuration->issuer);
    }

    public function testMalformedDiscoveryDocumentRaisesNetworkError(): void
    {
        $client = $this->client([new Response(200, [], (string) json_encode(['issuer' => 'https://api.test']))]);

        $this->expectException(\Axiam\Sdk\Core\NetworkError::class);
        $client->oidcDiscover();
    }

    public function testNonObjectDiscoveryBodyRaisesNetworkError(): void
    {
        // A JSON STRING (not even a list/array) at the top level -- json_decode(...,
        // true) never produces an array for this, exercising OidcConfiguration::fromWire()'s
        // top-level is_array() guard specifically (distinct from a missing-field check).
        $client = $this->client([new Response(200, [], (string) json_encode('just a scalar string'))]);

        $this->expectException(\Axiam\Sdk\Core\NetworkError::class);
        $client->oidcDiscover();
    }

    public function testDiscoveryDocumentWithNonArrayListFieldRaisesNetworkError(): void
    {
        $wire = $this->discoveryWire();
        $wire['scopes_supported'] = 'openid'; // must be an array, not a bare string
        $client = $this->client([new Response(200, [], (string) json_encode($wire))]);

        $this->expectException(\Axiam\Sdk\Core\NetworkError::class);
        $client->oidcDiscover();
    }

    // --- §12.3 rule 6: cache TTL (>= 5 minutes) ----------------------------------------

    public function testSecondCallWithinTtlIsServedFromCacheWithNoExtraRequest(): void
    {
        // Exactly ONE response queued — a second call within the TTL must be served
        // from cache; if it re-fetched, MockHandler would throw "queue is empty".
        $client = $this->client([$this->discoveryResponse()]);

        $first = $client->oidcDiscover();
        $second = $client->oidcDiscover();

        self::assertSame($first->issuer, $second->issuer);
    }

    public function testConfiguredTtlBelowFiveMinutesIsFlooredToFiveMinutes(): void
    {
        self::assertSame(300, OidcEngine::MIN_DISCOVERY_TTL_SECONDS);
    }

    // --- §12.3 rule 6: per-origin cache key ---------------------------------------------

    public function testNormalizeOriginLowercasesAndMakesPortExplicit(): void
    {
        self::assertSame('https://iam.example.com:443', OidcEngine::normalizeOrigin('https://IAM.example.com/'));
        self::assertSame('https://iam.example.com:443', OidcEngine::normalizeOrigin('https://iam.example.com:443/x'));
        self::assertSame('http://iam.example.com:80', OidcEngine::normalizeOrigin('http://iam.example.com'));
        self::assertSame('https://iam.example.com:9443', OidcEngine::normalizeOrigin('https://iam.example.com:9443/y'));
    }

    public function testDifferentOriginsAreNeverConfusedInTheCacheKey(): void
    {
        self::assertNotSame(
            OidcEngine::normalizeOrigin('https://a.example.com'),
            OidcEngine::normalizeOrigin('http://a.example.com'),
        );
    }

    // --- §12.3 rule 6: single-flight de-duplication ------------------------------------

    public function testEightInterleavedDiscoverCallsTriggerExactlyOneHttpRequest(): void
    {
        $history = [];
        $mock = new MockHandler([$this->discoveryResponse()]);
        $client = $this->clientWithHistory($mock, $history);
        $engine = $this->engineOf($client);

        $promises = [];
        for ($i = 0; $i < 8; $i++) {
            $promises[] = $engine->oidcDiscoverAsync();
        }

        $results = Utils::settle($promises)->wait();

        self::assertCount(1, $history, 'expected exactly one discovery HTTP request across 8 interleaved callers');
        foreach ($results as $result) {
            self::assertSame('fulfilled', $result['state']);
        }
    }

    /** @param array<int,Response> $history */
    private function clientWithHistory(MockHandler $mock, array &$history): AxiamClient
    {
        $stack = \GuzzleHttp\HandlerStack::create($mock);
        $stack->push(Middleware::history($history));

        return new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            oidcClientId: 'my-app',
            transportHandler: $stack,
        );
    }

    public function testOidcDiscoverAsyncReturnsPromiseInterface(): void
    {
        $client = $this->client([$this->discoveryResponse()]);
        $engine = $this->engineOf($client);

        $promise = $engine->oidcDiscoverAsync();

        self::assertInstanceOf(PromiseInterface::class, $promise);
        self::assertInstanceOf(OidcConfiguration::class, $promise->wait());
    }
}
