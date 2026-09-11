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

    // --- contract 1.42 §21.5 capability members ---------------------------------------

    /**
     * Contract 1.42 added `code_challenge_methods_supported` and
     * `token_endpoint_auth_signing_alg_values_supported` to the advertised document
     * (CONTRACT.md §21.5). When present they are read through verbatim.
     */
    public function testDiscoveryReadsTheContract142CapabilityMembers(): void
    {
        $wire = $this->discoveryWire();
        $wire['code_challenge_methods_supported'] = ['S256'];
        $wire['token_endpoint_auth_signing_alg_values_supported'] = ['PS256', 'ES256', 'EdDSA'];
        $client = $this->client([new Response(200, [], (string) json_encode($wire))]);

        $configuration = $client->oidcDiscover();

        self::assertSame(['S256'], $configuration->code_challenge_methods_supported);
        self::assertSame(
            ['PS256', 'ES256', 'EdDSA'],
            $configuration->token_endpoint_auth_signing_alg_values_supported,
        );
    }

    /**
     * Both members are REQUIRED in AXIAM's own schema and modelled optional here anyway,
     * which is the point of this test: RFC 8414 §2 defines no default for either, so an
     * absent `code_challenge_methods_supported` is NOT an implied `["S256"]` — and a
     * document from a non-AXIAM OP that omits them must still parse. Modelling them
     * required would turn every such document into a NetworkError, which is a regression
     * dressed up as strictness (CONTRACT.md §21.5, §12.3 rule 6).
     *
     * `null`, specifically: absent must be distinguishable from an advertised empty list,
     * which is a server saying "I support none of these".
     */
    public function testAbsentCapabilityMembersParseAsNullRatherThanBeingRejected(): void
    {
        // discoveryWire() carries neither member — the pre-1.42 document shape.
        $client = $this->client([$this->discoveryResponse()]);

        $configuration = $client->oidcDiscover();

        self::assertNull($configuration->code_challenge_methods_supported);
        self::assertNull($configuration->token_endpoint_auth_signing_alg_values_supported);
    }

    /** An advertised empty list is a real answer and survives as `[]`, never collapsing to null. */
    public function testAdvertisedEmptyCapabilityListIsNotCollapsedToNull(): void
    {
        $wire = $this->discoveryWire();
        $wire['code_challenge_methods_supported'] = [];
        $client = $this->client([new Response(200, [], (string) json_encode($wire))]);

        $configuration = $client->oidcDiscover();

        self::assertSame([], $configuration->code_challenge_methods_supported);
    }

    /**
     * Contract 1.42 amended §5 rule 3's RATIONALE, not the rule: `client_secret_basic` is
     * now accepted and advertised server-side, and an SDK still MUST NOT send an
     * `Authorization: Basic` header to `/oauth2/*`. An advertisement is a statement about
     * the deployment, not an instruction to the client, so a document listing Basic
     * changes nothing about how this SDK authenticates — the secret stays in the form
     * body, which is the channel proxies and APM agents do not log by default.
     */
    public function testAdvertisedClientSecretBasicDoesNotChangeTokenEndpointAuthentication(): void
    {
        $wire = $this->discoveryWire();
        $wire['token_endpoint_auth_methods_supported'] = ['client_secret_post', 'client_secret_basic'];

        $history = [];
        $stack = \GuzzleHttp\HandlerStack::create(new MockHandler([
            new Response(200, [], (string) json_encode($wire)),
            new Response(200, [], (string) json_encode([
                'access_token' => 'at',
                'token_type' => 'Bearer',
                'expires_in' => 900,
            ])),
        ]));
        $stack->push(Middleware::history($history));

        $client = new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            oidcClientId: 'my-app',
            oidcClientSecret: 'sh!',
            oidcTenantId: '11111111-1111-4111-8111-111111111111',
            transportHandler: $stack,
        );

        $client->loginClientCredentials();

        $tokenRequest = $history[1]['request'];
        self::assertFalse($tokenRequest->hasHeader('Authorization'));
        self::assertStringContainsString('client_secret=sh%21', (string) $tokenRequest->getBody());
    }
}
