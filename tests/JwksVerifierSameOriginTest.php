<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Auth\JwksVerifier;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use PHPUnit\Framework\TestCase;

/**
 * Targeted coverage for {@see JwksVerifier::isSameOriginHttps()}'s anti-SSRF/
 * anti-key-substitution guard (SDK-19) — invoked via reflection so each `parse_url()`
 * edge (a malformed candidate/base URL that `parse_url()` itself rejects with `false`,
 * and a candidate with an https scheme but no host) can be driven directly without
 * needing a full discovery-document HTTP round trip through
 * {@see JwksVerifier::resolveJwksUri()}/`fetchAndCache`.
 */
final class JwksVerifierSameOriginTest extends TestCase
{
    private function verifier(string $baseUrl = 'https://api.axiam.test'): JwksVerifier
    {
        $client = new Client(['handler' => HandlerStack::create(new MockHandler([]))]);

        return new JwksVerifier($client, $baseUrl);
    }

    private function isSameOriginHttps(JwksVerifier $verifier, string $candidate): bool
    {
        $ref = new \ReflectionMethod($verifier, 'isSameOriginHttps');
        $ref->setAccessible(true);

        return $ref->invoke($verifier, $candidate);
    }

    public function testMalformedCandidateUrlThatParseUrlRejectsIsNotSameOrigin(): void
    {
        // parse_url() itself returns false for a URL with a non-numeric port.
        self::assertFalse(parse_url('https://api.axiam.test:abc'), 'non-vacuousness: parse_url must genuinely reject this');

        self::assertFalse($this->isSameOriginHttps($this->verifier(), 'https://api.axiam.test:abc'));
    }

    public function testMalformedBaseUrlThatParseUrlRejectsIsNotSameOrigin(): void
    {
        self::assertFalse(parse_url('http:///x'), 'non-vacuousness: parse_url must genuinely reject this');

        // The verifier's OWN baseUrl is the malformed one this time.
        self::assertFalse($this->isSameOriginHttps($this->verifier('http:///x'), 'https://api.axiam.test/jwks'));
    }

    public function testHttpsCandidateWithNoHostIsNotSameOrigin(): void
    {
        // parse_url('https:foo') yields scheme=https but no 'host' key at all.
        $parts = parse_url('https:foo');
        self::assertIsArray($parts);
        self::assertArrayNotHasKey('host', $parts);

        self::assertFalse($this->isSameOriginHttps($this->verifier(), 'https:foo'));
    }

    public function testPlainHttpCandidateIsRejected(): void
    {
        self::assertFalse($this->isSameOriginHttps($this->verifier(), 'http://api.axiam.test/jwks'));
    }

    public function testDifferentHostCandidateIsRejected(): void
    {
        self::assertFalse($this->isSameOriginHttps($this->verifier(), 'https://evil.test/jwks'));
    }

    public function testSameHostAndSchemeAndPortIsAccepted(): void
    {
        self::assertTrue($this->isSameOriginHttps($this->verifier(), 'https://api.axiam.test/oauth2/jwks'));
    }

    public function testSameHostDifferentPortIsRejected(): void
    {
        self::assertFalse($this->isSameOriginHttps($this->verifier('https://api.axiam.test:8443'), 'https://api.axiam.test:9443/jwks'));
    }
}
