<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Oidc\AuthorizationRequest;
use Axiam\Sdk\Oidc\OidcConfiguration;
use GuzzleHttp\Handler\MockHandler;
use PHPUnit\Framework\TestCase;

/**
 * `oidcBegin` (CONTRACT.md §12.1) — pure local computation, no network I/O: the eight
 * SDK-owned authorization-URL query parameters, `openid` scope injection, RFC
 * 3986-percent-encoding (spaces as `%20`, never `+`), and the reserved-parameter
 * override guard.
 */
final class OidcBeginTest extends TestCase
{
    private const BASE_URL = 'https://api.test';

    private function configuration(): OidcConfiguration
    {
        return new OidcConfiguration(
            issuer: self::BASE_URL,
            authorization_endpoint: self::BASE_URL . '/oauth2/authorize',
            token_endpoint: self::BASE_URL . '/oauth2/token',
            userinfo_endpoint: self::BASE_URL . '/oauth2/userinfo',
            jwks_uri: self::BASE_URL . '/oauth2/jwks',
            revocation_endpoint: self::BASE_URL . '/oauth2/revoke',
            introspection_endpoint: self::BASE_URL . '/oauth2/introspect',
            response_types_supported: ['code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['EdDSA'],
            scopes_supported: ['openid'],
            token_endpoint_auth_methods_supported: ['client_secret_post'],
            claims_supported: ['sub'],
            grant_types_supported: ['authorization_code'],
        );
    }

    private function client(): AxiamClient
    {
        return new AxiamClient(
            self::BASE_URL,
            'acme-tenant',
            oidcClientId: 'my-app',
            transportHandler: new MockHandler([]),
        );
    }

    /** @return array<string,string> */
    private static function queryOf(string $url): array
    {
        $query = parse_url($url, PHP_URL_QUERY);
        parse_str(is_string($query) ? $query : '', $parsed);

        /** @var array<string,string> $parsed */
        return $parsed;
    }

    public function testBuildsAuthorizationUrlWithExactlyTheEightMandatedParameters(): void
    {
        $request = $this->client()->oidcBegin($this->configuration(), 'https://app.test/callback');

        self::assertInstanceOf(AuthorizationRequest::class, $request);
        $query = self::queryOf($request->url);
        self::assertSame('code', $query['response_type']);
        self::assertSame('my-app', $query['client_id']);
        self::assertSame('https://app.test/callback', $query['redirect_uri']);
        self::assertSame('openid', $query['scope']);
        self::assertSame($request->state, $query['state']);
        self::assertSame($request->nonce, $query['nonce']);
        self::assertArrayHasKey('code_challenge', $query);
        self::assertSame('S256', $query['code_challenge_method']);
        self::assertCount(8, $query);
    }

    public function testUrlIsBuiltFromTheAuthorizationEndpointNeverHardcoded(): void
    {
        $configuration = $this->configuration();
        $request = $this->client()->oidcBegin($configuration, 'https://app.test/callback');

        self::assertStringStartsWith($configuration->authorization_endpoint, $request->url);
    }

    public function testStateNonceAndCodeVerifierAreNeverStoredByTheSdk(): void
    {
        // Nothing to assert on "storage" directly (the point IS that there's no such
        // storage) -- but two independent calls must produce two independent, unrelated
        // triples, proving no shared/cached state leaks between them (§12.3 rule 1).
        $client = $this->client();
        $first = $client->oidcBegin($this->configuration(), 'https://app.test/callback');
        $second = $client->oidcBegin($this->configuration(), 'https://app.test/callback');

        self::assertNotSame($first->state, $second->state);
        self::assertNotSame($first->nonce, $second->nonce);
        self::assertNotSame($first->codeVerifier->reveal(), $second->codeVerifier->reveal());
    }

    public function testScopeDefaultsToOpenid(): void
    {
        $request = $this->client()->oidcBegin($this->configuration(), 'https://app.test/callback');

        self::assertSame('openid', self::queryOf($request->url)['scope']);
    }

    public function testOpenidIsAddedWhenCallerOmitsIt(): void
    {
        $request = $this->client()->oidcBegin($this->configuration(), 'https://app.test/callback', scope: 'profile email');

        $scope = self::queryOf($request->url)['scope'];
        self::assertStringContainsString('openid', $scope);
        self::assertStringContainsString('profile', $scope);
        self::assertStringContainsString('email', $scope);
    }

    public function testArrayScopeIsSpaceJoined(): void
    {
        $request = $this->client()->oidcBegin($this->configuration(), 'https://app.test/callback', scope: ['profile', 'email']);

        self::assertSame('openid profile email', self::queryOf($request->url)['scope']);
    }

    public function testDuplicateOpenidIsNotDoubled(): void
    {
        $request = $this->client()->oidcBegin($this->configuration(), 'https://app.test/callback', scope: 'openid openid profile');

        self::assertSame(1, substr_count(self::queryOf($request->url)['scope'], 'openid'));
    }

    /** Port-brief addendum item 10: spaces are percent-encoded as %20, never '+'. */
    public function testSpacesInScopeArePercentEncodedNotPlusEncoded(): void
    {
        $request = $this->client()->oidcBegin($this->configuration(), 'https://app.test/callback', scope: 'profile email');

        self::assertStringContainsString('%20', $request->url);
        self::assertStringNotContainsString('+', $request->url);
    }

    public function testExtraParamsAreAddedToTheAuthorizationUrl(): void
    {
        $request = $this->client()->oidcBegin(
            $this->configuration(),
            'https://app.test/callback',
            extraParams: ['prompt' => 'login', 'login_hint' => 'alice@example.test'],
        );

        $query = self::queryOf($request->url);
        self::assertSame('login', $query['prompt']);
        self::assertSame('alice@example.test', $query['login_hint']);
    }

    /** §12.1 rule 5: extraParams may not override an SDK-owned parameter. */
    public function testExtraParamsCannotOverrideAnSdkOwnedParameter(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->client()->oidcBegin(
            $this->configuration(),
            'https://app.test/callback',
            extraParams: ['response_type' => 'token'],
        );
    }

    /** @dataProvider reservedParamProvider */
    public function testEveryReservedParameterIsProtected(string $reserved): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->client()->oidcBegin($this->configuration(), 'https://app.test/callback', extraParams: [$reserved => 'x']);
    }

    /** @return list<array{0:string}> */
    public static function reservedParamProvider(): array
    {
        return [
            ['response_type'], ['client_id'], ['redirect_uri'], ['scope'],
            ['state'], ['nonce'], ['code_challenge'], ['code_challenge_method'],
        ];
    }

    public function testCodeChallengeMethodIsAlwaysS256NeverPlain(): void
    {
        $request = $this->client()->oidcBegin($this->configuration(), 'https://app.test/callback');

        self::assertSame('S256', self::queryOf($request->url)['code_challenge_method']);
    }

    public function testMissingOidcClientIdRaisesAuthError(): void
    {
        $client = new AxiamClient(self::BASE_URL, 'acme-tenant', transportHandler: new MockHandler([]));

        $this->expectException(\Axiam\Sdk\Core\AuthError::class);
        $client->oidcBegin($this->configuration(), 'https://app.test/callback');
    }
}
