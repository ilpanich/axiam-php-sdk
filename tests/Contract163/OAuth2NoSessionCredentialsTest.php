<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract163;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Oidc\OidcConfiguration;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * CONTRACT.md §6.1 rule 11 and §12.1 rule 3 (contract 1.63), with §14.6's new test: a jar
 * holding session cookies, then a device authorization, a device poll and a token request —
 * neither an `axiam_*` cookie nor `X-CSRF-Token` is sent on any of the three.
 */
final class OAuth2NoSessionCredentialsTest extends TestCase
{
    private const BASE_URL = 'https://api.test';

    /** @var list<array{request: RequestInterface}> */
    private array $history = [];

    public function testNoSessionCookieAndNoCsrfHeaderReachAnOAuth2Request(): void
    {
        $login = new Response(200, [
            'Set-Cookie' => ['axiam_access=at; Path=/', 'axiam_refresh=rt; Path=/', 'axiam_csrf=c; Path=/'],
            'X-CSRF-Token' => 'csrf-from-login',
            'Content-Type' => 'application/json',
        ], (string) json_encode(['user' => ['id' => 'u1']]));
        $device = new Response(200, [], (string) json_encode([
            'device_code' => 'dc', 'user_code' => 'WDJB-MJHT',
            'verification_uri' => self::BASE_URL . '/device', 'expires_in' => 600, 'interval' => 1,
        ]));
        $token = new Response(200, [], (string) json_encode([
            'access_token' => 'tok', 'token_type' => 'Bearer', 'expires_in' => 900,
        ]));
        $stack = HandlerStack::create(new MockHandler([$login, $device, $token, $token]));
        $stack->push(Middleware::history($this->history));
        $client = new AxiamClient(
            self::BASE_URL,
            'acme',
            oidcClientId: 'my-client',
            oidcClientSecret: 'secret',
            oidcTenantId: '22222222-2222-4222-8222-222222222222',
            transportHandler: $stack,
            retryEnabled: false,
        );
        $configuration = new OidcConfiguration(
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
            grant_types_supported: ['urn:ietf:params:oauth:grant-type:device_code', 'client_credentials'],
            device_authorization_endpoint: self::BASE_URL . '/oauth2/device_authorization',
        );

        $client->login('alice@example.test', 'pw');
        $client->deviceAuthorize(configuration: $configuration);
        $client->devicePoll('dc', configuration: $configuration);
        $client->loginClientCredentials(configuration: $configuration);

        // The login did arm the session: its own follow-ups would carry both.
        self::assertCount(4, $this->history);
        foreach ([1, 2, 3] as $i) {
            $request = $this->history[$i]['request'];
            self::assertStringStartsWith('/oauth2/', $request->getUri()->getPath());
            self::assertFalse($request->hasHeader('Cookie'), $request->getUri()->getPath() . ' carries a Cookie header');
            self::assertFalse($request->hasHeader('X-CSRF-Token'), $request->getUri()->getPath() . ' carries X-CSRF-Token');
            self::assertFalse($request->hasHeader('Authorization'));
        }
    }
}
