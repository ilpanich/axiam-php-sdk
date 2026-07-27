<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Oidc\MemoryOidcStateStore;
use Axiam\Sdk\Oidc\OidcLoginFlow;
use Axiam\Sdk\Oidc\OidcStateEntry;
use Axiam\Sdk\Symfony\OidcCallbackController;
use Axiam\Sdk\Symfony\OidcLoginController;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * {@see OidcLoginController} / {@see OidcCallbackController} — the Symfony pair
 * (CONTRACT.md §12, plan T8 item 2). Mirrors {@see \Axiam\Sdk\Tests\LaravelOidcControllerTest}
 * one-for-one, proving both framework bridges apply identical §12 semantics through
 * the SAME shared {@see OidcLoginFlow} core.
 *
 * Lives in the `integration` testsuite (needs `symfony/http-foundation`), same
 * reasoning as {@see \Axiam\Sdk\Tests\SymfonyAuthSubscriberTest}.
 */
final class SymfonyOidcControllerTest extends TestCase
{
    private const BASE_URL = 'https://api.test';

    /** @param array<int,Response> $queue */
    private function client(array $queue): AxiamClient
    {
        return new AxiamClient(
            self::BASE_URL,
            'acme-tenant',
            oidcClientId: 'my-app',
            oidcTenantId: '77777777-7777-7777-7777-777777777777',
            transportHandler: new MockHandler($queue),
        );
    }

    private function discoveryResponse(): Response
    {
        return new Response(200, [], (string) json_encode([
            'issuer' => self::BASE_URL,
            'authorization_endpoint' => self::BASE_URL . '/oauth2/authorize',
            'token_endpoint' => self::BASE_URL . '/oauth2/token',
            'userinfo_endpoint' => self::BASE_URL . '/oauth2/userinfo',
            'jwks_uri' => self::BASE_URL . '/oauth2/jwks',
            'revocation_endpoint' => self::BASE_URL . '/oauth2/revoke',
            'introspection_endpoint' => self::BASE_URL . '/oauth2/introspect',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['EdDSA'],
            'scopes_supported' => ['openid'],
            'token_endpoint_auth_methods_supported' => ['client_secret_post'],
            'claims_supported' => ['sub'],
            'grant_types_supported' => ['authorization_code'],
        ]));
    }

    public function testLoginControllerInvokeRedirectsToTheIdp(): void
    {
        $store = new MemoryOidcStateStore();
        $flow = new OidcLoginFlow($this->client([$this->discoveryResponse()]), $store, 'https://app.test/callback');
        $controller = new OidcLoginController($flow);

        $response = $controller(Request::create('/auth/axiam/login?return_to=/dashboard'));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertStringStartsWith(self::BASE_URL . '/oauth2/authorize', (string) $response->getTargetUrl());
        self::assertSame(1, $store->size());
    }

    public function testLoginControllerInvokeFailsClosedOn503WhenAxiamUnreachable(): void
    {
        $flow = new OidcLoginFlow($this->client([]), new MemoryOidcStateStore(), 'https://app.test/callback');
        $controller = new OidcLoginController($flow);

        $response = $controller(Request::create('/auth/axiam/login'));

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(503, $response->getStatusCode());
    }

    public function testCallbackControllerInvokeHappyPathReturnsJson(): void
    {
        $store = new MemoryOidcStateStore();
        $store->save(new OidcStateEntry(
            state: 'state-1',
            nonce: 'nonce-1',
            codeVerifier: new Sensitive('verifier-1'),
            redirectUri: 'https://app.test/callback',
        ));
        $flow = new OidcLoginFlow($this->client([
            $this->discoveryResponse(),
            new Response(200, [], (string) json_encode(['access_token' => 'a', 'token_type' => 'Bearer', 'expires_in' => 900])),
        ]), $store, 'https://app.test/callback');
        $controller = new OidcCallbackController($flow);

        $response = $controller(Request::create('/auth/axiam/callback?state=state-1&code=a-code'));

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    public function testCallbackControllerInvokeMapsIdpErrorTo401(): void
    {
        $flow = new OidcLoginFlow($this->client([]), new MemoryOidcStateStore(), 'https://app.test/callback');
        $controller = new OidcCallbackController($flow);

        $response = $controller(Request::create('/auth/axiam/callback?error=access_denied'));

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testCallbackControllerInvokeMapsMissingStateAndCodeTo400(): void
    {
        $flow = new OidcLoginFlow($this->client([]), new MemoryOidcStateStore(), 'https://app.test/callback');
        $controller = new OidcCallbackController($flow);

        $response = $controller(Request::create('/auth/axiam/callback'));

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(400, $response->getStatusCode());
    }
}
