<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Laravel\OidcCallbackController;
use Axiam\Sdk\Laravel\OidcLoginController;
use Axiam\Sdk\Oidc\MemoryOidcStateStore;
use Axiam\Sdk\Oidc\OidcLoginFlow;
use Axiam\Sdk\Oidc\OidcLoginOutcome;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * {@see OidcLoginController} / {@see OidcCallbackController} (CONTRACT.md §12, plan
 * T8 item 2): the invokable Laravel controllers translate an {@see OidcLoginOutcome}
 * from the shared {@see OidcLoginFlow} into a `Symfony\Component\HttpFoundation`
 * response — this test proves that translation for all three outcome kinds, plus the
 * query-parameter extraction each `__invoke()` performs.
 *
 * Lives in the `integration` testsuite (same reasoning as
 * {@see \Axiam\Sdk\Tests\LaravelMiddlewareTest}): these controllers are reachable only
 * behind a `class_exists(Symfony\Component\HttpFoundation\Request::class)` guard, and
 * this test needs that class to actually be installed.
 */
final class LaravelOidcControllerTest extends TestCase
{
    private const BASE_URL = 'https://api.test';

    /** @param array<int,Response> $queue */
    private function client(array $queue): AxiamClient
    {
        return new AxiamClient(
            self::BASE_URL,
            'acme-tenant',
            oidcClientId: 'my-app',
            oidcTenantId: '66666666-6666-6666-6666-666666666666',
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

    // ===================================================================================
    // toResponse(): all three OidcLoginOutcome kinds
    // ===================================================================================

    public function testToResponseTranslatesRedirectOutcome(): void
    {
        $response = OidcLoginController::toResponse(OidcLoginOutcome::redirect('https://idp.example/authorize'));

        self::assertInstanceOf(RedirectResponse::class, $response);
        self::assertSame('https://idp.example/authorize', $response->getTargetUrl());
    }

    public function testToResponseTranslatesJsonOutcome(): void
    {
        $response = OidcLoginController::toResponse(OidcLoginOutcome::json('user-1', 900));

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(200, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);
        self::assertTrue($data['authenticated']);
        self::assertSame('user-1', $data['sub']);
        self::assertSame(900, $data['expiresIn']);
    }

    public function testToResponseTranslatesErrorOutcome(): void
    {
        $response = OidcLoginController::toResponse(OidcLoginOutcome::error(401, 'authentication_failed', 'nope'));

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
        $data = json_decode((string) $response->getContent(), true);
        self::assertSame('authentication_failed', $data['error']);
        self::assertSame('nope', $data['message']);
    }

    // ===================================================================================
    // OidcLoginController::__invoke
    // ===================================================================================

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

    public function testLoginControllerInvokeWithoutReturnToStillWorks(): void
    {
        $store = new MemoryOidcStateStore();
        $flow = new OidcLoginFlow($this->client([$this->discoveryResponse()]), $store, 'https://app.test/callback');
        $controller = new OidcLoginController($flow);

        $response = $controller(Request::create('/auth/axiam/login'));

        self::assertInstanceOf(RedirectResponse::class, $response);
    }

    public function testLoginControllerInvokeFailsClosedOn503WhenAxiamUnreachable(): void
    {
        $flow = new OidcLoginFlow($this->client([]), new MemoryOidcStateStore(), 'https://app.test/callback');
        $controller = new OidcLoginController($flow);

        $response = $controller(Request::create('/auth/axiam/login'));

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(503, $response->getStatusCode());
    }

    // ===================================================================================
    // OidcCallbackController::__invoke
    // ===================================================================================

    public function testCallbackControllerInvokeHappyPathReturnsJson(): void
    {
        $store = new MemoryOidcStateStore();
        $store->save(new \Axiam\Sdk\Oidc\OidcStateEntry(
            state: 'state-1',
            nonce: 'nonce-1',
            codeVerifier: new \Axiam\Sdk\Core\Sensitive('verifier-1'),
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

        $response = $controller(Request::create('/auth/axiam/callback?error=access_denied&error_description=nope'));

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testCallbackControllerInvokeMapsMissingCodeTo400(): void
    {
        $flow = new OidcLoginFlow($this->client([]), new MemoryOidcStateStore(), 'https://app.test/callback');
        $controller = new OidcCallbackController($flow);

        $response = $controller(Request::create('/auth/axiam/callback?state=state-1'));

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(400, $response->getStatusCode());
    }
}
