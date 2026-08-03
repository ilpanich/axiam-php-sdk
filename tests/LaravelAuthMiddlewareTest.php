<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Laravel\AxiamMiddleware;
use Firebase\JWT\JWT;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Edge coverage for {@see AxiamMiddleware} (D-02, CONTRACT.md §10/§3) complementing
 * {@see LaravelMiddlewareTest}'s primary flows: a non-Bearer `Authorization` header, a
 * cookie-authenticated write missing the `axiam_csrf` cookie, a signature-valid token
 * with a malformed claim shape (empty `sub`), and the two non-array `roles`/`scope`
 * claim shapes {@see AxiamMiddleware::rolesFromClaims()} normalizes. Tokens are re-signed
 * with the committed Ed25519 fixture keypair (same approach as {@see JwtVerifyTest}) so
 * they verify against the fixture JWKS while carrying the exact claims under test.
 */
final class LaravelAuthMiddlewareTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/Fixtures';
    private const FIXTURE_TENANT = 'acme-tenant';
    private const BASE_URL = 'https://api.test';

    /** @return array<string,mixed> */
    private function fixtureJwks(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_jwks.json'), true);
        self::assertIsArray($decoded);

        return $decoded;
    }

    /** @param array<string,mixed> $claims */
    private function signedJwt(array $claims): string
    {
        $keypair = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_keypair.json'), true);
        self::assertIsArray($keypair);
        $secretKey = (string) base64_decode(strtr($keypair['secret_key_b64url'], '-_', '+/'), true);

        return JWT::encode(
            $claims + ['exp' => 4102444800],
            base64_encode($secretKey),
            'EdDSA',
            $keypair['kid'],
        );
    }

    /** @param list<Response> $queue */
    private function clientWith(array $queue): AxiamClient
    {
        return new AxiamClient(self::BASE_URL, self::FIXTURE_TENANT, transportHandler: new MockHandler($queue));
    }

    private function jwksQueue(): array
    {
        return [
            new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks'])),
            new Response(200, [], (string) json_encode($this->fixtureJwks())),
        ];
    }

    private function passthroughNext(): \Closure
    {
        return static fn (Request $request): JsonResponse => new JsonResponse(['ok' => true], 200);
    }

    public function testNonBearerAuthorizationHeaderReturns401(): void
    {
        // A non-Bearer scheme is treated as "no credential" — never a cookie fallback.
        $middleware = new AxiamMiddleware($this->clientWith([]), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Basic dXNlcjpwYXNz');
        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testCookieWriteWithCsrfHeaderButNoCsrfCookieReturns403(): void
    {
        // The X-CSRF-Token header is present but there is no axiam_csrf cookie to
        // double-submit against, so the constant-time check fails closed.
        $middleware = new AxiamMiddleware($this->clientWith([]), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'POST');
        $request->cookies->set('axiam_access', 'some-token');
        $request->headers->set('X-CSRF-Token', 'header-value');
        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(403, $response->getStatusCode());
    }

    public function testSignatureValidTokenWithEmptySubReturns401(): void
    {
        $token = $this->signedJwt(['sub' => '', 'tenant_id' => self::FIXTURE_TENANT]);
        $middleware = new AxiamMiddleware($this->clientWith($this->jwksQueue()), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);
        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
    }

    /**
     * CONTRACT.md §10.1 rule 4: the token's `tenant_id` MUST be asserted against the
     * CONFIGURED tenant. `X-Tenant-ID` is attacker-controlled, so letting it select the
     * expected value would compare the token against itself — a vacuous check that lets
     * any tenant's token into an app configured for a different one.
     */
    public function testAttackerSuppliedTenantHeaderCannotOverrideTheConfiguredTenant(): void
    {
        $token = $this->signedJwt(['sub' => 'evil', 'tenant_id' => 'attacker-tenant']);
        $middleware = new AxiamMiddleware($this->clientWith($this->jwksQueue()), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);
        $request->headers->set('X-Tenant-ID', 'attacker-tenant');
        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
    }

    /** A matching `X-Tenant-ID` header still narrows correctly and is admitted. */
    public function testMatchingTenantHeaderStillNarrowsAndIsAdmitted(): void
    {
        $token = $this->signedJwt(['sub' => 'user-x', 'tenant_id' => self::FIXTURE_TENANT]);
        $middleware = new AxiamMiddleware($this->clientWith($this->jwksQueue()), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);
        $request->headers->set('X-Tenant-ID', self::FIXTURE_TENANT);
        $middleware->handle($request, $this->passthroughNext());

        self::assertSame('user-x', $request->attributes->get('axiam_user')['user_id']);
    }

    /**
     * CONTRACT.md §10.1 rule 2, end to end through the guard: a signature-valid,
     * correct-tenant token carrying NO `exp` claim is a permanent credential and must
     * be rejected. Asserted at the GUARD level (not only at the verifier) so the guard
     * genuinely routing through the full §10.1 set is itself under test.
     */
    public function testTokenWithNoExpClaimIsRejectedByTheGuard(): void
    {
        // NOTE: bypasses signedJwt(), which always adds an exp.
        $keypair = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_keypair.json'), true);
        self::assertIsArray($keypair);
        $secretKey = (string) base64_decode(strtr($keypair['secret_key_b64url'], '-_', '+/'), true);
        $token = JWT::encode(
            ['sub' => 'user-x', 'tenant_id' => self::FIXTURE_TENANT],
            base64_encode($secretKey),
            'EdDSA',
            $keypair['kid'],
        );
        $middleware = new AxiamMiddleware($this->clientWith($this->jwksQueue()), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);
        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testScopeStringClaimIsNormalizedToRolesList(): void
    {
        $token = $this->signedJwt([
            'sub' => 'user-x',
            'tenant_id' => self::FIXTURE_TENANT,
            'scope' => 'read write delete',
        ]);
        $middleware = new AxiamMiddleware($this->clientWith($this->jwksQueue()), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);
        $middleware->handle($request, $this->passthroughNext());

        self::assertSame(
            ['read', 'write', 'delete'],
            $request->attributes->get('axiam_user')['roles'],
        );
    }

    public function testNonStringRolesClaimNormalizesToEmptyList(): void
    {
        $token = $this->signedJwt([
            'sub' => 'user-x',
            'tenant_id' => self::FIXTURE_TENANT,
            'roles' => 123,
        ]);
        $middleware = new AxiamMiddleware($this->clientWith($this->jwksQueue()), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);
        $middleware->handle($request, $this->passthroughNext());

        self::assertSame([], $request->attributes->get('axiam_user')['roles']);
    }
}
