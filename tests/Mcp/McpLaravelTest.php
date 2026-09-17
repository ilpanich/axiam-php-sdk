<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Mcp;

use Axiam\Sdk\AccessEnforcer;
use Axiam\Sdk\Attributes\RequireAccess;
use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Laravel\AxiamMiddleware;
use Axiam\Sdk\Management\ValidationError;
use Axiam\Sdk\Mcp\Mcp;
use Firebase\JWT\JWT;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * CONTRACT.md §28.9's tests 3–5 and the off-by-default regression, on the Laravel
 * surface ({@see AxiamMiddleware}, {@see AccessEnforcer} via `Route::axiam.access` /
 * `#[RequireAccess]`). Drives a REAL {@see AxiamClient} through its `transportHandler`
 * test-only seam, the same idiom {@see \Axiam\Sdk\Tests\LaravelMiddlewareTest} and
 * {@see \Axiam\Sdk\Tests\AccessEnforcerTest} already use.
 *
 * The fixture is §28.9's own, shared with {@see McpContractTest} and
 * {@see \Axiam\Sdk\Tests\Mcp\McpSymfonyTest} — a divergence between the two framework
 * bridges shows up here as a different expected value, never as a different test.
 */
final class McpLaravelTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/../Fixtures';
    private const TENANT = 'acme-tenant';
    private const BASE_URL = 'https://api.test';

    private const RESOURCE = 'https://mcp.example.com/mcp';
    private const AUTHORIZATION_SERVERS = ['https://axiam.example.com'];
    private const SCOPES_SUPPORTED = ['mcp:read', 'mcp:tools'];
    private const METADATA_URL = 'https://mcp.example.com/.well-known/oauth-protected-resource/mcp';
    private const METADATA_PATH = '/.well-known/oauth-protected-resource/mcp';

    /** @var array{user_id: string, tenant_id: string, roles: list<string>} */
    private const IDENTITY = [
        'user_id' => '11111111-1111-1111-1111-111111111111',
        'tenant_id' => self::TENANT,
        'roles' => [],
    ];
    private const RESOURCE_ID = '22222222-2222-2222-2222-222222222222';

    /** @return array<string,mixed> */
    private function jwks(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_jwks.json'), true);
        self::assertIsArray($decoded);

        return $decoded;
    }

    /** @return array{0:string,1:string} [raw 64-byte secret key, kid]. */
    private function keypair(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_keypair.json'), true);
        self::assertIsArray($decoded);

        return [(string) base64_decode(strtr($decoded['secret_key_b64url'], '-_', '+/'), true), $decoded['kid']];
    }

    /** @param array<string,mixed> $claims */
    private function sign(array $claims): string
    {
        [$secretKey, $kid] = $this->keypair();

        return JWT::encode($claims, base64_encode($secretKey), 'EdDSA', $kid);
    }

    private function validToken(string $aud = self::RESOURCE): string
    {
        return $this->sign(['sub' => 'user-1', 'tenant_id' => self::TENANT, 'exp' => time() + 900, 'aud' => $aud]);
    }

    private function expiredToken(): string
    {
        return $this->sign(['sub' => 'user-1', 'tenant_id' => self::TENANT, 'exp' => time() - 7200, 'aud' => self::RESOURCE]);
    }

    /** @return list<Response> */
    private function discoveryAndJwks(): array
    {
        return [
            new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks'])),
            new Response(200, [], (string) json_encode($this->jwks())),
        ];
    }

    /** @param list<Response> $queue */
    private function clientWith(array $queue, ?string $expectedAudience = self::RESOURCE): AxiamClient
    {
        return new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            transportHandler: new MockHandler($queue),
            expectedAudience: $expectedAudience,
        );
    }

    private function passthroughNext(): \Closure
    {
        return static fn (Request $request): JsonResponse => new JsonResponse(['ok' => true], 200);
    }

    // ---------------------------------------------------------------------------------
    // Test 3: 401 with the challenge.
    // ---------------------------------------------------------------------------------

    public function testNoCredentialReturns401WithVector1Exactly(): void
    {
        $middleware = new AxiamMiddleware($this->clientWith([]), self::TENANT, self::METADATA_URL);

        $response = $middleware->handle(Request::create('/mcp/tools', 'GET'), $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
        self::assertSame(
            sprintf('Bearer resource_metadata="%s"', self::METADATA_URL),
            $response->headers->get('WWW-Authenticate'),
        );
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('AuthError', $body['error']);
        self::assertArrayNotHasKey('error_description', $body);
    }

    public function testExpiredTokenReturns401WithVector2Exactly(): void
    {
        $middleware = new AxiamMiddleware($this->clientWith($this->discoveryAndJwks()), self::TENANT, self::METADATA_URL);

        $request = Request::create('/mcp/tools', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $this->expiredToken());
        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
        self::assertSame(
            sprintf('Bearer error="invalid_token", resource_metadata="%s"', self::METADATA_URL),
            $response->headers->get('WWW-Authenticate'),
        );
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('AuthError', $body['error']);
        self::assertArrayNotHasKey('error_description', $body);
    }

    public function testMetadataDocumentIsReachableWithNoCredentialWhenTheGuardIsGlobal(): void
    {
        $middleware = new AxiamMiddleware($this->clientWith([]), self::TENANT, self::METADATA_URL);

        // No Authorization header, no cookie — and the middleware is the ONLY thing
        // standing in front of this path, exactly as it would be if mounted globally
        // (->middleware('axiam.auth') applied to every route). It must exempt this one
        // path itself (CONTRACT.md §28.3 rule 2) and hand off to $next — the document
        // route registered separately by Route::serveProtectedResourceMetadata().
        $response = $middleware->handle(Request::create(self::METADATA_PATH, 'GET'), $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    public function testServeProtectedResourceMetadataResponseShape(): void
    {
        $metadata = Mcp::protectedResourceMetadata(self::RESOURCE, self::AUTHORIZATION_SERVERS, self::SCOPES_SUPPORTED);
        $response = Mcp::toJsonResponse($metadata);

        self::assertSame(200, $response->getStatusCode());
        self::assertStringStartsWith('application/json', (string) $response->headers->get('Content-Type'));
        // Symfony's ResponseHeaderBag computes Cache-Control from its own directive set
        // and may reorder it (e.g. "max-age=3600, public"); RFC 7234 gives the
        // directives no order, so this asserts the SET rather than a literal string —
        // unlike WWW-Authenticate, where CONTRACT.md §28.4 pins the exact order.
        $directives = array_map('trim', explode(',', (string) $response->headers->get('Cache-Control')));
        sort($directives);
        self::assertSame(['max-age=3600', 'public'], $directives);
        self::assertSame('*', $response->headers->get('Access-Control-Allow-Origin'));
        self::assertFalse($response->headers->has('Access-Control-Allow-Credentials'));
        self::assertSame($metadata->document, json_decode((string) $response->getContent(), true));
    }

    // ---------------------------------------------------------------------------------
    // Test 4: 403 insufficient_scope.
    // ---------------------------------------------------------------------------------

    /** @param list<Response> $queue */
    private function enforcerWith(array $queue): AccessEnforcer
    {
        return new AccessEnforcer($this->clientWith($queue), resourceMetadataUrl: self::METADATA_URL);
    }

    public function testNoGrantWithScopeReturns403WithVector3Exactly(): void
    {
        $enforcer = $this->enforcerWith([
            new Response(200, [], (string) json_encode(['allowed' => false, 'reason_code' => 'no_grant'])),
        ]);

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'invoke', resourceParam: 'id', scope: 'mcp:tools'),
            ['id' => self::RESOURCE_ID],
        );

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(403, $response->getStatusCode());
        self::assertSame(
            sprintf('Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="%s"', self::METADATA_URL),
            $response->headers->get('WWW-Authenticate'),
        );
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('authorization_denied', $body['error']);
    }

    public function testDeniedByRuleCarriesNoChallenge(): void
    {
        $enforcer = $this->enforcerWith([
            new Response(200, [], (string) json_encode(['allowed' => false, 'reason_code' => 'denied_by_rule'])),
        ]);

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'invoke', resourceParam: 'id', scope: 'mcp:tools'),
            ['id' => self::RESOURCE_ID],
        );

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(403, $response->getStatusCode());
        self::assertFalse($response->headers->has('WWW-Authenticate'));
    }

    public function testAbsentReasonCodeCarriesNoChallenge(): void
    {
        $enforcer = $this->enforcerWith([
            new Response(200, [], (string) json_encode(['allowed' => false])),
        ]);

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'invoke', resourceParam: 'id', scope: 'mcp:tools'),
            ['id' => self::RESOURCE_ID],
        );

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(403, $response->getStatusCode());
        self::assertFalse($response->headers->has('WWW-Authenticate'));
    }

    public function testDenialWithNoScopeArgumentCarriesNoChallenge(): void
    {
        $enforcer = $this->enforcerWith([
            new Response(200, [], (string) json_encode(['allowed' => false, 'reason_code' => 'no_grant'])),
        ]);

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'invoke', resourceParam: 'id'),
            ['id' => self::RESOURCE_ID],
        );

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(403, $response->getStatusCode());
        self::assertFalse($response->headers->has('WWW-Authenticate'));
    }

    // ---------------------------------------------------------------------------------
    // Test 5: a token whose `aud` is not the resource is refused.
    // ---------------------------------------------------------------------------------

    public function testTokenWithAudForAnotherResourceIsRefused401WithVector2(): void
    {
        $middleware = new AxiamMiddleware($this->clientWith($this->discoveryAndJwks()), self::TENANT, self::METADATA_URL);

        $request = Request::create('/mcp/tools', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $this->validToken(aud: 'https://other.example.com/mcp'));
        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
        self::assertSame(
            sprintf('Bearer error="invalid_token", resource_metadata="%s"', self::METADATA_URL),
            $response->headers->get('WWW-Authenticate'),
        );
    }

    public function testTokenWithGeneralPurposeAxiamUserAudienceIsRefused401(): void
    {
        $middleware = new AxiamMiddleware($this->clientWith($this->discoveryAndJwks()), self::TENANT, self::METADATA_URL);

        $request = Request::create('/mcp/tools', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $this->validToken(aud: 'axiam:user'));
        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
        self::assertSame(
            sprintf('Bearer error="invalid_token", resource_metadata="%s"', self::METADATA_URL),
            $response->headers->get('WWW-Authenticate'),
        );
    }

    public function testTokenWithTheExpectedAudienceIsAdmitted(): void
    {
        $middleware = new AxiamMiddleware($this->clientWith($this->discoveryAndJwks()), self::TENANT, self::METADATA_URL);

        $request = Request::create('/mcp/tools', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $this->validToken());
        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(200, $response->getStatusCode());
    }

    public function testResourceMetadataUrlWithoutExpectedAudienceFailsAtConstructionNamingBothOptions(): void
    {
        $client = $this->clientWith([], expectedAudience: null);

        try {
            new AxiamMiddleware($client, self::TENANT, self::METADATA_URL);
            self::fail('expected a ValidationError');
        } catch (ValidationError $e) {
            self::assertStringContainsString('resourceMetadataUrl', $e->getMessage());
            self::assertStringContainsString('expectedAudience', $e->getMessage());
        }
    }

    // ---------------------------------------------------------------------------------
    // Regression: with resourceMetadataUrl unset, nothing changes.
    // ---------------------------------------------------------------------------------

    public function testWithResourceMetadataUrlUnsetNo401EverCarriesAHeader(): void
    {
        $middleware = new AxiamMiddleware($this->clientWith([], expectedAudience: null), self::TENANT);

        $response = $middleware->handle(Request::create('/mcp/tools', 'GET'), $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
        self::assertFalse($response->headers->has('WWW-Authenticate'), 'the header must be ABSENT, not empty — a bare Bearer challenge is still a failure of this rule');
    }

    public function testWithResourceMetadataUrlUnsetTheMetadataPathIsNotExempted(): void
    {
        $middleware = new AxiamMiddleware($this->clientWith([], expectedAudience: null), self::TENANT);

        // Same path a configured guard would exempt — with the option OFF this is an
        // ordinary route like any other, and an ordinary unauthenticated request to it
        // still 401s.
        $response = $middleware->handle(Request::create(self::METADATA_PATH, 'GET'), $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testWithResourceMetadataUrlUnsetNo403EverCarriesAHeader(): void
    {
        $enforcer = new AccessEnforcer($this->clientWith(
            [new Response(200, [], (string) json_encode(['allowed' => false, 'reason_code' => 'no_grant']))],
            expectedAudience: null,
        ));

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'invoke', resourceParam: 'id', scope: 'mcp:tools'),
            ['id' => self::RESOURCE_ID],
        );

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(403, $response->getStatusCode());
        self::assertFalse($response->headers->has('WWW-Authenticate'));
    }
}
