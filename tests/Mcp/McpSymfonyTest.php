<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Mcp;

use Axiam\Sdk\AccessEnforcer;
use Axiam\Sdk\Attributes\RequireAccess;
use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Management\ValidationError;
use Axiam\Sdk\Mcp\Mcp;
use Axiam\Sdk\Symfony\AxiamAuthSubscriber;
use Axiam\Sdk\Symfony\ProtectedResourceMetadataController;
use Firebase\JWT\JWT;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * CONTRACT.md §28.9's tests 3–5 and the off-by-default regression, on the Symfony
 * surface ({@see AxiamAuthSubscriber}, {@see AccessEnforcer} via
 * `AxiamAccessAttributeListener` / `#[RequireAccess]`,
 * {@see ProtectedResourceMetadataController}). Drives a REAL {@see AxiamClient} through
 * its `transportHandler` test-only seam, the same idiom
 * {@see \Axiam\Sdk\Tests\SymfonyAuthSubscriberTest} and
 * {@see \Axiam\Sdk\Tests\AccessEnforcerTest} already use.
 *
 * The fixture is §28.9's own, shared with {@see McpContractTest} and
 * {@see \Axiam\Sdk\Tests\Mcp\McpLaravelTest} — a divergence between the two framework
 * bridges shows up here as a different expected value, never as a different test.
 */
final class McpSymfonyTest extends TestCase
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

    private function requestEvent(Request $request): RequestEvent
    {
        $kernel = new class implements HttpKernelInterface {
            public function handle(Request $request, int $type = self::MAIN_REQUEST, bool $catch = true): \Symfony\Component\HttpFoundation\Response
            {
                return new \Symfony\Component\HttpFoundation\Response();
            }
        };

        return new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);
    }

    // ---------------------------------------------------------------------------------
    // Test 3: 401 with the challenge.
    // ---------------------------------------------------------------------------------

    public function testNoCredentialReturns401WithVector1Exactly(): void
    {
        $subscriber = new AxiamAuthSubscriber($this->clientWith([]), self::TENANT, self::METADATA_URL);

        $event = $this->requestEvent(Request::create('/mcp/tools', 'GET'));
        $subscriber->onKernelRequest($event);

        self::assertTrue($event->hasResponse());
        $response = $event->getResponse();
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
        $subscriber = new AxiamAuthSubscriber($this->clientWith($this->discoveryAndJwks()), self::TENANT, self::METADATA_URL);

        $request = Request::create('/mcp/tools', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $this->expiredToken());
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertTrue($event->hasResponse());
        $response = $event->getResponse();
        self::assertSame(401, $response->getStatusCode());
        self::assertSame(
            sprintf('Bearer error="invalid_token", resource_metadata="%s"', self::METADATA_URL),
            $response->headers->get('WWW-Authenticate'),
        );
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('AuthError', $body['error']);
        self::assertArrayNotHasKey('error_description', $body);
    }

    public function testMetadataDocumentPathIsExemptedWhenTheSubscriberListensOnEveryRequest(): void
    {
        $subscriber = new AxiamAuthSubscriber($this->clientWith([]), self::TENANT, self::METADATA_URL);

        // No Authorization header, no cookie. AxiamAuthSubscriber listens on every
        // request (getSubscribedEvents() -> kernel.request), so it alone decides
        // whether this path 401s; it must exempt it (CONTRACT.md §28.3 rule 2) by
        // leaving no response set, letting the request continue to the controller.
        $event = $this->requestEvent(Request::create(self::METADATA_PATH, 'GET'));
        $subscriber->onKernelRequest($event);

        self::assertFalse($event->hasResponse(), 'the metadata document path must not be short-circuited with a 401');
    }

    public function testProtectedResourceMetadataControllerServesTheDocument(): void
    {
        $metadata = Mcp::protectedResourceMetadata(self::RESOURCE, self::AUTHORIZATION_SERVERS, self::SCOPES_SUPPORTED);
        $controller = new ProtectedResourceMetadataController($metadata);

        $response = $controller();

        self::assertSame(200, $response->getStatusCode());
        self::assertStringStartsWith('application/json', (string) $response->headers->get('Content-Type'));
        self::assertSame('*', $response->headers->get('Access-Control-Allow-Origin'));
        self::assertFalse($response->headers->has('Access-Control-Allow-Credentials'));
        self::assertSame($metadata->document, json_decode((string) $response->getContent(), true));
    }

    public function testProtectedResourceMetadataControllerCrossChecksTheGuard(): void
    {
        $metadata = Mcp::protectedResourceMetadata(self::RESOURCE, self::AUTHORIZATION_SERVERS, self::SCOPES_SUPPORTED);
        $mismatchedGuard = new AxiamAuthSubscriber(
            $this->clientWith([], expectedAudience: 'https://mcp.example.com/mcp'),
            self::TENANT,
            'https://mcp.example.com/.well-known/oauth-protected-resource/OTHER',
        );

        $this->expectException(ValidationError::class);
        new ProtectedResourceMetadataController($metadata, $mismatchedGuard);
    }

    public function testProtectedResourceMetadataControllerRejectsAnAudienceMismatchEvenWhenTheUrlAgrees(): void
    {
        $metadata = Mcp::protectedResourceMetadata(self::RESOURCE, self::AUTHORIZATION_SERVERS, self::SCOPES_SUPPORTED);
        // resourceMetadataUrl agrees with $metadata->metadataUrl; expectedAudience does not
        // agree with $metadata->document['resource'] — the SECOND half of §28.5 rule 3.
        $mismatchedGuard = new AxiamAuthSubscriber(
            $this->clientWith([], expectedAudience: 'https://not-the-resource.example.com'),
            self::TENANT,
            self::METADATA_URL,
        );

        $this->expectException(ValidationError::class);
        new ProtectedResourceMetadataController($metadata, $mismatchedGuard);
    }

    public function testProtectedResourceMetadataControllerAcceptsAnAgreeingGuardWithoutException(): void
    {
        $metadata = Mcp::protectedResourceMetadata(self::RESOURCE, self::AUTHORIZATION_SERVERS, self::SCOPES_SUPPORTED);
        $agreeingGuard = new AxiamAuthSubscriber($this->clientWith([]), self::TENANT, self::METADATA_URL);

        $controller = new ProtectedResourceMetadataController($metadata, $agreeingGuard);
        $response = $controller();

        self::assertSame(200, $response->getStatusCode());
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
        $subscriber = new AxiamAuthSubscriber($this->clientWith($this->discoveryAndJwks()), self::TENANT, self::METADATA_URL);

        $request = Request::create('/mcp/tools', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $this->validToken(aud: 'https://other.example.com/mcp'));
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertTrue($event->hasResponse());
        $response = $event->getResponse();
        self::assertSame(401, $response->getStatusCode());
        self::assertSame(
            sprintf('Bearer error="invalid_token", resource_metadata="%s"', self::METADATA_URL),
            $response->headers->get('WWW-Authenticate'),
        );
    }

    public function testTokenWithGeneralPurposeAxiamUserAudienceIsRefused401(): void
    {
        $subscriber = new AxiamAuthSubscriber($this->clientWith($this->discoveryAndJwks()), self::TENANT, self::METADATA_URL);

        $request = Request::create('/mcp/tools', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $this->validToken(aud: 'axiam:user'));
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertTrue($event->hasResponse());
        self::assertSame(401, $event->getResponse()->getStatusCode());
    }

    public function testTokenWithTheExpectedAudienceIsAdmitted(): void
    {
        $subscriber = new AxiamAuthSubscriber($this->clientWith($this->discoveryAndJwks()), self::TENANT, self::METADATA_URL);

        $request = Request::create('/mcp/tools', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $this->validToken());
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertFalse($event->hasResponse(), 'an admitted token must never have a response set on the event');
    }

    public function testResourceMetadataUrlWithoutExpectedAudienceFailsAtConstructionNamingBothOptions(): void
    {
        $client = $this->clientWith([], expectedAudience: null);

        try {
            new AxiamAuthSubscriber($client, self::TENANT, self::METADATA_URL);
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
        $subscriber = new AxiamAuthSubscriber($this->clientWith([], expectedAudience: null), self::TENANT);

        $event = $this->requestEvent(Request::create('/mcp/tools', 'GET'));
        $subscriber->onKernelRequest($event);

        self::assertTrue($event->hasResponse());
        $response = $event->getResponse();
        self::assertSame(401, $response->getStatusCode());
        self::assertFalse($response->headers->has('WWW-Authenticate'), 'the header must be ABSENT, not empty — a bare Bearer challenge is still a failure of this rule');
    }

    public function testWithResourceMetadataUrlUnsetTheMetadataPathIsNotExempted(): void
    {
        $subscriber = new AxiamAuthSubscriber($this->clientWith([], expectedAudience: null), self::TENANT);

        $event = $this->requestEvent(Request::create(self::METADATA_PATH, 'GET'));
        $subscriber->onKernelRequest($event);

        self::assertTrue($event->hasResponse());
        self::assertSame(401, $event->getResponse()->getStatusCode());
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
