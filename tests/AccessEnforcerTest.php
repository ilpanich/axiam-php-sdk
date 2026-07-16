<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AccessEnforcer;
use Axiam\Sdk\Attributes\RequireAccess;
use Axiam\Sdk\Attributes\RequireRole;
use Axiam\Sdk\AxiamClient;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Request as Psr7Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * The full CONTRACT.md §11 matrix for {@see AccessEnforcer} — the ONE enforcement
 * implementation both framework bridges ({@see \Axiam\Sdk\Symfony\AxiamAccessAttributeListener},
 * {@see \Axiam\Sdk\Laravel\AxiamAccessMiddleware}) delegate to. Drives a REAL
 * {@see AxiamClient} wired via its `transportHandler` test-only seam (the same idiom
 * every other REST test in this suite uses, e.g. {@see LaravelMiddlewareTest}) — never
 * a PHPUnit mock (`AxiamClient` is `final`, by design). The base transport handler here
 * is a small capturing wrapper around a {@see MockHandler} rather than a bare one, so
 * this suite can additionally assert exactly what reaches the wire (`subject_id`,
 * `scope`) — CONTRACT.md §11.2.2/§11.2.4.
 */
final class AccessEnforcerTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const FIXTURE_USER_ID = '11111111-1111-1111-1111-111111111111';
    private const FIXTURE_RESOURCE_ID = '22222222-2222-2222-2222-222222222222';

    /** @var array{user_id: string, tenant_id: string, roles: list<string>} */
    private const IDENTITY = [
        'user_id' => self::FIXTURE_USER_ID,
        'tenant_id' => 'acme-tenant',
        'roles' => ['editor'],
    ];

    /**
     * @param list<Response|\Throwable> $queue
     * @param list<RequestInterface> $captured Populated, in order, with every request
     *        that reaches the transport (i.e. fully decorated by AuthMiddleware) —
     *        lets a test assert the exact wire body/headers without needing Guzzle's
     *        `Middleware::history()` (which cannot be injected through AxiamClient's
     *        own internal `HandlerStack` construction).
     */
    private function clientWith(array $queue, array &$captured = []): AxiamClient
    {
        $mock = new MockHandler($queue);
        $transportHandler = static function (RequestInterface $request, array $options) use ($mock, &$captured) {
            $captured[] = $request;

            return $mock($request, $options);
        };

        return new AxiamClient(self::BASE_URL, 'acme-tenant', transportHandler: $transportHandler);
    }

    private function enforcerWith(array $queue, array &$captured = []): AccessEnforcer
    {
        return new AccessEnforcer($this->clientWith($queue, $captured));
    }

    // --- require_auth (CONTRACT.md §11.1) -------------------------------------------

    public function testEnforceAuthWithNoIdentityReturns401(): void
    {
        $enforcer = $this->enforcerWith([]);

        $response = $enforcer->enforceAuth(null);

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('authentication_failed', $body['error']);
    }

    public function testEnforceAuthWithIdentityReturnsNull(): void
    {
        $enforcer = $this->enforcerWith([]);

        self::assertNull($enforcer->enforceAuth(self::IDENTITY));
    }

    // --- require_role (CONTRACT.md §11.1/§11.2.9 — local, no server round-trip) -----

    public function testEnforceRoleWithNoIdentityReturns401NotServerRoundTrip(): void
    {
        // Empty queue: a require_role check on an unauthenticated request must never
        // reach the server at all.
        $enforcer = $this->enforcerWith([]);

        $response = $enforcer->enforceRole(null, new RequireRole('admin'));

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testEnforceRoleAllowsWhenIdentityHoldsOneOfTheRequiredRoles(): void
    {
        // Empty queue: require_role never calls the server (CONTRACT.md §11.2.9).
        $enforcer = $this->enforcerWith([]);

        $response = $enforcer->enforceRole(self::IDENTITY, new RequireRole('admin', 'editor'));

        self::assertNull($response);
    }

    public function testEnforceRoleDeniesWhenIdentityHoldsNoneOfTheRequiredRoles(): void
    {
        $enforcer = $this->enforcerWith([]);

        $response = $enforcer->enforceRole(self::IDENTITY, new RequireRole('admin', 'owner'));

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('authorization_denied', $body['error']);
    }

    // --- require_access (CONTRACT.md §11.1): unauthenticated -> 401, never calls server

    public function testEnforceAccessWithNoIdentityReturns401NotServerRoundTrip(): void
    {
        $captured = [];
        $enforcer = $this->enforcerWith([], $captured);

        $response = $enforcer->enforceAccess(null, new RequireAccess(action: 'read', resourceParam: 'id'), ['id' => self::FIXTURE_RESOURCE_ID]);

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
        self::assertCount(0, $captured, 'an unauthenticated require_access check must never reach the wire');
    }

    // --- require_access: allow --------------------------------------------------------

    public function testEnforceAccessAllowReturnsNull(): void
    {
        $captured = [];
        $enforcer = $this->enforcerWith([new Response(200, [], (string) json_encode(['allowed' => true]))], $captured);

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'read', resourceParam: 'id'),
            ['id' => self::FIXTURE_RESOURCE_ID],
        );

        self::assertNull($response);
        self::assertCount(1, $captured);
    }

    // --- require_access: subject_id on the wire (CONTRACT.md §11.2.2) ---------------

    public function testEnforceAccessSendsAuthenticatedUserIdAsSubjectIdOnTheWire(): void
    {
        $captured = [];
        $enforcer = $this->enforcerWith([new Response(200, [], (string) json_encode(['allowed' => true]))], $captured);

        $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'read', resourceParam: 'id'),
            ['id' => self::FIXTURE_RESOURCE_ID],
        );

        self::assertCount(1, $captured);
        $body = json_decode((string) $captured[0]->getBody(), true);
        self::assertSame(self::FIXTURE_USER_ID, $body['subject_id'] ?? null, 'subject_id must be the REQUEST\'s authenticated user, never omitted');
        self::assertSame('read', $body['action'] ?? null);
        self::assertSame(self::FIXTURE_RESOURCE_ID, $body['resource_id'] ?? null);
    }

    // --- require_access: scope passthrough (CONTRACT.md §11.2.4) --------------------

    public function testEnforceAccessPassesScopeThroughVerbatim(): void
    {
        $captured = [];
        $enforcer = $this->enforcerWith([new Response(200, [], (string) json_encode(['allowed' => true]))], $captured);

        $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'read', resourceParam: 'id', scope: 'confidential'),
            ['id' => self::FIXTURE_RESOURCE_ID],
        );

        $body = json_decode((string) $captured[0]->getBody(), true);
        self::assertSame('confidential', $body['scope'] ?? null);
    }

    // --- require_access: deny -> 403 (200 response, allowed=false) -------------------

    public function testEnforceAccessDenyReturns403(): void
    {
        $enforcer = $this->enforcerWith([new Response(200, [], (string) json_encode(['allowed' => false]))]);

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'delete', resourceParam: 'id'),
            ['id' => self::FIXTURE_RESOURCE_ID],
        );

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('authorization_denied', $body['error']);
    }

    // --- require_access: deny -> 403 (server itself returns 403, AuthzError path) ----

    public function testEnforceAccessServerAuthzErrorReturns403(): void
    {
        $enforcer = $this->enforcerWith([new Response(403, [], (string) json_encode(['error' => 'AuthzError', 'message' => 'forbidden']))]);

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'delete', resourceParam: 'id'),
            ['id' => self::FIXTURE_RESOURCE_ID],
        );

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(403, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('authorization_denied', $body['error']);
    }

    // --- require_access: unresolvable resource -> 400 (missing route param) ---------

    public function testEnforceAccessMissingRouteParamReturns400NotServerRoundTrip(): void
    {
        $captured = [];
        $enforcer = $this->enforcerWith([], $captured);

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'read', resourceParam: 'id'),
            [], // no 'id' route param present
        );

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(400, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('invalid_request', $body['error']);
        self::assertCount(0, $captured, 'an unresolvable resource must never reach the wire');
    }

    // --- require_access: unresolvable resource -> 400 (non-UUID route param value) --

    public function testEnforceAccessNonUuidRouteParamReturns400(): void
    {
        $enforcer = $this->enforcerWith([]);

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'read', resourceParam: 'id'),
            ['id' => 'not-a-uuid'],
        );

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(400, $response->getStatusCode());
    }

    // --- require_access: unresolvable resource -> 400 (non-UUID resourceId literal) -

    public function testEnforceAccessNonUuidResourceIdLiteralReturns400(): void
    {
        $enforcer = $this->enforcerWith([]);

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'read', resourceId: 'not-a-uuid'),
            [],
        );

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(400, $response->getStatusCode());
    }

    // --- require_access: static resourceId literal takes precedence over resourceParam

    public function testEnforceAccessStaticResourceIdLiteralTakesPrecedence(): void
    {
        $captured = [];
        $enforcer = $this->enforcerWith([new Response(200, [], (string) json_encode(['allowed' => true]))], $captured);

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'read', resourceId: self::FIXTURE_RESOURCE_ID, resourceParam: 'id'),
            ['id' => '33333333-3333-3333-3333-333333333333'], // must be ignored
        );

        self::assertNull($response);
        $body = json_decode((string) $captured[0]->getBody(), true);
        self::assertSame(self::FIXTURE_RESOURCE_ID, $body['resource_id'] ?? null);
    }

    // --- require_access: resolver callback used when resourceParam is unset ---------

    public function testEnforceAccessUsesResolverWhenResourceParamIsNull(): void
    {
        $captured = [];
        $enforcer = $this->enforcerWith([new Response(200, [], (string) json_encode(['allowed' => true]))], $captured);

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'read', resourceParam: null),
            [],
            static fn (): string => self::FIXTURE_RESOURCE_ID,
        );

        self::assertNull($response);
        $body = json_decode((string) $captured[0]->getBody(), true);
        self::assertSame(self::FIXTURE_RESOURCE_ID, $body['resource_id'] ?? null);
    }

    public function testEnforceAccessResolverReturningNonUuidReturns400(): void
    {
        $enforcer = $this->enforcerWith([]);

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'read', resourceParam: null),
            [],
            static fn (): ?string => null,
        );

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(400, $response->getStatusCode());
    }

    // --- require_access: transport failure -> 503, fail-closed (CONTRACT.md §11.2.5) -

    public function testEnforceAccessNetworkErrorFailsClosedWith503(): void
    {
        $enforcer = $this->enforcerWith([
            new ConnectException('connection refused', new Psr7Request('POST', '/api/v1/authz/check')),
        ]);

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'read', resourceParam: 'id'),
            ['id' => self::FIXTURE_RESOURCE_ID],
        );

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(503, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('authz_unavailable', $body['error']);
    }

    // --- require_access: the shared client's OWN session 401s mid-check -> 503, -----
    // --- fail-closed (never manufactures a false "re-authenticate" prompt for a -----
    // --- request whose end user was already verified by the §10 guard) --------------

    public function testEnforceAccessClientAuthErrorFailsClosedWith503(): void
    {
        $enforcer = $this->enforcerWith([new Response(401, [], (string) json_encode(['error' => 'AuthError', 'message' => 'unauthenticated']))]);

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'read', resourceParam: 'id'),
            ['id' => self::FIXTURE_RESOURCE_ID],
        );

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(503, $response->getStatusCode());
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('authz_unavailable', $body['error']);
    }

    // --- redaction (CONTRACT.md §11.2.8): no token material in any output -----------

    public function testNoTokenMaterialInAnyErrorOutput(): void
    {
        $enforcer = $this->enforcerWith([
            new ConnectException('connection refused', new Psr7Request('POST', '/api/v1/authz/check')),
        ]);

        $response = $enforcer->enforceAccess(
            self::IDENTITY,
            new RequireAccess(action: 'read', resourceParam: 'id'),
            ['id' => self::FIXTURE_RESOURCE_ID],
        );

        self::assertInstanceOf(JsonResponse::class, $response);
        $raw = (string) $response->getContent();
        self::assertStringNotContainsString('Bearer', $raw);
        self::assertStringNotContainsString(self::FIXTURE_USER_ID, $raw, 'the identity itself must not leak into the error body');
    }
}
