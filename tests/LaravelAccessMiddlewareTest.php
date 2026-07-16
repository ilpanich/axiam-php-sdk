<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AccessEnforcer;
use Axiam\Sdk\Attributes\RequireAccess;
use Axiam\Sdk\Attributes\RequireAuth;
use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Laravel\AxiamAccessMiddleware;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * A minimal stand-in for `Illuminate\Routing\Route`: exposes only the two methods
 * {@see \Axiam\Sdk\Laravel\AxiamAccessMiddleware} actually reads off it
 * (`getActionName()`, `parameters()`) via duck-typed `method_exists()` calls — see that
 * class's own docblock for why it never references the real Illuminate class by name.
 */
final class FakeLaravelRoute
{
    /** @param array<string,mixed> $parameters */
    public function __construct(private readonly string $actionName, private readonly array $parameters)
    {
    }

    public function getActionName(): string
    {
        return $this->actionName;
    }

    /** @return array<string,mixed> */
    public function parameters(): array
    {
        return $this->parameters;
    }
}

/**
 * A `Symfony\Component\HttpFoundation\Request` subclass that additionally exposes
 * `route(): ?FakeLaravelRoute`, mimicking the ONE extra method a real
 * `Illuminate\Http\Request` carries that {@see AxiamAccessMiddleware}'s
 * attribute-reflection style depends on. Built via the parent `Request::create()`
 * factory (which internally does `new static(...)`, so late static binding hands back
 * an instance of THIS subclass) so every other `Request` behavior (attributes, cookies,
 * headers) stays real.
 */
final class FakeLaravelRequest extends Request
{
    public ?FakeLaravelRoute $fakeRoute = null;

    public function route(): ?FakeLaravelRoute
    {
        return $this->fakeRoute;
    }
}

/**
 * A controller fixture for the attribute-reflection style, mirroring
 * {@see AccessAttributeFixtureController} (the Symfony-side twin) so both bridges are
 * proven against the same attribute shapes.
 */
final class LaravelAccessFixtureController
{
    #[RequireAuth]
    public function authOnly(): string
    {
        return 'ok';
    }

    #[RequireAccess(action: 'read', resourceParam: 'id')]
    public function readDocument(): string
    {
        return 'ok';
    }
}

/**
 * The full CONTRACT.md §11 matrix for {@see AxiamAccessMiddleware}, covering BOTH
 * developer-experience styles it supports (string-param and attribute-reflection),
 * driven through a REAL {@see AccessEnforcer}/{@see AxiamClient} pair (never a PHPUnit
 * mock — `AxiamClient` is `final`), mirroring every other bridge test in this suite
 * (e.g. {@see LaravelMiddlewareTest}).
 */
final class LaravelAccessMiddlewareTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const FIXTURE_USER_ID = '11111111-1111-1111-1111-111111111111';

    /** @var array{user_id: string, tenant_id: string, roles: list<string>} */
    private const IDENTITY = [
        'user_id' => self::FIXTURE_USER_ID,
        'tenant_id' => 'acme-tenant',
        'roles' => ['editor'],
    ];

    /** @param list<Response> $queue */
    private function middlewareWith(array $queue): AxiamAccessMiddleware
    {
        $client = new AxiamClient(self::BASE_URL, 'acme-tenant', transportHandler: new MockHandler($queue));

        return new AxiamAccessMiddleware(new AccessEnforcer($client));
    }

    private function passthroughNext(): \Closure
    {
        return static fn (Request $request): JsonResponse => new JsonResponse(['ok' => true], 200);
    }

    // ================================================================
    // String-param style: axiam.access:ACTION,SCOPE(optional),RESOURCE_PARAM(optional)
    // ================================================================

    public function testStringParamFormMissingActionThrows(): void
    {
        // An explicit empty-string action (e.g. ->middleware('axiam.access:')) is a
        // programming error — distinct from calling with NO params at all, which
        // instead selects the attribute-reflection style (see the next test).
        $middleware = $this->middlewareWith([]);
        $request = Request::create('/documents/1', 'GET');
        $request->attributes->set('axiam_user', self::IDENTITY);

        $this->expectException(\InvalidArgumentException::class);

        $middleware->handle($request, $this->passthroughNext(), '');
    }

    public function testStringParamFormAllowsUsingDefaultResourceParam(): void
    {
        // Only 'action' given: scope defaults to null, resourceParam defaults to 'id'.
        $middleware = $this->middlewareWith([new Response(200, [], (string) json_encode(['allowed' => true]))]);
        $request = Request::create('/documents/22222222-2222-2222-2222-222222222222', 'GET');
        $request->attributes->set('axiam_user', self::IDENTITY);
        $request->attributes->set('id', '22222222-2222-2222-2222-222222222222');

        $response = $middleware->handle($request, $this->passthroughNext(), 'read');

        self::assertSame(200, $response->getStatusCode());
    }

    public function testStringParamFormMatchingTaskExampleAllows(): void
    {
        // Exactly the illustrative form this middleware's own docblock documents:
        // ->middleware('axiam.access:read,documents,id') == action=read, scope=documents,
        // resourceParam=id.
        $captured = [];
        $mock = new MockHandler([new Response(200, [], (string) json_encode(['allowed' => true]))]);
        $transportHandler = static function ($request, $options) use ($mock, &$captured) {
            $captured[] = $request;

            return $mock($request, $options);
        };
        $client = new AxiamClient(self::BASE_URL, 'acme-tenant', transportHandler: $transportHandler);
        $middleware = new AxiamAccessMiddleware(new AccessEnforcer($client));

        $request = Request::create('/documents/22222222-2222-2222-2222-222222222222', 'GET');
        $request->attributes->set('axiam_user', self::IDENTITY);
        $request->attributes->set('id', '22222222-2222-2222-2222-222222222222');

        $response = $middleware->handle($request, $this->passthroughNext(), 'read', 'documents', 'id');

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $captured[0]->getBody(), true);
        self::assertSame('read', $body['action'] ?? null);
        self::assertSame('documents', $body['scope'] ?? null);
        self::assertSame('22222222-2222-2222-2222-222222222222', $body['resource_id'] ?? null);
        self::assertSame(self::FIXTURE_USER_ID, $body['subject_id'] ?? null);
    }

    public function testStringParamFormDenyReturns403(): void
    {
        $middleware = $this->middlewareWith([new Response(200, [], (string) json_encode(['allowed' => false]))]);
        $request = Request::create('/documents/22222222-2222-2222-2222-222222222222', 'DELETE');
        $request->attributes->set('axiam_user', self::IDENTITY);
        $request->attributes->set('id', '22222222-2222-2222-2222-222222222222');

        $response = $middleware->handle($request, $this->passthroughNext(), 'delete');

        self::assertSame(403, $response->getStatusCode());
    }

    public function testStringParamFormNoIdentityReturns401NotServerRoundTrip(): void
    {
        $middleware = $this->middlewareWith([]);
        $request = Request::create('/documents/1', 'GET');

        $response = $middleware->handle($request, $this->passthroughNext(), 'read');

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testStringParamFormMissingResourceParamReturns400(): void
    {
        $middleware = $this->middlewareWith([]);
        $request = Request::create('/documents', 'GET');
        $request->attributes->set('axiam_user', self::IDENTITY);
        // No 'id' attribute set at all.

        $response = $middleware->handle($request, $this->passthroughNext(), 'read');

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(400, $response->getStatusCode());
    }

    // ================================================================
    // Attribute-reflection style: ->middleware('axiam.access') with no params
    // ================================================================

    public function testAttributeStyleWithNoRouteIsANoOpPassthrough(): void
    {
        // A plain Symfony Request (no route() method) — the middleware must degrade to
        // a silent no-op rather than erroring.
        $middleware = $this->middlewareWith([]);
        $request = Request::create('/documents/1', 'GET');
        $request->attributes->set('axiam_user', self::IDENTITY);

        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertSame(200, $response->getStatusCode());
    }

    public function testAttributeStyleRequireAuthWithNoIdentityReturns401(): void
    {
        $middleware = $this->middlewareWith([]);
        $request = FakeLaravelRequest::create('/documents/1', 'GET');
        $request->fakeRoute = new FakeLaravelRoute(LaravelAccessFixtureController::class . '@authOnly', []);

        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(401, $response->getStatusCode());
    }

    public function testAttributeStyleRequireAuthWithIdentityPasses(): void
    {
        $middleware = $this->middlewareWith([]);
        $request = FakeLaravelRequest::create('/documents/1', 'GET');
        $request->attributes->set('axiam_user', self::IDENTITY);
        $request->fakeRoute = new FakeLaravelRoute(LaravelAccessFixtureController::class . '@authOnly', []);

        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertSame(200, $response->getStatusCode());
    }

    public function testAttributeStyleRequireAccessResolvesResourceFromRouteParameters(): void
    {
        $captured = [];
        $mock = new MockHandler([new Response(200, [], (string) json_encode(['allowed' => true]))]);
        $transportHandler = static function ($request, $options) use ($mock, &$captured) {
            $captured[] = $request;

            return $mock($request, $options);
        };
        $client = new AxiamClient(self::BASE_URL, 'acme-tenant', transportHandler: $transportHandler);
        $middleware = new AxiamAccessMiddleware(new AccessEnforcer($client));

        $request = FakeLaravelRequest::create('/documents/22222222-2222-2222-2222-222222222222', 'GET');
        $request->attributes->set('axiam_user', self::IDENTITY);
        $request->fakeRoute = new FakeLaravelRoute(
            LaravelAccessFixtureController::class . '@readDocument',
            ['id' => '22222222-2222-2222-2222-222222222222'],
        );

        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertSame(200, $response->getStatusCode());
        $body = json_decode((string) $captured[0]->getBody(), true);
        self::assertSame('22222222-2222-2222-2222-222222222222', $body['resource_id'] ?? null);
        self::assertSame(self::FIXTURE_USER_ID, $body['subject_id'] ?? null);
    }

    public function testAttributeStyleRequireAccessDenyReturns403(): void
    {
        $middleware = $this->middlewareWith([new Response(200, [], (string) json_encode(['allowed' => false]))]);
        $request = FakeLaravelRequest::create('/documents/22222222-2222-2222-2222-222222222222', 'GET');
        $request->attributes->set('axiam_user', self::IDENTITY);
        $request->fakeRoute = new FakeLaravelRoute(
            LaravelAccessFixtureController::class . '@readDocument',
            ['id' => '22222222-2222-2222-2222-222222222222'],
        );

        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(403, $response->getStatusCode());
    }

    public function testAttributeStyleUnrecognizedControllerClassIsANoOp(): void
    {
        $middleware = $this->middlewareWith([]);
        $request = FakeLaravelRequest::create('/documents/1', 'GET');
        $request->fakeRoute = new FakeLaravelRoute('Some\\Nonexistent\\Controller@show', []);

        $response = $middleware->handle($request, $this->passthroughNext());

        self::assertSame(200, $response->getStatusCode());
    }
}
