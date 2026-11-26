<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract168;

use Axiam\Sdk\AccessEnforcer;
use Axiam\Sdk\Attributes\RequireAuth;
use Axiam\Sdk\Attributes\RequireRole;
use Axiam\Sdk\Attributes\RequireScope;
use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Laravel\AxiamAccessMiddleware;
use Axiam\Sdk\Laravel\AxiamMiddleware;
use Axiam\Sdk\Symfony\AxiamAccessAttributeListener;
use Axiam\Sdk\Symfony\AxiamAuthSubscriber;
use Axiam\Sdk\Tests\Fixtures\AccessTokenFixtureTrait;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response as PsrResponse;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/** Minimal `Illuminate\Routing\Route` stand-in: the two methods {@see AxiamAccessMiddleware} reads. */
final class Contract168Route
{
    public function __construct(private readonly string $action)
    {
    }

    public function getActionName(): string
    {
        return $this->action;
    }

    /** @return array<string,mixed> */
    public function parameters(): array
    {
        return [];
    }
}

/** A `Request` that also answers `route()`, as `Illuminate\Http\Request` does. */
final class Contract168Request extends Request
{
    public ?Contract168Route $fakeRoute = null;

    public function route(): ?Contract168Route
    {
        return $this->fakeRoute;
    }
}

/** Controller fixtures carrying the §11 attributes the bridges enforce. */
final class Contract168Controller
{
    #[RequireRole('admin')]
    public function roleAdmin(): string
    {
        return 'ok';
    }

    #[RequireScope('admin')]
    public function scopeAdmin(): string
    {
        return 'ok';
    }

    // PHP-R1-1: a route needing several scopes stacks the attribute; every instance must pass.
    #[RequireScope('documents:read')]
    #[RequireScope('documents:write')]
    public function scopeReadAndWrite(): string
    {
        return 'ok';
    }

    #[RequireAuth]
    public function authOnly(): string
    {
        return 'ok';
    }

    public function unguarded(): string
    {
        return 'ok';
    }
}

/**
 * N15 end to end (CONTRACT.md §11.2 rule 11, contract 1.68), through BOTH framework bridges with
 * real signed access tokens: the §10 guard turns the token into an identity, the §11 attribute
 * enforcement decides. Also the ride-along fix: the Laravel attribute-mode middleware DENIES a
 * route whose action it cannot reflect, instead of waving it through as though it needed nothing.
 */
final class RequireRoleScopeBridgesMiddlewareTest extends TestCase
{
    use AccessTokenFixtureTrait;

    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';

    private function client(): AxiamClient
    {
        $jwks = (string) file_get_contents(__DIR__ . '/../Fixtures/ed25519_jwks.json');
        $mock = new MockHandler([
            new PsrResponse(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks'])),
            new PsrResponse(200, [], $jwks),
        ]);

        return new AxiamClient(self::BASE_URL, self::TENANT, transportHandler: $mock);
    }

    // ---- PHP-R1-1: stacked #[RequireScope] is repeatable and all-must-pass --------------

    public function testStackedRequireScopeIsRepeatable(): void
    {
        $attributes = (new \ReflectionMethod(Contract168Controller::class, 'scopeReadAndWrite'))
            ->getAttributes(RequireScope::class);
        self::assertCount(2, $attributes);
        self::assertSame(['documents:read'], $attributes[0]->newInstance()->scopes);
        self::assertSame(['documents:write'], $attributes[1]->newInstance()->scopes);
    }

    public function testLaravelStackedRequireScopeNeedsEveryInstance(): void
    {
        self::assertSame(200, $this->laravelStatus($this->mintAccessToken(['scope' => 'openid documents:read documents:write']), 'scopeReadAndWrite'));
        self::assertSame(403, $this->laravelStatus($this->mintAccessToken(['scope' => 'openid documents:read']), 'scopeReadAndWrite'));
        self::assertSame(403, $this->laravelStatus($this->mintAccessToken(['scope' => 'openid documents:write']), 'scopeReadAndWrite'));
    }

    public function testSymfonyStackedRequireScopeNeedsEveryInstance(): void
    {
        self::assertSame(200, $this->symfonyStatus($this->mintAccessToken(['scope' => 'openid documents:read documents:write']), 'scopeReadAndWrite'));
        self::assertSame(403, $this->symfonyStatus($this->mintAccessToken(['scope' => 'openid documents:read']), 'scopeReadAndWrite'));
        self::assertSame(403, $this->symfonyStatus($this->mintAccessToken(['scope' => 'openid documents:write']), 'scopeReadAndWrite'));
    }

    // ---- Laravel -------------------------------------------------------------------

    private function laravelStatus(string $token, string $method): int
    {
        $client = $this->client();
        $request = Contract168Request::create('/admin', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);
        $request->fakeRoute = new Contract168Route(Contract168Controller::class . '@' . $method);

        $next = static fn (Request $r): JsonResponse => new JsonResponse(['ok' => true], 200);
        $authenticated = (new AxiamMiddleware($client, self::TENANT))->handle($request, $next);
        self::assertSame(200, $authenticated->getStatusCode(), 'the token itself must pass the §10 guard');

        return (new AxiamAccessMiddleware(new AccessEnforcer($client)))->handle($request, $next)->getStatusCode();
    }

    public function testLaravelScopeOpenidAdminWithNoRolesClaimIs403OnRequireRoleAdmin(): void
    {
        $token = $this->mintAccessToken(['scope' => 'openid admin']);

        self::assertSame(403, $this->laravelStatus($token, 'roleAdmin'));
    }

    public function testLaravelRolesAdminIs200OnRequireRoleAdminWhateverTheScope(): void
    {
        self::assertSame(200, $this->laravelStatus($this->mintAccessToken(['scope' => 'openid', 'roles' => ['admin']]), 'roleAdmin'));
    }

    public function testLaravelRequireScopeAdminIs200ForScopeOpenidAdmin(): void
    {
        self::assertSame(200, $this->laravelStatus($this->mintAccessToken(['scope' => 'openid admin']), 'scopeAdmin'));
    }

    public function testLaravelRolesAdminDoesNotStandInForScopeAdmin(): void
    {
        self::assertSame(403, $this->laravelStatus($this->mintAccessToken(['scope' => 'openid', 'roles' => ['admin']]), 'scopeAdmin'));
    }

    public function testLaravelTheIdentityKeepsRolesAndScopesApart(): void
    {
        $client = $this->client();
        $request = Request::create('/x', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $this->mintAccessToken(['scope' => 'openid admin']));
        (new AxiamMiddleware($client, self::TENANT))->handle($request, static fn (Request $r): JsonResponse => new JsonResponse([]));

        $identity = $request->attributes->get('axiam_user');
        self::assertIsArray($identity);
        self::assertNull($identity['roles'], 'no roles claim: null, which fails every require_role');
        self::assertSame(['openid', 'admin'], $identity['scopes']);
    }

    // ---- Laravel: ride-along, the attribute mode fails closed ----------------------

    private function laravelAttributeModeStatus(Request $request): int
    {
        $client = new AxiamClient(self::BASE_URL, self::TENANT, transportHandler: new MockHandler([]));
        $request->attributes->set('axiam_user', ['user_id' => 'user-1', 'tenant_id' => self::TENANT, 'roles' => ['admin'], 'scopes' => ['admin']]);

        return (new AxiamAccessMiddleware(new AccessEnforcer($client)))
            ->handle($request, static fn (Request $r): JsonResponse => new JsonResponse(['ok' => true], 200))
            ->getStatusCode();
    }

    public function testLaravelAttributeModeDeniesAClosureRoute(): void
    {
        $request = Contract168Request::create('/x', 'GET');
        $request->fakeRoute = new Contract168Route('Closure');

        self::assertSame(403, $this->laravelAttributeModeStatus($request));
    }

    public function testLaravelAttributeModeDeniesARouteWhoseControllerDoesNotResolve(): void
    {
        $request = Contract168Request::create('/x', 'GET');
        $request->fakeRoute = new Contract168Route('Some\\Nonexistent\\Controller@show');

        self::assertSame(403, $this->laravelAttributeModeStatus($request));
        $request->fakeRoute = new Contract168Route(Contract168Controller::class . '@noSuchMethod');
        self::assertSame(403, $this->laravelAttributeModeStatus($request));
    }

    public function testLaravelAttributeModeDeniesARequestWithNoRoute(): void
    {
        // A plain Request (no route() at all), and one whose route() is null.
        self::assertSame(403, $this->laravelAttributeModeStatus(Request::create('/x', 'GET')));
        self::assertSame(403, $this->laravelAttributeModeStatus(Contract168Request::create('/x', 'GET')));
    }

    public function testLaravelAttributeModeStillPassesAReflectableControllerWithNoAttributes(): void
    {
        // Reflected fine, genuinely nothing to enforce: this is "no declaration", not "could not read it".
        $request = Contract168Request::create('/x', 'GET');
        $request->fakeRoute = new Contract168Route(Contract168Controller::class . '@unguarded');

        self::assertSame(200, $this->laravelAttributeModeStatus($request));
    }

    public function testLaravelTheDenialIsAStandardizedJsonBody(): void
    {
        $request = Contract168Request::create('/x', 'GET');
        $request->fakeRoute = new Contract168Route('Closure');
        $client = new AxiamClient(self::BASE_URL, self::TENANT, transportHandler: new MockHandler([]));

        $response = (new AxiamAccessMiddleware(new AccessEnforcer($client)))->handle($request, static fn (Request $r): JsonResponse => new JsonResponse([]));

        self::assertInstanceOf(JsonResponse::class, $response);
        $body = json_decode((string) $response->getContent(), true);
        self::assertSame('authorization_denied', $body['error']);
    }

    // ---- Symfony -------------------------------------------------------------------

    private function symfonyStatus(string $token, string $method): int
    {
        $client = $this->client();
        $request = Request::create('/admin', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);

        $kernel = new class implements HttpKernelInterface {
            public function handle(Request $request, int $type = self::MAIN_REQUEST, bool $catch = true): \Symfony\Component\HttpFoundation\Response
            {
                return new \Symfony\Component\HttpFoundation\Response();
            }
        };
        $requestEvent = new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);
        (new AxiamAuthSubscriber($client, self::TENANT))->onKernelRequest($requestEvent);
        self::assertFalse($requestEvent->hasResponse(), 'the token itself must pass the §10 guard');

        $controller = [new Contract168Controller(), $method];
        $controllerEvent = new ControllerEvent($kernel, $controller, $request, HttpKernelInterface::MAIN_REQUEST);
        (new AxiamAccessAttributeListener(new AccessEnforcer($client)))->onKernelController($controllerEvent);

        if ($controllerEvent->getController() === $controller) {
            return 200;
        }
        $denied = ($controllerEvent->getController())();
        self::assertInstanceOf(JsonResponse::class, $denied);

        return $denied->getStatusCode();
    }

    public function testSymfonyScopeOpenidAdminWithNoRolesClaimIs403OnRequireRoleAdmin(): void
    {
        self::assertSame(403, $this->symfonyStatus($this->mintAccessToken(['scope' => 'openid admin']), 'roleAdmin'));
    }

    public function testSymfonyRolesAdminIs200OnRequireRoleAdmin(): void
    {
        self::assertSame(200, $this->symfonyStatus($this->mintAccessToken(['scope' => 'openid', 'roles' => ['admin']]), 'roleAdmin'));
    }

    public function testSymfonyRequireScopeAdminIs200ForScopeOpenidAdminAnd403ForRolesOnly(): void
    {
        self::assertSame(200, $this->symfonyStatus($this->mintAccessToken(['scope' => 'openid admin']), 'scopeAdmin'));
        self::assertSame(403, $this->symfonyStatus($this->mintAccessToken(['scope' => 'openid', 'roles' => ['admin']]), 'scopeAdmin'));
    }
}
