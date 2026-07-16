<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AccessEnforcer;
use Axiam\Sdk\Attributes\RequireAccess;
use Axiam\Sdk\Attributes\RequireAuth;
use Axiam\Sdk\Attributes\RequireRole;
use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Symfony\AxiamAccessAttributeListener;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * A controller fixture with method-level attributes, exercising every combination
 * {@see SymfonyAccessAttributeListenerTest} drives: an auth-only endpoint, a
 * require_access endpoint resolving its resource from a route parameter, a
 * require_access endpoint with a static resourceId literal, a require_role endpoint,
 * and a plain unguarded endpoint (no attributes at all).
 */
final class AccessAttributeFixtureController
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

    #[RequireAccess(action: 'read', resourceId: '22222222-2222-2222-2222-222222222222')]
    public function staticResource(): string
    {
        return 'ok';
    }

    #[RequireRole('admin', 'owner')]
    public function adminOnly(): string
    {
        return 'ok';
    }

    public function unguarded(): string
    {
        return 'ok';
    }
}

/**
 * A class-level `#[RequireAccess]` that a method carrying none of its own inherits
 * (CONTRACT.md §11 — method-level attributes take precedence over class-level ones,
 * per attribute type; a method with no attribute of a given type falls back to the
 * class-level one, if any), used to prove
 * {@see AxiamAccessAttributeListener}'s class-level fallback.
 */
#[RequireAccess(action: 'read', resourceParam: 'id')]
final class ClassLevelAccessFixtureController
{
    public function inheritsClassLevelCheck(): string
    {
        return 'ok';
    }
}

/**
 * A class-level `#[RequireRole]` that a method's OWN `#[RequireRole]` overrides
 * (same attribute type at both levels — proves method-level truly wins rather than
 * both being combined), used to prove
 * {@see AxiamAccessAttributeListener}'s method-over-class precedence rule.
 */
#[RequireRole('admin')]
final class RoleOverrideFixtureController
{
    #[RequireRole('owner')]
    public function methodLevelOverridesClassLevel(): string
    {
        return 'ok';
    }
}

/**
 * The full CONTRACT.md §11 matrix for {@see AxiamAccessAttributeListener} — proves the
 * listener correctly reflects `#[RequireAuth]`/`#[RequireAccess]`/`#[RequireRole]` off
 * the resolved Symfony controller callable and delegates to a REAL
 * {@see AccessEnforcer}/{@see AxiamClient} pair (wired via the `transportHandler` test
 * seam, same idiom as every other bridge test in this suite, e.g.
 * {@see SymfonyAuthSubscriberTest}) — never a PHPUnit mock (`AxiamClient` is `final`).
 */
final class SymfonyAccessAttributeListenerTest extends TestCase
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
    private function listenerWith(array $queue): AxiamAccessAttributeListener
    {
        $client = new AxiamClient(self::BASE_URL, 'acme-tenant', transportHandler: new MockHandler($queue));

        return new AxiamAccessAttributeListener(new AccessEnforcer($client));
    }

    /** @param array<string,mixed> $routeParams */
    private function controllerEvent(callable $controller, ?array $identity, array $routeParams = []): ControllerEvent
    {
        $request = Request::create('/documents/1', 'GET');
        $request->attributes->set('axiam_user', $identity);
        foreach ($routeParams as $name => $value) {
            $request->attributes->set($name, $value);
        }

        $kernel = new class implements HttpKernelInterface {
            public function handle(Request $request, int $type = self::MAIN_REQUEST, bool $catch = true): \Symfony\Component\HttpFoundation\Response
            {
                return new \Symfony\Component\HttpFoundation\Response();
            }
        };

        return new ControllerEvent($kernel, $controller, $request, HttpKernelInterface::MAIN_REQUEST);
    }

    // --- no attributes at all: controller left completely untouched -----------------

    public function testControllerWithNoAttributesIsLeftUntouched(): void
    {
        $listener = $this->listenerWith([]);
        $controller = [new AccessAttributeFixtureController(), 'unguarded'];
        $event = $this->controllerEvent($controller, null);

        $listener->onKernelController($event);

        self::assertSame($controller, $event->getController(), 'a controller with no #[Require*] attributes must never be replaced');
    }

    // --- require_auth: no identity -> controller replaced, returns 401 --------------

    public function testRequireAuthWithNoIdentityReplacesControllerWith401(): void
    {
        $listener = $this->listenerWith([]);
        $event = $this->controllerEvent([new AccessAttributeFixtureController(), 'authOnly'], null);

        $listener->onKernelController($event);

        $replaced = $event->getController();
        self::assertIsCallable($replaced);
        $response = $replaced();
        self::assertSame(401, $response->getStatusCode());
    }

    // --- require_auth: identity present -> controller untouched ---------------------

    public function testRequireAuthWithIdentityLeavesControllerUntouched(): void
    {
        $listener = $this->listenerWith([]);
        $controller = [new AccessAttributeFixtureController(), 'authOnly'];
        $event = $this->controllerEvent($controller, self::IDENTITY);

        $listener->onKernelController($event);

        self::assertSame($controller, $event->getController());
    }

    // --- require_access: resolved from route parameter, allow -----------------------

    public function testRequireAccessResolvedFromRouteParamAllows(): void
    {
        $listener = $this->listenerWith([new Response(200, [], (string) json_encode(['allowed' => true]))]);
        $controller = [new AccessAttributeFixtureController(), 'readDocument'];
        $event = $this->controllerEvent($controller, self::IDENTITY, ['id' => '22222222-2222-2222-2222-222222222222']);

        $listener->onKernelController($event);

        self::assertSame($controller, $event->getController(), 'an allowed check must never replace the controller');
    }

    // --- require_access: deny -> controller replaced, returns 403 --------------------

    public function testRequireAccessDenyReplacesControllerWith403(): void
    {
        $listener = $this->listenerWith([new Response(200, [], (string) json_encode(['allowed' => false]))]);
        $event = $this->controllerEvent(
            [new AccessAttributeFixtureController(), 'readDocument'],
            self::IDENTITY,
            ['id' => '22222222-2222-2222-2222-222222222222'],
        );

        $listener->onKernelController($event);

        $replaced = $event->getController();
        self::assertIsCallable($replaced);
        self::assertSame(403, $replaced()->getStatusCode());
    }

    // --- require_access: missing route param -> controller replaced, returns 400 ----

    public function testRequireAccessMissingRouteParamReplacesControllerWith400(): void
    {
        $listener = $this->listenerWith([]);
        $event = $this->controllerEvent([new AccessAttributeFixtureController(), 'readDocument'], self::IDENTITY, []);

        $listener->onKernelController($event);

        $replaced = $event->getController();
        self::assertIsCallable($replaced);
        self::assertSame(400, $replaced()->getStatusCode());
    }

    // --- require_access: static resourceId literal, no route param needed -----------

    public function testRequireAccessStaticResourceIdLiteralAllows(): void
    {
        $listener = $this->listenerWith([new Response(200, [], (string) json_encode(['allowed' => true]))]);
        $controller = [new AccessAttributeFixtureController(), 'staticResource'];
        $event = $this->controllerEvent($controller, self::IDENTITY);

        $listener->onKernelController($event);

        self::assertSame($controller, $event->getController());
    }

    // --- require_role: local check, allow (no server round-trip) --------------------

    public function testRequireRoleAllowsWithoutServerRoundTrip(): void
    {
        // Empty queue: require_role must never call the server.
        $listener = $this->listenerWith([]);
        $controller = [new AccessAttributeFixtureController(), 'adminOnly'];
        $event = $this->controllerEvent($controller, ['user_id' => self::FIXTURE_USER_ID, 'tenant_id' => 'acme-tenant', 'roles' => ['admin']]);

        $listener->onKernelController($event);

        self::assertSame($controller, $event->getController());
    }

    // --- require_role: local check, deny -> controller replaced, returns 403 --------

    public function testRequireRoleDeniesReplacesControllerWith403(): void
    {
        $listener = $this->listenerWith([]);
        $event = $this->controllerEvent(
            [new AccessAttributeFixtureController(), 'adminOnly'],
            ['user_id' => self::FIXTURE_USER_ID, 'tenant_id' => 'acme-tenant', 'roles' => ['viewer']],
        );

        $listener->onKernelController($event);

        $replaced = $event->getController();
        self::assertIsCallable($replaced);
        self::assertSame(403, $replaced()->getStatusCode());
    }

    // --- class-level #[RequireAccess]: applies when the method itself carries none --

    public function testClassLevelRequireAccessAppliesWhenMethodHasNone(): void
    {
        $listener = $this->listenerWith([]);
        $event = $this->controllerEvent(
            [new ClassLevelAccessFixtureController(), 'inheritsClassLevelCheck'],
            null, // no identity -> 401, proves the class-level attribute was actually read
        );

        $listener->onKernelController($event);

        $replaced = $event->getController();
        self::assertIsCallable($replaced);
        self::assertSame(401, $replaced()->getStatusCode());
    }

    // --- method-level attribute takes precedence over class-level -------------------

    public function testMethodLevelAttributeTakesPrecedenceOverClassLevel(): void
    {
        // Empty queue: require_role never calls the server either way, so an empty
        // queue proves nothing by itself here — what matters is WHICH role list gets
        // checked. The identity holds 'owner' but not 'admin': allowed only if the
        // METHOD-level #[RequireRole('owner')] is what's actually evaluated, denied if
        // the CLASS-level #[RequireRole('admin')] were used instead.
        $listener = $this->listenerWith([]);
        $controller = [new RoleOverrideFixtureController(), 'methodLevelOverridesClassLevel'];
        $event = $this->controllerEvent(
            $controller,
            ['user_id' => self::FIXTURE_USER_ID, 'tenant_id' => 'acme-tenant', 'roles' => ['owner']],
        );

        $listener->onKernelController($event);

        self::assertSame(
            $controller,
            $event->getController(),
            'the method-level RequireRole(owner) must be evaluated, not the class-level RequireRole(admin)',
        );
    }

    // --- a Closure controller has nothing to reflect -> left untouched ---------------

    public function testClosureControllerIsLeftUntouched(): void
    {
        $listener = $this->listenerWith([]);
        $controller = static fn (): string => 'ok';
        $event = $this->controllerEvent($controller, null);

        $listener->onKernelController($event);

        self::assertSame($controller, $event->getController());
    }
}
