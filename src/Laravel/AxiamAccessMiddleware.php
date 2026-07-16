<?php

declare(strict_types=1);

namespace Axiam\Sdk\Laravel;

use Axiam\Sdk\AccessEnforcer;
use Axiam\Sdk\Attributes\RequireAccess;
use Axiam\Sdk\Attributes\RequireAuth;
use Axiam\Sdk\Attributes\RequireRole;
use Closure;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

/**
 * Laravel CONTRACT.md §11 declarative-authorization enforcement middleware, registered
 * under the `axiam.access` alias (D-02). Supports BOTH developer-experience styles the
 * plan calls for, from the SAME class, delegating every actual decision to the shared
 * {@see AccessEnforcer} (never re-implementing resource resolution, subject
 * propagation, or the error-mapping table itself):
 *
 *   1. **String-param style** — `->middleware('axiam.access:read,documents,id')`, i.e.
 *      `axiam.access:<action>,<scope?>,<resourceParam?>`. `<action>` is required;
 *      `<scope>` defaults to `null` (pass `''` — an empty CSV segment — to explicitly
 *      skip it while still supplying a `<resourceParam>`); `<resourceParam>` defaults
 *      to `'id'`, matching this SDK's own `/documents/{id}`-shaped example routes, so
 *      the common case only needs `axiam.access:read` or `axiam.access:read,documents`.
 *      This style never inspects controller attributes — the string params ARE the
 *      declaration for that route.
 *   2. **Attribute style** — no middleware params at all
 *      (`->middleware('axiam.access')`), in which case this middleware reflects the
 *      CURRENT ROUTE's resolved controller (via `$request->route()`) for
 *      `#[RequireAuth]`/`#[RequireRole]`/`#[RequireAccess]` (method-level attributes
 *      take precedence over class-level ones), mirroring exactly how
 *      {@see \Axiam\Sdk\Symfony\AxiamAccessAttributeListener} reflects the Symfony
 *      controller callable — so a consuming application can annotate a controller
 *      method once and reuse it from either framework's bridge.
 *
 * Deliberately type-hinted against `Symfony\Component\HttpFoundation\Request` (not
 * `Illuminate\Http\Request`), same rationale as {@see AxiamMiddleware}'s own doc
 * comment: a real `Illuminate\Http\Request` IS a
 * `Symfony\Component\HttpFoundation\Request`, and Laravel's kernel always passes the
 * real subclass to route middleware, so this avoids a new `illuminate/http` dev/runtime
 * dependency. The one wrinkle this class alone has to work around: `route()` (and the
 * returned route's `getActionName()`/`parameters()`) exist only on
 * `Illuminate\Http\Request`/`Illuminate\Routing\Route`, not on the Symfony parent type
 * this class declares — {@see self::currentRoute()} reads them via a `method_exists()`
 * guard followed by a variable-method-name call (not a literal `$request->route()`
 * call), so neither PHPStan (which only knows the declared Symfony type) nor this
 * class's own autoloading ever needs `Illuminate\Http\Request`/`Illuminate\Routing\Route`
 * to exist as concrete, referenceable classes — the attribute-reflection style degrades
 * to a silent no-op on any `Request` implementation that lacks a `route()` method
 * (including a plain Symfony `Request` used directly, e.g. in tests).
 */
final class AxiamAccessMiddleware
{
    public function __construct(private readonly AccessEnforcer $enforcer)
    {
    }

    /**
     * @param Request $request Inbound request.
     * @param Closure $next    Next middleware in the pipeline.
     * @param string  ...$params String-param style arguments — `<action>,<scope?>,<resourceParam?>`
     *        (see this class's own docblock). When empty, the attribute-reflection
     *        style is used instead.
     *
     * @return mixed The next middleware's response, or a 401/403/400/503 JSON error response.
     */
    public function handle(Request $request, Closure $next, string ...$params): mixed
    {
        $rawIdentity = $request->attributes->get('axiam_user');
        /** @var array{user_id: string, tenant_id: string, roles: list<string>}|null $identity */
        $identity = is_array($rawIdentity) ? $rawIdentity : null;

        $response = $params !== []
            ? $this->enforceFromParams($identity, $request, $params)
            : $this->enforceFromAttributes($identity, $request);

        return $response ?? $next($request);
    }

    /**
     * @param array{user_id: string, tenant_id: string, roles: list<string>}|null $identity
     * @param list<string> $params
     */
    private function enforceFromParams(?array $identity, Request $request, array $params): ?JsonResponse
    {
        $action = $params[0] ?? null;
        if (!is_string($action) || $action === '') {
            throw new \InvalidArgumentException(
                "axiam.access middleware requires at least an action parameter, e.g. ->middleware('axiam.access:read')",
            );
        }

        $scope = ($params[1] ?? '') !== '' ? $params[1] : null;
        $resourceParam = ($params[2] ?? '') !== '' ? $params[2] : 'id';

        $attribute = new RequireAccess(action: $action, resourceId: null, resourceParam: $resourceParam, scope: $scope);

        return $this->enforcer->enforceAccess($identity, $attribute, $this->routeParams($request));
    }

    /** @param array{user_id: string, tenant_id: string, roles: list<string>}|null $identity */
    private function enforceFromAttributes(?array $identity, Request $request): ?JsonResponse
    {
        $reflected = $this->reflectRouteController($request);
        if ($reflected === null) {
            return null;
        }
        [$method, $class] = $reflected;

        $requireAuth = $this->findAttribute($method, $class, RequireAuth::class);
        $requireRole = $this->findAttribute($method, $class, RequireRole::class);
        $requireAccess = $this->findAttribute($method, $class, RequireAccess::class);

        if ($requireAuth === null && $requireRole === null && $requireAccess === null) {
            return null;
        }

        $response = null;
        if ($requireAuth !== null) {
            $response = $this->enforcer->enforceAuth($identity);
        }
        if ($response === null && $requireRole !== null) {
            $response = $this->enforcer->enforceRole($identity, $requireRole);
        }
        if ($response === null && $requireAccess !== null) {
            $response = $this->enforcer->enforceAccess($identity, $requireAccess, $this->routeParams($request));
        }

        return $response;
    }

    /**
     * Resolves `[ReflectionMethod, ReflectionClass]` for the CURRENT route's controller
     * action, or `null` when there is no route (`$request->route()` unavailable — e.g.
     * a plain Symfony `Request` in a unit test), the route has no controller (a
     * `Closure`-based route — PHP forbids `Attribute::TARGET_METHOD`/`TARGET_CLASS`
     * attributes on a `Closure` entirely, so there is nothing to reflect), or the
     * resolved controller class/method does not actually exist.
     *
     * @return array{0: \ReflectionMethod, 1: \ReflectionClass<object>}|null
     */
    private function reflectRouteController(Request $request): ?array
    {
        $route = $this->currentRoute($request);
        if ($route === null || !method_exists($route, 'getActionName')) {
            return null;
        }

        $accessor = 'getActionName';
        $actionName = $route->$accessor();
        if (!is_string($actionName) || !str_contains($actionName, '@')) {
            return null;
        }

        [$className, $methodName] = explode('@', $actionName, 2);
        if (!class_exists($className) || !method_exists($className, $methodName)) {
            return null;
        }

        try {
            return [new \ReflectionMethod($className, $methodName), new \ReflectionClass($className)];
        } catch (\ReflectionException) {
            return null;
        }
    }

    /**
     * The resolved route's parameters (`Illuminate\Routing\Route::parameters()`), or a
     * fallback to `$request->attributes->all()` when no Laravel route is available —
     * this keeps {@see self::enforceFromParams()}'s `resourceParam` lookup and
     * {@see self::enforceFromAttributes()}'s `RequireAccess::$resourceParam` lookup
     * working the same way in a plain-Symfony-`Request` unit test as in a real Laravel
     * request.
     *
     * @return array<string,mixed>
     */
    private function routeParams(Request $request): array
    {
        $route = $this->currentRoute($request);
        if ($route !== null && method_exists($route, 'parameters')) {
            $accessor = 'parameters';
            $parameters = $route->$accessor();
            if (is_array($parameters)) {
                /** @var array<string,mixed> $parameters */
                return $parameters;
            }
        }

        return $request->attributes->all();
    }

    /**
     * Duck-typed `$request->route()` accessor (see this class's own docblock for why
     * this is a variable-method-name call rather than a literal `$request->route()`
     * one). Returns `null` when the request has no such method (a plain Symfony
     * `Request`) or the route itself is `null` (no route matched / not yet resolved).
     */
    private function currentRoute(Request $request): ?object
    {
        if (!method_exists($request, 'route')) {
            return null;
        }

        $accessor = 'route';
        $route = $request->$accessor();

        return is_object($route) ? $route : null;
    }

    /**
     * Reads a single instance of `$attributeClass` off `$method`, falling back to
     * `$class` when the method carries none — method-level attributes take precedence
     * over class-level ones (mirrors
     * {@see \Axiam\Sdk\Symfony\AxiamAccessAttributeListener}'s own resolution order
     * exactly, so the two bridges never disagree on which attribute wins).
     *
     * @template T of object
     * @param class-string<T> $attributeClass
     * @param \ReflectionClass<object> $class
     *
     * @return T|null
     */
    private function findAttribute(\ReflectionMethod $method, \ReflectionClass $class, string $attributeClass): ?object
    {
        $methodAttributes = $method->getAttributes($attributeClass);
        if ($methodAttributes !== []) {
            /** @var T */
            return $methodAttributes[0]->newInstance();
        }

        $classAttributes = $class->getAttributes($attributeClass);
        if ($classAttributes !== []) {
            /** @var T */
            return $classAttributes[0]->newInstance();
        }

        return null;
    }
}
