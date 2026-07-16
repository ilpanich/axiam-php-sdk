<?php

declare(strict_types=1);

namespace Axiam\Sdk\Attributes;

use Attribute;

/**
 * Declarative per-endpoint authorization requirement (CONTRACT.md §11, canonical
 * `require_access(action, resource[, scope])`). Placing this attribute on a controller
 * method or class does not itself perform any check — it is metadata read by the
 * framework-specific enforcement listener
 * ({@see \Axiam\Sdk\Symfony\AxiamAccessAttributeListener},
 * {@see \Axiam\Sdk\Laravel\AxiamAccessMiddleware}), which resolves the target resource
 * and delegates the actual authorization decision to
 * {@see \Axiam\Sdk\AccessEnforcer::enforceAccess()}.
 *
 * Zero framework dependency — this class has no runtime dependency beyond the built-in
 * `Attribute` class, so it is safe to reference regardless of which (if any) web
 * framework is installed.
 *
 * Resource resolution follows CONTRACT.md §11.2.3, in order of precedence:
 *
 *   1. {@see self::$resourceId} — a static UUID literal, for singleton resources;
 *   2. {@see self::$resourceParam} — the name of a route/path parameter carrying the
 *      resource UUID (defaults to `'id'`);
 *   3. a resolver callback supplied by the caller of the enforcement service for
 *      anything else (body fields, headers, composite lookups) — this attribute itself
 *      carries no resolver callable (attribute arguments must be compile-time
 *      constant expressions in PHP), so a resolver-based check is wired at the
 *      framework-integration call site instead of via this attribute.
 *
 * A missing or unparseable resource value is a 400 `invalid_request` response — never a
 * silent allow, never a nil-UUID fallback (CONTRACT.md §11.2.3).
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]
final class RequireAccess
{
    /**
     * @param string      $action       The AXIAM action being checked (e.g. `read`).
     * @param string|null $resourceId   A static UUID literal identifying the resource,
     *                                  for endpoints that always target one singleton
     *                                  resource. Mutually exclusive in effect with
     *                                  {@see self::$resourceParam} — when both are
     *                                  set, this literal takes precedence
     *                                  (CONTRACT.md §11.2.3a).
     * @param string|null $resourceParam The name of the route/path parameter whose
     *                                  value is the resource UUID. Defaults to `'id'`;
     *                                  ignored when {@see self::$resourceId} is set.
     * @param string|null $scope        Optional sub-resource scope, passed through to
     *                                  `checkAccess` verbatim (CONTRACT.md §11.2.4).
     */
    public function __construct(
        public readonly string $action,
        public readonly ?string $resourceId = null,
        public readonly ?string $resourceParam = 'id',
        public readonly ?string $scope = null,
    ) {
    }
}
