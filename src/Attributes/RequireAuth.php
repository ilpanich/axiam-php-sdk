<?php

declare(strict_types=1);

namespace Axiam\Sdk\Attributes;

use Attribute;

/**
 * Declarative "endpoint requires an authenticated AXIAM identity" marker (CONTRACT.md
 * §11, canonical `require_auth`). Pure sugar over the CONTRACT.md §10 authentication
 * guard for frameworks (Laravel, Symfony) where that guard is applied per-route rather
 * than globally: placing this attribute on a controller method or class does not itself
 * perform any verification — it is read by the framework-specific enforcement listener
 * ({@see \Axiam\Sdk\Symfony\AxiamAccessAttributeListener},
 * {@see \Axiam\Sdk\Laravel\AxiamAccessMiddleware}) which delegates the actual check to
 * {@see \Axiam\Sdk\AccessEnforcer::enforceAuth()}.
 *
 * Zero framework dependency — this class has no constructor arguments and imports
 * nothing beyond the built-in `Attribute` class, so it is safe to reference from any
 * PHP ≥8.1 codebase regardless of which (if any) web framework is installed.
 *
 * A missing/invalid/expired identity is a 401 `authentication_failed` response
 * (CONTRACT.md §11.2.5) — never a silent pass-through.
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]
final class RequireAuth
{
}
