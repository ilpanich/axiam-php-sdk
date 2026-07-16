<?php

declare(strict_types=1);

namespace Axiam\Sdk\Attributes;

use Attribute;

/**
 * Declarative local role check (CONTRACT.md §11, canonical `require_role(role...)`,
 * MAY-level helper). Placing this attribute on a controller method or class does not
 * itself perform any check — it is metadata read by the framework-specific enforcement
 * listener ({@see \Axiam\Sdk\Symfony\AxiamAccessAttributeListener},
 * {@see \Axiam\Sdk\Laravel\AxiamAccessMiddleware}), which delegates to
 * {@see \Axiam\Sdk\AccessEnforcer::enforceRole()}.
 *
 * Zero framework dependency — this class has no runtime dependency beyond the built-in
 * `Attribute` class.
 *
 * **This is a LOCAL check only** (CONTRACT.md §11.2.9): it reads the `roles` already
 * present in the verified identity injected by the CONTRACT.md §10 authentication
 * guard (the `axiam_user` request attribute) and never makes a server round-trip.
 * Passes when the identity's roles intersect with ANY of {@see self::$roles} (logical
 * OR, matching the shared cross-SDK semantics). Role names are tenant-defined and this
 * check is intentionally coarse — {@see \Axiam\Sdk\Attributes\RequireAccess} (backed by
 * the server's authoritative RBAC engine) is the ONLY check that should gate access to
 * a specific resource; do not use `RequireRole` as a substitute for it.
 *
 * An unauthenticated request is a 401 `authentication_failed` response (a role check
 * requires an identity to read roles from); a request whose identity's roles do not
 * intersect {@see self::$roles} is a 403 `authorization_denied` response.
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]
final class RequireRole
{
    /** @var list<string> */
    public readonly array $roles;

    /**
     * @param string ...$roles One or more tenant-defined role names; the check passes
     *                         when the identity holds at least one of them.
     */
    public function __construct(string ...$roles)
    {
        $this->roles = array_values($roles);
    }
}
