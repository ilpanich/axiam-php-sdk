<?php

declare(strict_types=1);

namespace Axiam\Sdk\Attributes;

use Attribute;

/**
 * Declares that a role must exist, as part of a CONTRACT.md §27.6 manifest.
 *
 * PHP's declarative idiom is the attribute, and this SDK already uses it for §11
 * ({@see RequireAccess}, {@see RequireRole}). §27.6 gets the same treatment: annotate a
 * class that stands for a tenant's desired shape, and
 * {@see \Axiam\Sdk\Management\Manifest\ManifestAttributeReader} turns it into a
 * {@see \Axiam\Sdk\Management\Manifest\ManagementManifest}.
 *
 * The attribute carries no behaviour. It is metadata, exactly like `RequireAccess` — the
 * reader builds the manifest, and only `apply()` ever writes anything.
 *
 * Repeatable, because one class normally declares a whole tenant.
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::IS_REPEATABLE)]
final class ManagedRole
{
    /**
     * @param string $key         Manifest-local identity, referenced by {@see ManagedGroup}.
     * @param string $name        The role's name on the server.
     * @param string $description Human-readable description.
     * @param bool   $isGlobal    Whether the role applies tenant-wide.
     * @param array<string,string> $grants Permission KEY => `allow` | `deny`. AXIAM's RBAC
     *        is deny-override: an explicit `deny` beats every allow at any depth, so it is
     *        a strong statement rather than a default a narrower allow can reverse.
     */
    public function __construct(
        public readonly string $key,
        public readonly string $name,
        public readonly string $description = '',
        public readonly bool $isGlobal = false,
        public readonly array $grants = [],
    ) {
    }
}
