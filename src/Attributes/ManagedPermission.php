<?php

declare(strict_types=1);

namespace Axiam\Sdk\Attributes;

use Attribute;

/**
 * Declares that a permission must exist, as part of a CONTRACT.md §27.6 manifest.
 *
 * See {@see ManagedRole} for why the declarative layer wears an attribute in PHP.
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::IS_REPEATABLE)]
final class ManagedPermission
{
    /**
     * @param string $key         Manifest-local identity, referenced by a role's `grants`.
     * @param string $action      The action this permission names (e.g. `documents:read`).
     * @param string $description Human-readable description.
     */
    public function __construct(
        public readonly string $key,
        public readonly string $action,
        public readonly string $description = '',
    ) {
    }
}
