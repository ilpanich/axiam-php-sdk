<?php

declare(strict_types=1);

namespace Axiam\Sdk\Attributes;

use Attribute;

/**
 * Declares that a group must exist, as part of a CONTRACT.md §27.6 manifest.
 *
 * See {@see ManagedRole} for why the declarative layer wears an attribute in PHP.
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::IS_REPEATABLE)]
final class ManagedGroup
{
    /**
     * @param string       $key         Manifest-local identity.
     * @param string       $name        The group's name on the server.
     * @param string       $description Human-readable description.
     * @param list<string> $roleKeys    KEYS of the roles this group carries.
     * @param array<string,mixed> $metadata Free-form metadata.
     */
    public function __construct(
        public readonly string $key,
        public readonly string $name,
        public readonly string $description = '',
        public readonly array $roleKeys = [],
        public readonly array $metadata = [],
    ) {
    }
}
