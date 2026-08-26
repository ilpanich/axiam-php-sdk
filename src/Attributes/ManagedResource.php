<?php

declare(strict_types=1);

namespace Axiam\Sdk\Attributes;

use Attribute;

/**
 * Declares that a resource must exist, as part of a CONTRACT.md §27.6 manifest.
 *
 * `$parentKey` names another `ManagedResource`'s KEY, never a UUID: a manifest describes
 * a tenant that may not exist yet, and a UUID does not exist until the first apply.
 * Resources are the one kind where a manifest can describe an impossible shape — a
 * parent cycle — and {@see \Axiam\Sdk\Management\Manifest\ManifestValidation} refuses one
 * before any request is sent.
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::IS_REPEATABLE)]
final class ManagedResource
{
    /**
     * @param string      $key       Manifest-local identity.
     * @param string      $name      The resource's name on the server.
     * @param string      $type      Its `resource_type`.
     * @param string|null $parentKey The KEY of the parent resource, or `null` for a root.
     * @param array<string,mixed> $metadata Free-form metadata.
     */
    public function __construct(
        public readonly string $key,
        public readonly string $name,
        public readonly string $type,
        public readonly ?string $parentKey = null,
        public readonly array $metadata = [],
    ) {
    }
}
