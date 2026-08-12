<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * A UMA resource set — an AXIAM resource seen through the Protection API
 * (CONTRACT.md §20.1).
 *
 * `$id` is **the AXIAM resource id**, not a parallel identifier: the same UUID is
 * directly usable as the `$resourceId` of a later {@see RequestedPermission}, and as
 * the resource id anywhere else in this SDK.
 */
final class ResourceSet
{
    /**
     * @param string $name Human-readable name, shown in the admin UI.
     * @param string|null $id Assigned by the server on registration; null on the way in.
     * @param string|null $type Free-form resource type. Defaults server-side to `uma_resource` when null, so a resource server that omits it does not produce a row that sorts oddly next to hand-made ones.
     * @param list<string> $resourceScopes The scope names a resource server may ask for on this resource. **Replaced wholesale by an update, never merged** (§20.2 rule 8) — this SDK does not read the current scopes and fold them into an update payload as a convenience, because that would make removing a scope impossible through it.
     */
    public function __construct(
        public readonly string $name,
        public readonly ?string $id = null,
        public readonly ?string $type = null,
        public readonly array $resourceScopes = [],
    ) {
    }
}
