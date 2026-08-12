<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * One `(resource, scopes)` pair a resource server requires (CONTRACT.md §20.1).
 */
final class RequestedPermission
{
    /**
     * @param string $resourceId The AXIAM resource id — the same UUID the Protection API returned as `_id`.
     * @param list<string> $resourceScopes Scope names, each of which the resource must already declare. Matched exactly: no prefix or wildcard semantics in either direction.
     */
    public function __construct(
        public readonly string $resourceId,
        public readonly array $resourceScopes,
    ) {
    }
}
