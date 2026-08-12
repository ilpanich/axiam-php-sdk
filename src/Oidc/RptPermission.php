<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * One entry of an RPT's `permissions` claim (CONTRACT.md §20.1).
 *
 * **A record of a decision already made, not a live authorization answer**
 * (§20.2 rule 7). These are the pairs the engine allowed when the RPT was minted; a
 * grant revoked afterwards does not empty a live RPT. Do not cache them beyond the
 * token's own expiry — which is why that expiry is short.
 */
final class RptPermission
{
    /**
     * @param string $resourceId The resource the engine allowed.
     * @param list<string> $resourceScopes The scopes it allowed on that resource.
     * @param int $exp Absolute expiry, seconds since the epoch.
     */
    public function __construct(
        public readonly string $resourceId,
        public readonly array $resourceScopes,
        public readonly int $exp,
    ) {
    }
}
