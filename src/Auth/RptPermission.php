<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

/**
 * A UMA 2.0 permission carried by an RPT (CONTRACT.md §20) — one entry of
 * {@see TokenIntrospection::$permissions}.
 *
 * Mirrors the server's `RptPermission` field for field, including the per-permission
 * `$exp`: UMA allows an RPT to accumulate permissions with different lifetimes.
 * Flattening that to a single token-level expiry would foreclose a shape the
 * specification permits and the domain model already carries.
 */
final class RptPermission
{
    /**
     * @param string        $resourceId     Resource UUID.
     * @param list<string>  $resourceScopes Scopes granted on that resource.
     * @param int           $exp            Absolute expiry of THIS permission, seconds
     *                                      since the epoch.
     */
    public function __construct(
        public readonly string $resourceId,
        public readonly array $resourceScopes,
        public readonly int $exp,
    ) {
    }
}
