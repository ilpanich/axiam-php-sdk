<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management;

/**
 * The `{org_id}`/`{tenant_id}` a namespace handle substitutes into its routes
 * (CONTRACT.md §27.4 rule 3).
 *
 * Both default to the client's own identifiers. A handle can be re-scoped with
 * {@see \Axiam\Sdk\Management\ManagementSupport::inOrg()} /
 * `forTenant()`, which returns a NEW handle rather than mutating the one you called it
 * on — an administrator holding a handle to their own tenant should not find it silently
 * repointed at someone else's because an unrelated code path re-scoped a shared object.
 */
final class NamespaceScope
{
    /**
     * @param string|null $orgId    Overrides the client's organization id; `null` uses it.
     * @param string|null $tenantId Overrides the client's tenant id; `null` uses it.
     */
    public function __construct(
        public readonly ?string $orgId = null,
        public readonly ?string $tenantId = null,
    ) {
    }

    /** This scope with `{org_id}` pinned to `$orgId`, leaving `{tenant_id}` as it was. */
    public function withOrg(string $orgId): self
    {
        return new self($orgId, $this->tenantId);
    }

    /** This scope with `{tenant_id}` pinned to `$tenantId`, leaving `{org_id}` as it was. */
    public function withTenant(string $tenantId): self
    {
        return new self($this->orgId, $tenantId);
    }
}
