<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management;

use Axiam\Sdk\Core\AxiamException;

/**
 * Base class for the 24 generated namespace handles (CONTRACT.md §27.2).
 *
 * Holds the two things every handle needs and nothing else: the shared
 * {@see ManagementTransport} and the {@see NamespaceScope} its routes substitute.
 * Keeping this hand-written means the generator emits only operations — the scope
 * override semantics of §27.4 rule 3 are written once and reviewed once, rather than
 * regenerated into 24 places where they could quietly diverge.
 *
 * §27.2 asks for namespace HANDLES, not a flat symbol list: `$client->management()
 * ->users()->get($id)`. Only the C and C++ SDKs take §27.3's flat-symbol
 * accommodation, and only because their languages have no method-bearing namespace to
 * hang one on.
 *
 * `inOrg()`/`forTenant()` return `new static(...)`, which is only sound while every
 * subclass keeps this constructor's signature. That is declared rather than assumed:
 * `@phpstan-consistent-constructor` makes PHPStan ENFORCE it across all 24 generated
 * handles, so a handle that grew a constructor of its own fails the build instead of
 * failing at runtime on the one call that re-scopes it.
 *
 * @phpstan-consistent-constructor
 */
abstract class ManagementSupport
{
    /**
     * @param ManagementTransport $transport      The one wire path (§27.8).
     * @param NamespaceScope      $scope          Per-handle `{org_id}`/`{tenant_id}` overrides.
     * @param string|null         $clientOrgId    The client's own organization id, or `null`.
     * @param string|null         $clientTenantId The client's own tenant id, or `null`.
     */
    public function __construct(
        protected readonly ManagementTransport $transport,
        protected readonly NamespaceScope $scope = new NamespaceScope(),
        protected readonly ?string $clientOrgId = null,
        protected readonly ?string $clientTenantId = null,
    ) {
    }

    /**
     * A COPY of this handle scoped to `$orgId` (§27.4 rule 3).
     *
     * Returns a new handle rather than mutating this one. An administrator holding a
     * handle to their own organization should not find it repointed at someone else's
     * because an unrelated code path re-scoped a shared object — and on a management
     * surface that failure mode writes to the wrong tenant rather than merely reading
     * from it.
     */
    public function inOrg(string $orgId): static
    {
        return new static(
            $this->transport,
            $this->scope->withOrg($orgId),
            $this->clientOrgId,
            $this->clientTenantId,
        );
    }

    /**
     * A COPY of this handle scoped to `$tenantId` (§27.4 rule 3). See {@see self::inOrg()}
     * for why it copies.
     */
    public function forTenant(string $tenantId): static
    {
        return new static(
            $this->transport,
            $this->scope->withTenant($tenantId),
            $this->clientOrgId,
            $this->clientTenantId,
        );
    }

    /**
     * The `{org_id}` this handle substitutes: its own override, else the client's.
     *
     * Throws rather than sending an empty path segment. `/api/v1/organizations//tenants`
     * is not a 404 the caller can act on — it is a route that does not exist, reported as
     * if the object were missing.
     */
    protected function orgId(): string
    {
        $value = $this->scope->orgId ?? $this->clientOrgId;
        if ($value === null || $value === '') {
            throw new AxiamException(
                'this operation needs an organization id: either construct AxiamClient with '
                . 'one, or scope the handle with ->inOrg($orgId) (CONTRACT.md §27.4 rule 3)',
            );
        }

        return $value;
    }

    /**
     * The `{tenant_id}` this handle substitutes: its own override, else the client's.
     * Throws for the same reason {@see self::orgId()} does.
     */
    protected function tenantId(): string
    {
        $value = $this->scope->tenantId ?? $this->clientTenantId;
        if ($value === null || $value === '') {
            throw new AxiamException(
                'this operation needs a tenant id: either construct AxiamClient with one, '
                . 'or scope the handle with ->forTenant($tenantId) (CONTRACT.md §27.4 rule 3)',
            );
        }

        return $value;
    }
}
