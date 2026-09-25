<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

use Axiam\Sdk\Management\ManagementApi;
use Axiam\Sdk\Management\Models;
use Axiam\Sdk\Management\PageRequest;

/**
 * Plans and applies a §27.6 manifest (CONTRACT.md §27.6, §27.7).
 *
 * Two operations, with deliberately different risk profiles:
 *
 * - {@see self::plan()} **writes nothing.** It reads the tenant and reports the
 *   difference. Safe against production, safe in CI, safe to run on a schedule.
 * - {@see self::apply()} performs the plan, **stopping at the first failure and NOT
 *   rolling back** (§27.7). What already landed stays landed, and the returned
 *   {@see ApplyReport} says exactly what that was.
 *
 * Both build on the ordinary §27 namespace handles — there is no separate manifest
 * endpoint on the server, and this class invents no wire protocol. It is a client-side
 * convergence loop over operations the imperative surface already exposes, which is why
 * everything §27.8 guarantees about that surface (CSRF, cookies, tenant header, TLS,
 * retry, telemetry) holds here too.
 */
final class ManifestApi
{
    /** Page size used when reading existing state; large enough to make one call usual. */
    private const SCAN_LIMIT = 200;

    /**
     * @param ManagementApi $management The management surface to read and write through.
     */
    public function __construct(private readonly ManagementApi $management)
    {
    }

    /**
     * Computes what an apply would do. Sends only reads.
     *
     * @throws ManifestException when the manifest is incoherent (checked before any read).
     */
    public function plan(ManagementManifest $manifest): ManagementPlan
    {
        // Validate BEFORE any read — a dangling reference or a cycle must be refused
        // with zero wire calls, and ordered()'s side effect (thrown or not) is exactly
        // that check. apply() relies on this too: it calls plan() first.
        $manifest->ordered();

        $existing = $this->currentState($manifest);
        $plan = $this->planAgainst($manifest, $existing);

        // CONTRACT 1.52 N6.4 (C-12): "plan reports a binding Update, not only apply."
        // A read-only pass, ADDITIVE to planAgainst()'s field-level drift — never
        // called by apply() (which calls planAgainst() directly, never this method),
        // so apply()'s own wire sequence is byte-for-byte unaffected by it.
        return $this->withPendingEdges($manifest, $plan, $this->seedIds($existing));
    }

    /**
     * Upgrades a Role/Group/ServiceAccount's `PlannedChange` to `Update` — augmenting
     * its `$drift` with a `grants`/`roles` entry naming exactly the pending subset —
     * whenever the manifest declares a grant or role binding for it that is NOT yet
     * present on the server. `Create`d entities are left alone: nothing exists yet to
     * read, and `Create` already signals that every declared grant/binding is new.
     *
     * Read-only, exactly like {@see self::reconcileRoleGrants()}/
     * {@see self::reconcileRoleBindings()}'s own detection step, but this method never
     * sends anything — those two remain the only callers that write, and they keep
     * reading fresh state of their own right before doing so (state may have moved
     * since this plan was computed), so this pass changes nothing about what `apply()`
     * itself reads or sends.
     *
     * @param array<string,array<string,string>> $ids
     */
    private function withPendingEdges(ManagementManifest $manifest, ManagementPlan $plan, array $ids): ManagementPlan
    {
        $changes = [];
        foreach ($plan->changes as $change) {
            $entity = $change->entity;
            $edgeKey = match ($entity->kind) {
                ManifestKind::Role => 'grants',
                ManifestKind::Group, ManifestKind::ServiceAccount => 'roles',
                default => null,
            };

            if ($change->action === ChangeAction::Create || $edgeKey === null || ($entity->fields[$edgeKey] ?? []) === []) {
                $changes[] = $change;
                continue;
            }

            $pending = $entity->kind === ManifestKind::Role
                ? $this->pendingGrants($entity, $manifest, $ids)
                : $this->pendingBindings($entity, $manifest, $ids);

            if ($pending === []) {
                $changes[] = $change;
                continue;
            }

            $drift = $change->fields;
            $drift[$edgeKey] = $pending;
            $changes[] = new PlannedChange($entity, ChangeAction::Update, $drift, $change->id);
        }

        return new ManagementPlan($changes);
    }

    /**
     * The subset of `$roleEntity`'s declared grants that are NOT already present on the
     * server — the read-only twin of {@see self::reconcileRoleGrants()}'s own detection
     * step, used by {@see self::withPendingEdges()} (never by {@see self::apply()}).
     *
     * @param array<string,array<string,string>> $ids
     * @return array<string,string> permission KEY => effect
     */
    private function pendingGrants(ManifestEntity $roleEntity, ManagementManifest $manifest, array $ids): array
    {
        /** @var array<string,string> $grants */
        $grants = $roleEntity->fields['grants'] ?? [];
        if ($grants === []) {
            return [];
        }

        $roleId = $this->resolveId($ids, ManifestKind::Role, $roleEntity->name);
        $current = $this->management->roles()->listPermissions($roleId);
        $currentPermissionIds = [];
        foreach ($current as $grant) {
            $currentPermissionIds[$grant->permission->id] = true;
        }

        $pending = [];
        foreach ($grants as $permissionKey => $effect) {
            $permission = $this->findEntityByKey($manifest, ManifestKind::Permission, $permissionKey);
            $permissionId = $this->resolveId($ids, ManifestKind::Permission, $permission->name);
            if (!isset($currentPermissionIds[$permissionId])) {
                $pending[$permissionKey] = $effect;
            }
        }

        return $pending;
    }

    /**
     * The subset of `$entity`'s declared role bindings that are NOT already bound
     * exactly as declared (a plain assign, or one needing a rebind) — the read-only
     * twin of {@see self::reconcileRoleBindings()}'s own detection step, used by
     * {@see self::withPendingEdges()} (never by {@see self::apply()}).
     *
     * @param array<string,array<string,string>> $ids
     * @return list<RoleBinding>
     */
    private function pendingBindings(ManifestEntity $entity, ManagementManifest $manifest, array $ids): array
    {
        /** @var list<RoleBinding> $bindings */
        $bindings = $entity->fields['roles'] ?? [];
        if ($bindings === []) {
            return [];
        }

        $kind = $entity->kind;
        $subjectId = $this->resolveId($ids, $kind, $entity->name);
        $current = $kind === ManifestKind::Group
            ? $this->management->groups()->listRoles($subjectId)
            : $this->management->serviceAccounts()->listRoles($subjectId);

        /** @var array<string,Models\RoleAssignment> $byRoleId */
        $byRoleId = [];
        foreach ($current as $assignment) {
            $byRoleId[$assignment->role->id] = $assignment;
        }

        $pending = [];
        foreach ($bindings as $binding) {
            $role = $this->findEntityByKey($manifest, ManifestKind::Role, $binding->role);
            $roleId = $this->resolveId($ids, ManifestKind::Role, $role->name);
            $resourceId = null;
            if ($binding->resource !== null) {
                $resource = $this->findEntityByKey($manifest, ManifestKind::Resource, $binding->resource);
                $resourceId = $this->resolveId($ids, ManifestKind::Resource, $resource->name);
            }

            $existing = $byRoleId[$roleId] ?? null;
            if ($existing !== null) {
                $existingInherit = $existing->inherit ?? true;
                if ($existing->resourceId === $resourceId && $existingInherit === $binding->inherit) {
                    continue; // already bound exactly as declared
                }
            }

            $pending[] = $binding;
        }

        return $pending;
    }

    /**
     * {@see self::plan()}'s computation against an ALREADY-READ `$existing` — the seam
     * {@see self::apply()} uses so its own single `currentState()` read serves both the
     * plan and {@see self::seedIds()}. Reading it twice per apply would not be WRONG,
     * only wasteful and, worse, a silent behaviour change for every existing caller that
     * counts requests against a fixed mock queue.
     *
     * @param array<string,array<string,array<string,mixed>>> $existing kind => name => object
     */
    private function planAgainst(ManagementManifest $manifest, array $existing): ManagementPlan
    {
        $ordered = $manifest->ordered();

        $changes = [];
        foreach ($ordered as $entity) {
            $current = $existing[$entity->kind->value][$entity->name] ?? null;

            if ($current === null) {
                $changes[] = new PlannedChange($entity, ChangeAction::Create);
                continue;
            }

            $drift = $entity->drift($current);
            // `grants` and `roles` are manifest-side concepts describing edges, not
            // columns on the server's object, so they never count as field drift.
            unset($drift['grants'], $drift['roles']);

            $id = \is_string($current['id'] ?? null) ? $current['id'] : null;
            $changes[] = $drift === []
                ? new PlannedChange($entity, ChangeAction::Unchanged, [], $id)
                : new PlannedChange($entity, ChangeAction::Update, $drift, $id);
        }

        return new ManagementPlan($changes);
    }

    /**
     * Applies a manifest, stopping at the first failure.
     *
     * Re-plans internally rather than taking a plan as an argument, so what is applied is
     * computed against the tenant's state NOW. A plan handed in from an earlier run
     * describes a tenant that may have moved since, and applying it would either duplicate
     * work or fail on a conflict — either way acting on a world that no longer exists.
     *
     * Two phases. First, every entity's own Create/Update lands, in the manifest's
     * derived order — this is §27.6 rule 5's ordering, and it is what makes the second
     * phase possible: a role exists before anything tries to grant it a permission. Second,
     * §13 row 17's fix: role permission grants and group role bindings are reconciled —
     * ADDITIVELY, never revoked or unassigned (§27.6 rule 4's "omission is never deletion",
     * extended to edges the same way it already governs entities) — for every role/group
     * the manifest declares grants/roles for, whether or not that role/group's OWN fields
     * needed a Create or Update. A role that already exists, unchanged, with a grant added
     * to the manifest since the last apply still gets that grant on this run.
     *
     * @throws ManifestException when the manifest is incoherent (checked before any write).
     */
    public function apply(ManagementManifest $manifest): ApplyReport
    {
        // Validate before any read — see plan()'s identical guard.
        $manifest->ordered();

        // ONE read, shared by the plan and by seedIds() below — see planAgainst()'s doc.
        $existing = $this->currentState($manifest);
        $plan = $this->planAgainst($manifest, $existing);
        $pending = $plan->pending();
        $ids = $this->seedIds($existing);

        // Grown as a `CreateServiceAccount` step runs — see applyServiceAccount(). Threaded
        // into EVERY return below, success or failure, because the secret it carries is
        // real the moment the server answers, whatever a LATER step in the same apply does
        // (§27.5 rule 5).
        $createdServiceAccounts = [];

        $applied = [];
        foreach ($pending as $index => $change) {
            try {
                $ids[$change->entity->kind->value][$change->entity->name]
                    = $this->perform($change, $manifest, $ids, $createdServiceAccounts);
            } catch (\Throwable $failure) {
                // §27.7: stop here, do not undo what landed. The report is the recovery
                // tool; see ApplyReport's class doc for why an automatic rollback would
                // be the wrong reflex.
                return new ApplyReport(
                    $applied,
                    $change,
                    $failure,
                    array_values(\array_slice($pending, $index + 1)),
                    $createdServiceAccounts,
                );
            }
            $applied[] = $change;
        }

        $edges = $this->pendingEdgeReconciliations($manifest, $plan);
        foreach ($edges as $index => $edgeChange) {
            try {
                $sentAny = $this->reconcileEdges($edgeChange, $manifest, $ids);
            } catch (\Throwable $failure) {
                return new ApplyReport(
                    $applied,
                    $edgeChange,
                    $failure,
                    array_values(\array_slice($edges, $index + 1)),
                    $createdServiceAccounts,
                );
            }
            // Recorded only when something actually reached the wire — a role/group
            // whose grants/bindings already matched is exactly as unremarkable as an
            // entity whose own fields already matched, which perform() never sees.
            if ($sentAny) {
                $applied[] = $edgeChange;
            }
        }

        return new ApplyReport($applied, createdServiceAccounts: $createdServiceAccounts);
    }

    /**
     * Performs one planned change, returning the server's id for it.
     *
     * An update sends ONLY the drifted fields — the sparse body of §27.4 rule 5. Sending
     * the whole declaration instead would overwrite fields the manifest never mentioned
     * with whatever the manifest happens to imply about them.
     *
     * @param array<string,array<string,string>> $ids kind => name => id, for every entity
     *        applied so far this run (plus everything {@see self::seedIds()} found
     *        already existing) — how a resource's `parent_id` is resolved from its
     *        manifest-local parent KEY (§13 row 17 defect b).
     * @param list<Models\ServiceAccountCreatedResponse> $createdServiceAccounts Appended
     *        to when this step creates a service account — see {@see self::apply()}.
     */
    private function perform(
        PlannedChange $change,
        ManagementManifest $manifest,
        array $ids,
        array &$createdServiceAccounts,
    ): string {
        $entity = $change->entity;
        $fields = $change->action === ChangeAction::Create ? $entity->fields : $change->fields;

        return match ($entity->kind) {
            ManifestKind::Resource => $this->applyResource($change, $fields, $manifest, $ids),
            ManifestKind::Permission => $this->applyPermission($change, $fields),
            ManifestKind::Role => $this->applyRole($change, $fields),
            ManifestKind::Group => $this->applyGroup($change, $fields),
            ManifestKind::ServiceAccount => $this->applyServiceAccount($change, $fields, $createdServiceAccounts),
        };
    }

    /**
     * Creates or updates one resource, returning its id.
     *
     * §13 row 17 defect (b): on Create, resolves the resource's PARENT — its manifest-local
     * key, carried as {@see ManifestEntity::$depends}'s one entry for a resource with a
     * parent (see {@see ManifestBuilder::resource()}) — to the parent's server id via `$ids`,
     * and sends it as `parent_id`. The parent is guaranteed to exist by this point: §27.6
     * rule 5 sorts resources topologically, so a parent is always applied (and its id
     * recorded into `$ids`) before any child that names it.
     *
     * @param array<string,mixed> $fields
     * @param array<string,array<string,string>> $ids
     */
    private function applyResource(PlannedChange $change, array $fields, ManagementManifest $manifest, array $ids): string
    {
        $resources = $this->management->resources();

        if ($change->action === ChangeAction::Create) {
            $created = $resources->create(new Models\CreateResourceRequest(
                name: self::str($fields, 'name'),
                resourceType: self::str($fields, 'resource_type'),
                metadata: $fields['metadata'] ?? null,
                parentId: $this->resolveParentId($change->entity, $manifest, $ids),
            ));

            return $created->id;
        }

        $updated = $resources->update((string) $change->id, new Models\UpdateResourceRequest(
            name: isset($fields['name']) ? self::str($fields, 'name') : null,
            resourceType: isset($fields['resource_type']) ? self::str($fields, 'resource_type') : null,
            metadata: $fields['metadata'] ?? null,
        ));

        return $updated->id;
    }

    /**
     * The parent resource's server id for `$entity`, or `null` when it declares none.
     *
     * `$entity->depends` holds exactly the parent's manifest-local key for a resource with
     * one ({@see ManifestBuilder::resource()}) — nothing else contributes a `depends` entry
     * for a resource, so its presence/absence IS the parent question.
     *
     * @param array<string,array<string,string>> $ids
     */
    private function resolveParentId(ManifestEntity $entity, ManagementManifest $manifest, array $ids): ?string
    {
        $parentKey = $entity->depends[0] ?? null;
        if ($parentKey === null) {
            return null;
        }

        $parent = $this->findEntityByKey($manifest, ManifestKind::Resource, $parentKey);

        return $this->resolveId($ids, ManifestKind::Resource, $parent->name);
    }

    /**
     * Creates or updates one permission, returning its id.
     *
     * @param array<string,mixed> $fields
     */
    private function applyPermission(PlannedChange $change, array $fields): string
    {
        $permissions = $this->management->permissions();

        if ($change->action === ChangeAction::Create) {
            $created = $permissions->create(new Models\CreatePermissionRequest(
                action: self::str($fields, 'action'),
                description: self::str($fields, 'description'),
            ));

            return $created->id;
        }

        $updated = $permissions->update((string) $change->id, new Models\UpdatePermissionRequest(
            action: isset($fields['action']) ? self::str($fields, 'action') : null,
            description: isset($fields['description']) ? self::str($fields, 'description') : null,
        ));

        return $updated->id;
    }

    /**
     * Creates or updates one role, returning its id. Grant reconciliation happens
     * separately — see {@see self::reconcileEdges()} — so a role that already exists,
     * unchanged, still gets a grant added to the manifest since the last apply.
     *
     * @param array<string,mixed> $fields
     */
    private function applyRole(PlannedChange $change, array $fields): string
    {
        $roles = $this->management->roles();

        if ($change->action === ChangeAction::Create) {
            $created = $roles->create(new Models\CreateRoleRequest(
                description: self::str($fields, 'description'),
                isGlobal: (bool) ($fields['is_global'] ?? false),
                name: self::str($fields, 'name'),
            ));

            return $created->id;
        }

        $updated = $roles->update((string) $change->id, new Models\UpdateRole(
            description: isset($fields['description']) ? self::str($fields, 'description') : null,
            isGlobal: isset($fields['is_global']) ? (bool) $fields['is_global'] : null,
            name: isset($fields['name']) ? self::str($fields, 'name') : null,
        ));

        return $updated->id;
    }

    /**
     * Creates or updates one group, returning its id. Role-binding reconciliation
     * happens separately — see {@see self::reconcileEdges()}.
     *
     * @param array<string,mixed> $fields
     */
    private function applyGroup(PlannedChange $change, array $fields): string
    {
        $groups = $this->management->groups();

        if ($change->action === ChangeAction::Create) {
            $created = $groups->create(new Models\CreateGroupRequest(
                description: self::str($fields, 'description'),
                name: self::str($fields, 'name'),
                metadata: $fields['metadata'] ?? null,
            ));

            return $created->id;
        }

        $updated = $groups->update((string) $change->id, new Models\UpdateGroup(
            description: isset($fields['description']) ? self::str($fields, 'description') : null,
            name: isset($fields['name']) ? self::str($fields, 'name') : null,
            metadata: $fields['metadata'] ?? null,
        ));

        return $updated->id;
    }

    /**
     * Creates or updates one service account, returning its id (CONTRACT.md §27.6.1
     * addition 3, contract 1.51). Role-binding reconciliation happens separately — see
     * {@see self::reconcileEdges()}.
     *
     * `description` is the only field an `Update` sends — `name`/`status` are never
     * manifest fields here (see {@see ManifestBuilder::serviceAccount()}) — and a
     * `Create`'s response, `client_secret` included, is appended to `$createdServiceAccounts`
     * for {@see ApplyReport} to carry, the ONE time that secret is ever returned. `apply()`
     * never calls `rotateSecret()`.
     *
     * @param array<string,mixed> $fields
     * @param list<Models\ServiceAccountCreatedResponse> $createdServiceAccounts
     */
    private function applyServiceAccount(PlannedChange $change, array $fields, array &$createdServiceAccounts): string
    {
        $accounts = $this->management->serviceAccounts();

        if ($change->action === ChangeAction::Create) {
            $created = $accounts->create(new Models\CreateServiceAccountRequest(
                name: self::str($fields, 'name'),
                description: isset($fields['description']) ? self::str($fields, 'description') : null,
            ));
            $createdServiceAccounts[] = $created;

            return $created->id;
        }

        $updated = $accounts->update((string) $change->id, new Models\UpdateServiceAccount(
            description: isset($fields['description']) ? self::str($fields, 'description') : null,
        ));

        return $updated->id;
    }

    /**
     * §13 row 17 defect (a): the role/group entities whose GRANTS/ROLES need
     * reconciling — every one the manifest declares at least one grant or role key for,
     * whether or not that role/group's own fields are `Create`, `Update` or `Unchanged`.
     *
     * Represented as synthetic {@see PlannedChange}s (action `Update`, empty `fields` —
     * this is a reconciliation of EDGES, not of the entity's own columns) purely so
     * {@see ApplyReport} can name which entity a reconciliation failure was for, exactly
     * as it already does for an entity's own Create/Update.
     *
     * @return list<PlannedChange>
     */
    private function pendingEdgeReconciliations(ManagementManifest $manifest, ManagementPlan $plan): array
    {
        $out = [];
        foreach ($plan->changes as $change) {
            $entity = $change->entity;
            $edgeKey = match ($entity->kind) {
                ManifestKind::Role => 'grants',
                ManifestKind::Group, ManifestKind::ServiceAccount => 'roles',
                default => null,
            };
            if ($edgeKey === null) {
                continue;
            }
            $edges = $entity->fields[$edgeKey] ?? [];
            if ($edges === []) {
                continue;
            }
            $out[] = new PlannedChange($entity, ChangeAction::Update);
        }

        return $out;
    }

    /**
     * Grants every permission a role's manifest declaration names and does not already
     * have, or assigns every role a group's manifest declaration names and does not
     * already carry — ADDITIVELY (§27.6 rule 4: omission is never deletion, and neither
     * is a grant/binding this run's manifest simply does not mention).
     *
     * @param array<string,array<string,string>> $ids
     *
     * @return bool Whether any wire call was actually made — {@see self::apply()} only
     *              records this reconciliation as `applied` when something was, exactly
     *              as an entity whose OWN fields already matched is never recorded
     *              either (it is never even offered to {@see self::perform()}).
     */
    private function reconcileEdges(PlannedChange $change, ManagementManifest $manifest, array $ids): bool
    {
        $entity = $change->entity;

        return match ($entity->kind) {
            ManifestKind::Role => $this->reconcileRoleGrants($entity, $manifest, $ids),
            ManifestKind::Group, ManifestKind::ServiceAccount => $this->reconcileRoleBindings($entity, $manifest, $ids),
            default => throw new ManifestException(
                'unreachable: only roles, groups and service accounts reconcile edges',
            ),
        };
    }

    /**
     * @param array<string,array<string,string>> $ids
     */
    private function reconcileRoleGrants(ManifestEntity $roleEntity, ManagementManifest $manifest, array $ids): bool
    {
        /** @var array<string,string> $grants permission KEY => effect ('allow'|'deny') */
        $grants = $roleEntity->fields['grants'] ?? [];
        if ($grants === []) {
            return false;
        }

        $roleId = $this->resolveId($ids, ManifestKind::Role, $roleEntity->name);
        $roles = $this->management->roles();

        $current = $roles->listPermissions($roleId);
        $currentPermissionIds = [];
        foreach ($current as $grant) {
            $currentPermissionIds[$grant->permission->id] = true;
        }

        $sentAny = false;
        foreach ($grants as $permissionKey => $effect) {
            $permission = $this->findEntityByKey($manifest, ManifestKind::Permission, $permissionKey);
            $permissionId = $this->resolveId($ids, ManifestKind::Permission, $permission->name);

            if (isset($currentPermissionIds[$permissionId])) {
                continue; // already granted — never re-granted, never revoked for a dropped key
            }

            $roles->grantPermission($roleId, new Models\GrantPermissionRequest(
                permissionId: $permissionId,
                effect: $effect === 'deny' ? Models\PermissionEffect::Deny : null,
            ));
            $sentAny = true;
        }

        return $sentAny;
    }

    /**
     * Reconciles one subject's (a group's or a service account's) role bindings —
     * CONTRACT.md §27.6.1 addition 2, contract 1.51.
     *
     * ADDITIVE, exactly like {@see self::reconcileRoleGrants()}: a role the manifest does
     * not name for this subject is never unassigned. For a role the manifest DOES name,
     * three things can happen against the current assignment (found by role id — the
     * server keys an assignment on `(subject, role)`, so there is at most one):
     *
     * - none exists: ASSIGN.
     * - one exists with the SAME resource and `inherit`: nothing — already converged.
     * - one exists with a DIFFERENT resource or `inherit`: UPDATE, as unassign then
     *   assign (there is no update endpoint). The server assignment's `tenant_scope`
     *   (§5.2.3, not a manifest field) is carried across unchanged. If the assign fails,
     *   the previous assignment is put back and {@see BindingRebindFailed} carries both
     *   results — thrown rather than returned, so {@see self::apply()}'s existing
     *   `catch (\Throwable)` around this whole call records it on the report exactly like
     *   any other step failure.
     *
     * @param array<string,array<string,string>> $ids
     *
     * @return bool Whether any wire call was actually made — see
     *              {@see self::reconcileRoleGrants()}'s identical contract.
     *
     * @throws BindingRebindFailed when an Update's re-assignment fails.
     */
    private function reconcileRoleBindings(ManifestEntity $entity, ManagementManifest $manifest, array $ids): bool
    {
        /** @var list<RoleBinding> $bindings */
        $bindings = $entity->fields['roles'] ?? [];
        if ($bindings === []) {
            return false;
        }

        $kind = $entity->kind;
        $subjectId = $this->resolveId($ids, $kind, $entity->name);
        $current = $kind === ManifestKind::Group
            ? $this->management->groups()->listRoles($subjectId)
            : $this->management->serviceAccounts()->listRoles($subjectId);

        /** @var array<string,Models\RoleAssignment> $byRoleId */
        $byRoleId = [];
        foreach ($current as $assignment) {
            $byRoleId[$assignment->role->id] = $assignment;
        }

        $sentAny = false;
        foreach ($bindings as $binding) {
            $role = $this->findEntityByKey($manifest, ManifestKind::Role, $binding->role);
            $roleId = $this->resolveId($ids, ManifestKind::Role, $role->name);
            $resourceId = null;
            if ($binding->resource !== null) {
                $resource = $this->findEntityByKey($manifest, ManifestKind::Resource, $binding->resource);
                $resourceId = $this->resolveId($ids, ManifestKind::Resource, $resource->name);
            }

            $existing = $byRoleId[$roleId] ?? null;
            if ($existing === null) {
                $this->assignRole($kind, $roleId, $subjectId, $resourceId, $binding->inherit, null);
                $sentAny = true;
                continue;
            }

            // Server assignments written before `inherit` existed report it as `null`,
            // which means `true` — same reading as every other §27 response (RoleAssignment
            // itself already defaults it that way in `fromArray()`).
            $existingInherit = $existing->inherit ?? true;
            if ($existing->resourceId === $resourceId && $existingInherit === $binding->inherit) {
                continue; // already bound exactly as declared — never re-sent
            }

            $this->rebindRole($kind, $roleId, $subjectId, $resourceId, $binding->inherit, $existing);
            $sentAny = true;
        }

        return $sentAny;
    }

    /**
     * One binding `Update`: unassign the current assignment, then assign the declared
     * one. On a failed assign, restores the previous assignment (carrying its
     * `tenant_scope` across, both times) and throws {@see BindingRebindFailed} naming
     * both outcomes — the C-12 question 7 answer this port gives.
     */
    private function rebindRole(
        ManifestKind $kind,
        string $roleId,
        string $subjectId,
        ?string $resourceId,
        bool $inherit,
        Models\RoleAssignment $previous,
    ): void {
        $previousInherit = $previous->inherit ?? true;

        $this->unassignRole($kind, $roleId, $subjectId, $previous->resourceId);
        try {
            $this->assignRole($kind, $roleId, $subjectId, $resourceId, $inherit, $previous->tenantScope);
        } catch (\Throwable $assignFailure) {
            try {
                $this->assignRole(
                    $kind,
                    $roleId,
                    $subjectId,
                    $previous->resourceId,
                    $previousInherit,
                    $previous->tenantScope,
                );
            } catch (\Throwable $restoreFailure) {
                throw new BindingRebindFailed($assignFailure->getMessage(), false, $restoreFailure->getMessage());
            }
            throw new BindingRebindFailed($assignFailure->getMessage(), true);
        }
    }

    /**
     * `roles.assign_to_*`, for whichever kind of subject — `inherit` reaches the wire
     * only as `false` (CONTRACT.md §27.13 S-10 rule 1), so an inheritable binding's
     * request body stays byte-for-byte what it was before contract 1.51.
     *
     * @param list<string>|null $tenantScope
     */
    private function assignRole(
        ManifestKind $kind,
        string $roleId,
        string $subjectId,
        ?string $resourceId,
        bool $inherit,
        ?array $tenantScope,
    ): void {
        $roles = $this->management->roles();
        $inheritWire = $inherit ? null : false;

        if ($kind === ManifestKind::Group) {
            $roles->assignToGroup($roleId, new Models\AssignRoleToGroupRequest(
                groupId: $subjectId,
                inherit: $inheritWire,
                resourceId: $resourceId,
                tenantScope: $tenantScope,
            ));

            return;
        }

        $roles->assignToServiceAccount($roleId, new Models\AssignRoleToServiceAccountRequest(
            serviceAccountId: $subjectId,
            inherit: $inheritWire,
            resourceId: $resourceId,
            tenantScope: $tenantScope,
        ));
    }

    /** `roles.unassign_from_*`. The resource names WHICH assignment: `null` removes the tenant-wide one. */
    private function unassignRole(ManifestKind $kind, string $roleId, string $subjectId, ?string $resourceId): void
    {
        $roles = $this->management->roles();

        if ($kind === ManifestKind::Group) {
            $roles->unassignFromGroup($roleId, $subjectId, $resourceId);

            return;
        }

        $roles->unassignFromServiceAccount($roleId, $subjectId, $resourceId);
    }

    /**
     * The id of every entity that already exists, before this apply's own Create/Update
     * loop runs — built from `$existing`, the same read {@see self::planAgainst()} used
     * for this run's plan. `apply()` grows this map as each Create/Update lands, so by
     * the time edge reconciliation runs it has every entity's id, whether pre-existing
     * or created moments ago in this same run.
     *
     * @param array<string,array<string,array<string,mixed>>> $existing kind => name => object
     * @return array<string,array<string,string>> kind => name => id
     */
    private function seedIds(array $existing): array
    {
        $ids = [];
        foreach ($existing as $kindValue => $byName) {
            foreach ($byName as $name => $row) {
                $id = $row['id'] ?? null;
                if (\is_string($id)) {
                    $ids[$kindValue][$name] = $id;
                }
            }
        }

        return $ids;
    }

    /**
     * The manifest entity of `$kind` declared under manifest-local `$key`.
     *
     * Always finds one: {@see ManifestValidation::assertValid()} already refused a
     * dangling reference before the first request went out, so by the time this runs
     * every key a `depends`/grant/role-binding names is a key the manifest declares.
     */
    private function findEntityByKey(ManagementManifest $manifest, ManifestKind $kind, string $key): ManifestEntity
    {
        foreach ($manifest->entities as $entity) {
            if ($entity->kind === $kind && $entity->key === $key) {
                return $entity;
            }
        }

        throw new ManifestException(sprintf('manifest has no %s declared under key "%s"', $kind->value, $key));
    }

    /**
     * The server id `$ids` records for `$kind`'s entity named `$name`.
     *
     * @param array<string,array<string,string>> $ids
     */
    private function resolveId(array $ids, ManifestKind $kind, string $name): string
    {
        $id = $ids[$kind->value][$name] ?? null;
        if (!\is_string($id)) {
            throw new ManifestException(sprintf(
                'manifest: could not resolve the id of %s "%s" — expected it to already exist or '
                . 'to have just been created (§27.6 rule 5 ordering)',
                $kind->value,
                $name,
            ));
        }

        return $id;
    }

    /**
     * Reads the tenant's current state for every kind the manifest mentions.
     *
     * Only the kinds actually declared are scanned: a manifest that declares two
     * permissions has no business listing every group in the tenant, and on a large tenant
     * that is the difference between one request and dozens.
     *
     * @return array<string,array<string,array<string,mixed>>> kind => name => object
     */
    private function currentState(ManagementManifest $manifest): array
    {
        $kinds = [];
        foreach ($manifest->entities as $entity) {
            $kinds[$entity->kind->value] = $entity->kind;
        }

        $page = new PageRequest(0, self::SCAN_LIMIT);
        $state = [];
        foreach ($kinds as $value => $kind) {
            $state[$value] = match ($kind) {
                ManifestKind::Resource => self::index($this->management->resources()->listItems($page)->items),
                ManifestKind::Permission => self::index($this->management->permissions()->listItems($page)->items),
                ManifestKind::Role => self::index($this->management->roles()->listItems($page)->items),
                ManifestKind::Group => self::index($this->management->groups()->listItems($page)->items),
                ManifestKind::ServiceAccount => self::indexServiceAccounts(
                    $this->management->serviceAccounts()->listItems($page)->items,
                    $manifest,
                ),
            };
        }

        return $state;
    }

    /**
     * Keys a page of service accounts by `name`, like {@see self::index()} — with one
     * difference `index()` cannot have: a service account's `name` is NOT a unique index
     * on the server (only its `client_id` is), so a tenant can hold two accounts sharing
     * one. `plan()`/`apply()` refuse BEFORE any write when more than one existing account
     * matches a name this manifest actually declares — reconciling an arbitrary one of
     * them would be a guess neither `plan()` nor an operator reading it could see was
     * made.
     *
     * A duplicate among names the manifest does NOT mention is not this method's problem:
     * nothing here reconciles it, so nothing here needs to be able to tell it apart from
     * a single match.
     *
     * @param list<Models\ServiceAccountResponse> $items
     * @return array<string,array<string,mixed>>
     *
     * @throws ManifestException when more than one existing account matches a declared name.
     */
    private static function indexServiceAccounts(array $items, ManagementManifest $manifest): array
    {
        $declaredNames = [];
        foreach ($manifest->entities as $entity) {
            if ($entity->kind === ManifestKind::ServiceAccount) {
                $declaredNames[$entity->name] = true;
            }
        }

        $out = [];
        $seen = [];
        foreach ($items as $item) {
            if (!\is_object($item) || !method_exists($item, 'toArray')) {
                continue;
            }
            /** @var array<string,mixed> $row */
            $row = $item->toArray();
            $name = $row['name'] ?? null;
            if (!\is_string($name)) {
                continue;
            }

            if (isset($seen[$name]) && isset($declaredNames[$name])) {
                throw new ManifestException(sprintf(
                    'service account %s is ambiguous: more than one existing account is named '
                    . '%s, and a service account\'s name is not unique on the server — rename '
                    . 'one, or remove it from the manifest',
                    $name,
                    $name,
                ));
            }
            $seen[$name] = true;
            $out[$name] = $row;
        }

        return $out;
    }

    /**
     * Keys a page of server objects by their `name`, which is how a declaration is matched
     * to an existing object.
     *
     * @param list<mixed> $items
     * @return array<string,array<string,mixed>>
     */
    private static function index(array $items): array
    {
        $out = [];
        foreach ($items as $item) {
            if (!\is_object($item) || !method_exists($item, 'toArray')) {
                continue;
            }
            /** @var array<string,mixed> $row */
            $row = $item->toArray();
            $name = $row['name'] ?? $row['action'] ?? null;
            if (\is_string($name)) {
                $out[$name] = $row;
            }
        }

        return $out;
    }

    /**
     * Reads one required string field out of a declaration.
     *
     * @param array<string,mixed> $fields
     */
    private static function str(array $fields, string $key): string
    {
        $value = $fields[$key] ?? null;
        if (!\is_string($value)) {
            throw new ManifestException(sprintf('manifest field "%s" must be a string', $key));
        }

        return $value;
    }
}
