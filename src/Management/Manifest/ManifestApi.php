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

        return $this->planAgainst($manifest, $this->currentState($manifest));
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

        $applied = [];
        foreach ($pending as $index => $change) {
            try {
                $ids[$change->entity->kind->value][$change->entity->name] = $this->perform($change, $manifest, $ids);
            } catch (\Throwable $failure) {
                // §27.7: stop here, do not undo what landed. The report is the recovery
                // tool; see ApplyReport's class doc for why an automatic rollback would
                // be the wrong reflex.
                return new ApplyReport(
                    $applied,
                    $change,
                    $failure,
                    array_values(\array_slice($pending, $index + 1)),
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
                );
            }
            // Recorded only when something actually reached the wire — a role/group
            // whose grants/bindings already matched is exactly as unremarkable as an
            // entity whose own fields already matched, which perform() never sees.
            if ($sentAny) {
                $applied[] = $edgeChange;
            }
        }

        return new ApplyReport($applied);
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
     */
    private function perform(PlannedChange $change, ManagementManifest $manifest, array $ids): string
    {
        $entity = $change->entity;
        $fields = $change->action === ChangeAction::Create ? $entity->fields : $change->fields;

        return match ($entity->kind) {
            ManifestKind::Resource => $this->applyResource($change, $fields, $manifest, $ids),
            ManifestKind::Permission => $this->applyPermission($change, $fields),
            ManifestKind::Role => $this->applyRole($change, $fields),
            ManifestKind::Group => $this->applyGroup($change, $fields),
        };
    }

    /**
     * Creates or updates one resource, returning its id.
     *
     * `$manifest`/`$ids` are unused today; the next commit (§13 row 17 defect b) gives
     * `Create` a `parent_id` resolved through them, so the signature is already shaped
     * for it rather than changing again immediately after.
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
                ManifestKind::Group => 'roles',
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
            ManifestKind::Group => $this->reconcileGroupRoles($entity, $manifest, $ids),
            default => throw new ManifestException('unreachable: only roles and groups reconcile edges'),
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
     * @param array<string,array<string,string>> $ids
     */
    private function reconcileGroupRoles(ManifestEntity $groupEntity, ManagementManifest $manifest, array $ids): bool
    {
        /** @var list<string> $roleKeys */
        $roleKeys = $groupEntity->fields['roles'] ?? [];
        if ($roleKeys === []) {
            return false;
        }

        $groupId = $this->resolveId($ids, ManifestKind::Group, $groupEntity->name);
        $roles = $this->management->roles();

        $current = $this->management->groups()->listRoles($groupId);
        $currentRoleIds = [];
        foreach ($current as $assignment) {
            $currentRoleIds[$assignment->role->id] = true;
        }

        $sentAny = false;
        foreach ($roleKeys as $roleKey) {
            $role = $this->findEntityByKey($manifest, ManifestKind::Role, $roleKey);
            $roleId = $this->resolveId($ids, ManifestKind::Role, $role->name);

            if (isset($currentRoleIds[$roleId])) {
                continue; // already bound — never re-assigned, never unassigned for a dropped key
            }

            $roles->assignToGroup($roleId, new Models\AssignRoleToGroupRequest(groupId: $groupId));
            $sentAny = true;
        }

        return $sentAny;
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
            };
        }

        return $state;
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
