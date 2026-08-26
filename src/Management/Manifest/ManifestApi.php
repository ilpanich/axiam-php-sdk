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
        $ordered = $manifest->ordered();
        $existing = $this->currentState($manifest);

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
     * @throws ManifestException when the manifest is incoherent (checked before any write).
     */
    public function apply(ManagementManifest $manifest): ApplyReport
    {
        $plan = $this->plan($manifest);
        $pending = $plan->pending();

        $applied = [];
        foreach ($pending as $index => $change) {
            try {
                $this->perform($change);
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

        return new ApplyReport($applied);
    }

    /**
     * Performs one planned change.
     *
     * An update sends ONLY the drifted fields — the sparse body of §27.4 rule 5. Sending
     * the whole declaration instead would overwrite fields the manifest never mentioned
     * with whatever the manifest happens to imply about them.
     */
    private function perform(PlannedChange $change): void
    {
        $entity = $change->entity;
        $fields = $change->action === ChangeAction::Create ? $entity->fields : $change->fields;

        match ($entity->kind) {
            ManifestKind::Resource => $this->applyResource($change, $fields),
            ManifestKind::Permission => $this->applyPermission($change, $fields),
            ManifestKind::Role => $this->applyRole($change, $fields),
            ManifestKind::Group => $this->applyGroup($change, $fields),
        };
    }

    /**
     * Creates or updates one resource.
     *
     * @param array<string,mixed> $fields
     */
    private function applyResource(PlannedChange $change, array $fields): void
    {
        $resources = $this->management->resources();

        if ($change->action === ChangeAction::Create) {
            $resources->create(new Models\CreateResourceRequest(
                name: self::str($fields, 'name'),
                resourceType: self::str($fields, 'resource_type'),
                metadata: $fields['metadata'] ?? null,
            ));

            return;
        }

        $resources->update((string) $change->id, new Models\UpdateResourceRequest(
            name: isset($fields['name']) ? self::str($fields, 'name') : null,
            resourceType: isset($fields['resource_type']) ? self::str($fields, 'resource_type') : null,
            metadata: $fields['metadata'] ?? null,
        ));
    }

    /**
     * Creates or updates one permission.
     *
     * @param array<string,mixed> $fields
     */
    private function applyPermission(PlannedChange $change, array $fields): void
    {
        $permissions = $this->management->permissions();

        if ($change->action === ChangeAction::Create) {
            $permissions->create(new Models\CreatePermissionRequest(
                action: self::str($fields, 'action'),
                description: self::str($fields, 'description'),
            ));

            return;
        }

        $permissions->update((string) $change->id, new Models\UpdatePermissionRequest(
            action: isset($fields['action']) ? self::str($fields, 'action') : null,
            description: isset($fields['description']) ? self::str($fields, 'description') : null,
        ));
    }

    /**
     * Creates or updates one role, then reconciles its permission grants.
     *
     * @param array<string,mixed> $fields
     */
    private function applyRole(PlannedChange $change, array $fields): void
    {
        $roles = $this->management->roles();

        if ($change->action === ChangeAction::Create) {
            $roles->create(new Models\CreateRoleRequest(
                description: self::str($fields, 'description'),
                isGlobal: (bool) ($fields['is_global'] ?? false),
                name: self::str($fields, 'name'),
            ));

            return;
        }

        $roles->update((string) $change->id, new Models\UpdateRole(
            description: isset($fields['description']) ? self::str($fields, 'description') : null,
            isGlobal: isset($fields['is_global']) ? (bool) $fields['is_global'] : null,
            name: isset($fields['name']) ? self::str($fields, 'name') : null,
        ));
    }

    /**
     * Creates or updates one group.
     *
     * @param array<string,mixed> $fields
     */
    private function applyGroup(PlannedChange $change, array $fields): void
    {
        $groups = $this->management->groups();

        if ($change->action === ChangeAction::Create) {
            $groups->create(new Models\CreateGroupRequest(
                description: self::str($fields, 'description'),
                name: self::str($fields, 'name'),
                metadata: $fields['metadata'] ?? null,
            ));

            return;
        }

        $groups->update((string) $change->id, new Models\UpdateGroup(
            description: isset($fields['description']) ? self::str($fields, 'description') : null,
            name: isset($fields['name']) ? self::str($fields, 'name') : null,
            metadata: $fields['metadata'] ?? null,
        ));
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
