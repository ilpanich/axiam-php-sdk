<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

/**
 * Refuses an incoherent manifest BEFORE the first wire call (CONTRACT.md §27.6).
 *
 * The timing is the whole design. §27.7 gives apply no rollback, so a manifest that turns
 * out to be unapplicable halfway through leaves a tenant in a state nobody described —
 * some objects created, some not, and a dependency that can never be satisfied. Every
 * check here is one that can be made from the manifest alone, and every one of them runs
 * before a single request is sent.
 */
final class ManifestValidation
{
    /**
     * Throws unless `$manifest` is coherent.
     *
     * @throws ManifestException on a duplicate key, a dangling reference, or a cycle.
     */
    public static function assertValid(ManagementManifest $manifest): void
    {
        $keys = self::assertUniqueKeys($manifest);
        self::assertNoDanglingReferences($manifest, $keys);
        self::assertNoCycles($manifest);
        self::assertNoInvalidBindings($manifest);
    }

    /**
     * Every key must be unique within its kind.
     *
     * Two declarations sharing a key do not merge — one silently wins, and which one is an
     * accident of ordering. Since the key is also how an entity is referenced, the loser
     * takes every reference to it along.
     *
     * @return array<string,true> The set of `kind:key` identities.
     */
    private static function assertUniqueKeys(ManagementManifest $manifest): array
    {
        $seen = [];
        foreach ($manifest->entities as $entity) {
            $identity = $entity->kind->value . ':' . $entity->key;
            if (isset($seen[$identity])) {
                throw new ManifestException(sprintf(
                    'manifest declares %s twice — a key must be unique within its kind',
                    $identity,
                ));
            }
            $seen[$identity] = true;
        }

        return $seen;
    }

    /**
     * Every `depends` entry must name an entity the manifest actually declares — OF THE
     * RIGHT KIND (CONTRACT 1.52 N6.6, C-12: "references resolve by kind"). A resource's
     * `parent` must be another Resource; a role binding's `role`/`resource` must be a
     * Role/Resource respectively — {@see ManifestEntity::$expectedKinds} names which,
     * per dependency key. A key that exists under a DIFFERENT kind (a role binding
     * naming a Group's key, say) is exactly as dangling as a key that does not exist at
     * all: the server has nothing to resolve it to as the reference intends.
     *
     * A dependency with no entry in `$expectedKinds` — a {@see ManifestEntity} built by
     * hand rather than through {@see ManifestBuilder}, as some direct-construction tests
     * do — falls back to matching ANY kind, the pre-N6.6 behavior, so it keeps working
     * unchanged.
     *
     * A dangling reference is the failure mode this whole class exists for: it is
     * invisible until apply reaches the entity that needs it, by which point the objects
     * before it are already created.
     *
     * @param array<string,true> $keys The `kind:key` identity set {@see self::assertUniqueKeys()} built.
     */
    private static function assertNoDanglingReferences(ManagementManifest $manifest, array $keys): void
    {
        $byKey = [];
        foreach (array_keys($keys) as $identity) {
            $byKey[explode(':', $identity, 2)[1]] = true;
        }

        foreach ($manifest->entities as $entity) {
            foreach ($entity->depends as $dependency) {
                $expectedKind = $entity->expectedKinds[$dependency] ?? null;

                $resolved = $expectedKind !== null
                    ? isset($keys[$expectedKind->value . ':' . $dependency])
                    : isset($byKey[$dependency]);

                if (!$resolved) {
                    throw new ManifestException(sprintf(
                        '%s:%s depends on "%s"%s, which this manifest does not declare',
                        $entity->kind->value,
                        $entity->key,
                        $dependency,
                        $expectedKind !== null ? sprintf(' as a %s', $expectedKind->value) : '',
                    ));
                }
            }
        }
    }

    /**
     * The dependency graph must be acyclic.
     *
     * Resources are the realistic source of one: `parent_id` makes them a tree, and a
     * manifest can describe a shape that is not a tree. There is no ordering that
     * satisfies a cycle, so the only correct response is to refuse.
     */
    /**
     * The §27.6.1 addition 2 rules for role bindings — the two the server itself cannot
     * be argued out of, so refusing them here (before any request) is strictly better
     * than discovering a `409`/`400` partway through an `apply()` with no rollback:
     *
     * - The server keys an assignment on `(subject, role)` with no resource component
     *   (`has_role` is `UNIQUE(in, out)`), so ONE role bound twice to one subject — at two
     *   resources, or once plain and once scoped — describes a state it cannot hold.
     * - A role with `is_global: true` applies everywhere and ignores the resource, so the
     *   server refuses `inherit: false` on it with `400`. §27.6.1 lets an SDK say so
     *   first when that role is declared in the SAME manifest (C-12 question 6: PHP
     *   refuses, matching the reference).
     */
    private static function assertNoInvalidBindings(ManagementManifest $manifest): void
    {
        $globalRoleKeys = [];
        foreach ($manifest->entities as $entity) {
            if ($entity->kind === ManifestKind::Role && ($entity->fields['is_global'] ?? false) === true) {
                $globalRoleKeys[$entity->key] = true;
            }
        }

        foreach ($manifest->entities as $entity) {
            if ($entity->kind !== ManifestKind::Group && $entity->kind !== ManifestKind::ServiceAccount) {
                continue;
            }

            /** @var list<RoleBinding> $bindings */
            $bindings = $entity->fields['roles'] ?? [];
            $seenRoles = [];
            foreach ($bindings as $binding) {
                if (isset($seenRoles[$binding->role])) {
                    throw new ManifestException(sprintf(
                        '%s "%s" binds role "%s" more than once; a subject holds a role at most '
                        . 'once, whatever the resource (the server keys assignments on subject '
                        . 'and role, and answers 409 to a second)',
                        $entity->kind->value,
                        $entity->key,
                        $binding->role,
                    ));
                }
                $seenRoles[$binding->role] = true;

                if (!$binding->inherit && isset($globalRoleKeys[$binding->role])) {
                    throw new ManifestException(sprintf(
                        '%s "%s" binds global role "%s" with inherit: false; a global role '
                        . 'applies everywhere and ignores the resource, so the server refuses '
                        . 'the flag',
                        $entity->kind->value,
                        $entity->key,
                        $binding->role,
                    ));
                }
            }
        }
    }

    private static function assertNoCycles(ManagementManifest $manifest): void
    {
        $edges = [];
        foreach ($manifest->entities as $entity) {
            $edges[$entity->key] = $entity->depends;
        }

        $state = [];

        $walk = static function (string $key, array $path) use (&$walk, &$state, $edges): void {
            if (($state[$key] ?? null) === 'done') {
                return;
            }
            if (($state[$key] ?? null) === 'open') {
                $cycle = array_slice($path, (int) array_search($key, $path, true));
                throw new ManifestException(sprintf(
                    'manifest has a dependency cycle: %s',
                    implode(' -> ', [...$cycle, $key]),
                ));
            }

            $state[$key] = 'open';
            $path[] = $key;
            foreach ($edges[$key] ?? [] as $next) {
                if (isset($edges[$next])) {
                    $walk($next, $path);
                }
            }
            $state[$key] = 'done';
        };

        foreach (array_keys($edges) as $key) {
            $walk($key, []);
        }
    }
}
