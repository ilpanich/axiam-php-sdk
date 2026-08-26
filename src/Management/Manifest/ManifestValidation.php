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
     * Every `depends` entry must name an entity the manifest actually declares.
     *
     * A dangling reference is the failure mode this whole class exists for: it is
     * invisible until apply reaches the entity that needs it, by which point the objects
     * before it are already created.
     *
     * @param array<string,true> $keys
     */
    private static function assertNoDanglingReferences(ManagementManifest $manifest, array $keys): void
    {
        $byKey = [];
        foreach (array_keys($keys) as $identity) {
            $byKey[explode(':', $identity, 2)[1]] = true;
        }

        foreach ($manifest->entities as $entity) {
            foreach ($entity->depends as $dependency) {
                if (!isset($byKey[$dependency])) {
                    throw new ManifestException(sprintf(
                        '%s:%s depends on "%s", which this manifest does not declare',
                        $entity->kind->value,
                        $entity->key,
                        $dependency,
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
