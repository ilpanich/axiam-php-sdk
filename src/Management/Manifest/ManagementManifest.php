<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

/**
 * A declarative description of the state a tenant must be in (CONTRACT.md §27.6).
 *
 * The whole point of the declarative layer is that a manifest says what must EXIST, not
 * what to DO. The imperative surface (`$client->management()->roles()->create(...)`) is
 * fine for one change; it is a poor way to describe a tenant, because re-running it
 * either fails on the second run or requires the caller to hand-write the "does it exist
 * already?" logic for every object. A manifest is re-runnable by construction: apply it
 * twice and the second run sends nothing.
 *
 * Two properties are worth stating because they constrain everything else:
 *
 * - **Omission is never deletion.** A tenant holds objects this manifest does not mention,
 *   and they are left strictly alone.
 * - **Ordering is DERIVED, not declared.** The caller does not sequence anything; see
 *   {@see ManifestKind} and {@see self::ordered()}.
 */
final class ManagementManifest
{
    /**
     * @param list<ManifestEntity> $entities Everything this manifest declares.
     */
    public function __construct(public readonly array $entities = [])
    {
    }

    /** A fluent builder — the usual way to construct one by hand. */
    public static function builder(): ManifestBuilder
    {
        return new ManifestBuilder();
    }

    /**
     * The entities in apply order: by kind, then by an explicit dependency sort within
     * each kind, then by key.
     *
     * The final tie-break on `$key` is what makes a plan STABLE ACROSS RUNS (§27.6). Two
     * entities of the same kind with no dependency between them have no natural order, and
     * without a deterministic tie-break they would come out in whatever order the
     * declaration happened to be built in — making every plan diff unreadable.
     *
     * @return list<ManifestEntity>
     * @throws ManifestException when a dependency is dangling or circular.
     */
    public function ordered(): array
    {
        ManifestValidation::assertValid($this);

        $byKind = [];
        foreach ($this->entities as $entity) {
            $byKind[$entity->kind->value][] = $entity;
        }

        $out = [];
        foreach (ManifestKind::cases() as $kind) {
            $group = $byKind[$kind->value] ?? [];
            usort($group, static fn (ManifestEntity $a, ManifestEntity $b): int
                => strcmp($a->key, $b->key));
            foreach (self::topological($group) as $entity) {
                $out[] = $entity;
            }
        }

        return $out;
    }

    /**
     * Depth-first dependency sort within one kind, preserving the caller's key order for
     * anything unconstrained.
     *
     * @param list<ManifestEntity> $group
     * @return list<ManifestEntity>
     */
    private static function topological(array $group): array
    {
        $index = [];
        foreach ($group as $entity) {
            $index[$entity->key] = $entity;
        }

        $out = [];
        $done = [];

        $visit = static function (ManifestEntity $entity) use (&$visit, &$out, &$done, $index): void {
            if (isset($done[$entity->key])) {
                return;
            }
            // Marked BEFORE recursing: a cycle would otherwise recurse forever here.
            // ManifestValidation has already refused cycles, so this is belt and braces
            // rather than the primary defence — but an infinite loop is a bad way to
            // discover that the primary defence regressed.
            $done[$entity->key] = true;
            foreach ($entity->depends as $key) {
                if (isset($index[$key])) {
                    $visit($index[$key]);
                }
            }
            $out[] = $entity;
        };

        foreach ($group as $entity) {
            $visit($entity);
        }

        return $out;
    }

    /**
     * Every entity of one kind, keyed by its manifest key.
     *
     * @return array<string,ManifestEntity>
     */
    public function ofKind(ManifestKind $kind): array
    {
        $out = [];
        foreach ($this->entities as $entity) {
            if ($entity->kind === $kind) {
                $out[$entity->key] = $entity;
            }
        }

        return $out;
    }
}
