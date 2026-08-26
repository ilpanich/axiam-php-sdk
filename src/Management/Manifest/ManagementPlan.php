<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

/**
 * What {@see ManifestApi::plan()} produced: the ordered changes an apply would make.
 *
 * A plan is a VALUE. Producing one writes nothing (§27.6) — it reads the tenant's current
 * state and reports the difference, so it is safe to run against production, safe to
 * print, and safe to diff between runs. That last property is why the ordering is derived
 * and deterministic rather than dependent on hash iteration order: two runs against an
 * unchanged tenant must produce the same plan, or nobody can tell a real change from
 * noise.
 */
final class ManagementPlan
{
    /**
     * @param list<PlannedChange> $changes Every declared entity, in apply order —
     *                                     including the unchanged ones, so a reader can
     *                                     see what was considered and not only what moved.
     */
    public function __construct(public readonly array $changes)
    {
    }

    /**
     * Only the changes that would actually send a request.
     *
     * @return list<PlannedChange>
     */
    public function pending(): array
    {
        return array_values(array_filter(
            $this->changes,
            static fn (PlannedChange $c): bool => $c->action !== ChangeAction::Unchanged,
        ));
    }

    /** True when the tenant already matches the manifest and an apply would send nothing. */
    public function isConverged(): bool
    {
        return $this->pending() === [];
    }

    /**
     * The plan as lines of text, one per pending change — what an operator reads before
     * approving an apply.
     *
     * @return list<string>
     */
    public function describe(): array
    {
        return array_map(
            static fn (PlannedChange $c): string => $c->describe(),
            $this->pending(),
        );
    }
}
