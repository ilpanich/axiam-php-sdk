<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

/**
 * One entry in a {@see ManagementPlan}: what would happen to one entity, and why.
 */
final class PlannedChange
{
    /**
     * @param ManifestEntity      $entity The declaration this change is for.
     * @param ChangeAction        $action What would be done.
     * @param array<string,mixed> $fields For an update, ONLY the drifted fields — the
     *                                    sparse body §27.4 rule 5 asks for. Empty
     *                                    otherwise.
     * @param string|null         $id     The server id, when the entity already exists.
     */
    public function __construct(
        public readonly ManifestEntity $entity,
        public readonly ChangeAction $action,
        public readonly array $fields = [],
        public readonly ?string $id = null,
    ) {
    }

    /** A one-line rendering, e.g. `create role:auditor`. */
    public function describe(): string
    {
        return sprintf('%s %s:%s', $this->action->value, $this->entity->kind->value, $this->entity->key);
    }
}
