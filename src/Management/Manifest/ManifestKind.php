<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

/**
 * The entity kinds a §27.6 manifest can declare.
 *
 * The order of the cases is the order {@see ManagementPlan} applies them in, and it is
 * not alphabetical or arbitrary — it is the dependency order §27.6 requires be DERIVED
 * rather than written down by the caller. A role cannot be granted a permission that
 * does not exist yet, and a group cannot be assigned a role that does not exist yet.
 */
enum ManifestKind: string
{
    /** A hierarchical resource. Ordered first, and among themselves parents before children. */
    case Resource = 'resource';

    /** A permission (an action). Depends on nothing. */
    case Permission = 'permission';

    /** A role, plus the permission grants it carries. Depends on permissions and resources. */
    case Role = 'role';

    /** A group, plus the roles assigned to it. Depends on roles. */
    case Group = 'group';

    /**
     * This kind's position in the derived apply order — lower runs first.
     *
     * Reading it off the case list rather than storing a second number keeps the two
     * from drifting: to change the order you move the case, and there is no other place
     * that has to agree.
     */
    public function order(): int
    {
        return array_search($this, self::cases(), true) ?: 0;
    }
}
