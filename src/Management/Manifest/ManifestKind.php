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
     * A service account, plus the roles bound to it (CONTRACT.md §27.6.1 addition 3,
     * contract 1.51). Depends on roles and resources. Ordered LAST (§27.6 rule 5): a
     * service account's own natural key (its `name`) is not enforced unique by the
     * server, so nothing else in a manifest can reasonably depend on one.
     */
    case ServiceAccount = 'service_account';

    /**
     * The tenant's `Session-Timeout` cap (CONTRACT.md §27.6.2, contract 1.62): a singleton, so
     * it has no natural key and a manifest carries at most one. Ordered FIRST of the three
     * `network` kinds, because a profile's timeout is checked against the cap at the write.
     */
    case NetworkPolicy = 'network_policy';

    /**
     * A network segment (§27.6.2): natural key **site + kind + name**, `kind` being the wire
     * spelling `access` or `quarantine`. Ordered after the policy and before the profiles.
     */
    case NetworkSegment = 'network_segment';

    /**
     * A segment's reply profile (§27.6.2): natural key **its segment**. Ordered last, and in
     * the segments' own order, so that a plan is stable.
     */
    case NetworkProfile = 'network_profile';
}
