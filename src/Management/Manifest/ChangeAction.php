<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

/**
 * What a plan intends to do to one declared entity (CONTRACT.md §27.6).
 *
 * There is deliberately no `Delete`. §27.6 is explicit that OMISSION IS NEVER DELETION:
 * a manifest describes what must exist, not everything that may exist, and a tenant
 * almost always holds objects no manifest mentions. Inferring deletion from absence
 * would make an incomplete manifest a destructive one.
 */
enum ChangeAction: string
{
    /** The entity does not exist and will be created. */
    case Create = 'create';

    /** The entity exists but differs from the manifest, and will be updated in place. */
    case Update = 'update';

    /** The entity already matches the manifest. Nothing will be sent for it. */
    case Unchanged = 'unchanged';
}
