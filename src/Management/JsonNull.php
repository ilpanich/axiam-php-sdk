<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management;

/**
 * An explicit JSON `null`, as distinct from an ABSENT member (CONTRACT.md §27.4 rule 5,
 * "null is not absent").
 *
 * Everywhere else on the §27 surface a PHP `null` property means "absent" and is left out of
 * the wire body. A handful of fields need the third state, and only those declare
 * `T|JsonNull|null`:
 *
 * - `UpdateDirectoryConfig::$groupBaseDn` / `$groupFilter` (§30.2): `null` leaves the stored
 *   value alone, `JsonNull::Null` sends `null` and **clears** it —
 *   `new UpdateDirectoryConfig(groupFilter: JsonNull::Null)` sends exactly
 *   `{"group_filter": null}`.
 * - `SamlIdpInfo::$activeCredentialId` / `$nextCredentialId` (§29.8 test 8): decoded as
 *   `JsonNull::Null` when the server said `null` (the slot is empty), and as PHP `null` only
 *   when it sent no such member.
 */
enum JsonNull
{
    /** The JSON literal `null`. */
    case Null;
}
