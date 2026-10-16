<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management;

use Axiam\Sdk\Core\AuthzError;

/**
 * `409 Conflict` on the §27 management surface — CONTRACT.md §27.4 rule 7.
 *
 * Extends {@see AuthzError} because §2 already maps `409` there as a resource-level
 * refusal; rule 7 KEEPS that mapping rather than moving it. A `catch (AuthzError $e)`
 * written before §27 existed therefore behaves exactly as it did.
 *
 * **`reason_code` (contract 1.62, §36.4).** A `409` of the `network` operations says which
 * conflict it is in a `reason_code` member of its body (`stale_version`, `strands_profile`,
 * `has_children`, `site_gone`, `duplicate_name`, `duplicate_vlan`, `duplicate_rank`,
 * `profile_exists`, `other`, ...). {@see self::getReasonCode()} returns it verbatim — the
 * vocabulary is open, so a value this SDK has never seen comes back as the server wrote it —
 * and `null` when the body carries none (a server before 1.1.0, or a conflict of another
 * namespace). A caller branches on that code and never on the message, which is for a person.
 */
final class ConflictError extends AuthzError
{
    /**
     * @param string      $message    Describes what already exists, or what state forbids the write.
     * @param string|null $reasonCode The `reason_code` member of the `409` body, as written, or
     *                                `null` when the body had none.
     */
    public function __construct(string $message, private readonly ?string $reasonCode = null)
    {
        parent::__construct($message);
    }

    /**
     * The `reason_code` the server named for this conflict (§36.3 rule 2, §36.4).
     *
     * @return string|null The code verbatim (an unknown one included), or `null` when the
     *                     response carried none. Never parsed out of the message.
     */
    public function getReasonCode(): ?string
    {
        return $this->reasonCode;
    }
}
