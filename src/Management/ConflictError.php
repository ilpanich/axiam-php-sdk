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
 */
final class ConflictError extends AuthzError
{
    /**
     * @param string $message Describes what already exists, or what state forbids the write.
     */
    public function __construct(string $message)
    {
        parent::__construct($message);
    }
}
