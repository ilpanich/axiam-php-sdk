<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management;

use Axiam\Sdk\Core\AuthzError;

/**
 * `404 Not Found` on the §27 management surface — CONTRACT.md §27.4 rule 7.
 *
 * Extends {@see AuthzError}, which is not the obvious parent and is the point. AXIAM is
 * multi-tenant, and the server answers `404` for an object belonging to another tenant
 * *precisely so* a probing caller cannot tell "does not exist" from "exists, not yours".
 * Classifying it as an authorization outcome keeps the SDK from re-creating that
 * distinction on the client side, where the server deliberately refused to draw it.
 */
final class NotFoundError extends AuthzError
{
    /**
     * @param string $message Describes the missing (or invisible) object.
     */
    public function __construct(string $message)
    {
        parent::__construct($message);
    }
}
