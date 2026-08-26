<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

use Axiam\Sdk\Core\AxiamException;

/**
 * A manifest was rejected before any request was sent (CONTRACT.md §27.6).
 *
 * Every use of this type is a refusal to START. A manifest with a dangling reference or a
 * dependency cycle cannot be applied coherently, and discovering that halfway through —
 * after some objects exist and some do not, with no rollback (§27.7) — is strictly worse
 * than refusing up front. Validation therefore runs before the first wire call, not
 * during.
 */
final class ManifestException extends AxiamException
{
}
