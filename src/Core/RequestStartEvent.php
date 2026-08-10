<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

/**
 * Emitted before an outbound call leaves the SDK (CONTRACT.md §19).
 */
final class RequestStartEvent extends TelemetryEvent
{
    /**
     * @param string $operation    Canonical operation name, e.g. `checkAccess`.
     * @param string $method       HTTP method.
     * @param string $pathTemplate The route constant — `/api/v1/authz/check`, never a
     *                             URL with ids substituted in. A metric label carrying
     *                             a UUID is a cardinality bomb.
     * @param int    $attempt      1 for the first try, incrementing per §16 retry.
     */
    public function __construct(
        public readonly string $operation,
        public readonly string $method,
        public readonly string $pathTemplate,
        public readonly int $attempt,
    ) {
    }
}
