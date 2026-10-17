<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

/**
 * What one `apply()` knows about the `network` namespace while it runs (CONTRACT.md §27.6.2
 * item 4): the rows `plan` read — the versions a `replace_*` or `delete_*` must send exactly —
 * and, per segment, the `version` of the newest write this apply made to it.
 *
 * The second is why this class exists. A profile is written against its segment's `version`
 * (`segment_version`), and a segment this same `apply` created or replaced has moved on from
 * the one `plan` read: the profile that follows must carry the **write's response** version,
 * or every profile behind a changed segment answers `409 stale_version`.
 *
 * @internal Built by {@see ManifestApi::apply()} and read by {@see NetworkReconciler}.
 */
final class NetworkApplyState
{
    /**
     * @param array<string,array<string,array<string,mixed>>> $rows The state `plan` read:
     *        kind => name => wire object (segments and policy by their key, profiles by their
     *        segment's).
     * @param array<string,int> $segmentVersions Segment key => the newest `version` known.
     */
    public function __construct(
        public readonly array $rows,
        public array $segmentVersions = [],
    ) {
        foreach ($rows[ManifestKind::NetworkSegment->value] ?? [] as $segmentKey => $row) {
            if (\is_int($row['version'] ?? null)) {
                $this->segmentVersions[$segmentKey] = $row['version'];
            }
        }
    }
}
