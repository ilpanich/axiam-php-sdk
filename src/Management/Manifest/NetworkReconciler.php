<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

use Axiam\Sdk\Management\ManagementTransport;
use Axiam\Sdk\Management\Models;
use Axiam\Sdk\Management\NetworkApi;
use Axiam\Sdk\Management\Page;
use Axiam\Sdk\Management\PageRequest;

/**
 * The `network` namespace of a §27.6 manifest (CONTRACT.md §27.6.2, contract 1.62): what
 * `plan` reads, and how `apply` writes the three kinds — the tenant's policy, its segments and
 * their reply profiles — through the generated {@see NetworkApi}.
 *
 * Rules this class keeps, each one the contract's:
 *
 * - **Reads are `GET`s, walked to exhaustion** (`get_policy`, `list_segments`,
 *   `list_profiles`), and every stated member is judged **on the value as read**: a profile's
 *   `session_timeout_secs` is the effective, clamped one. No hidden or stored value is
 *   compared and none is kept.
 * - **An `Update` is a full, version-conditional replacement built from the read** — the
 *   stated members replace the read's, the unstated ones are carried from it, a member stated
 *   as none (PHP `null` in the entity's fields) is left out of the body — sent with the
 *   `version` `plan` read, exactly. A segment's `kind`, `site_key` and `name` are never in it.
 * - **A profile carries its segment's `version`**, and when this same `apply` wrote the
 *   segment that is the write's response's, not the one `plan` read ({@see NetworkApplyState}).
 * - **Nothing is retried, re-read or adjusted.** A `409` (a {@see \Axiam\Sdk\Management\ConflictError}
 *   with its `reason_code`) or a `403` is the action's failure, and `apply` stops there.
 */
final class NetworkReconciler
{
    /** Page size used when reading; the walk continues until a page is empty. */
    private const SCAN_LIMIT = 200;

    /** The one manifest-local key (and name) of the singleton policy. */
    public const POLICY_KEY = 'network';

    /**
     * @param NetworkApi $network The generated namespace handle the reads and writes go through.
     */
    public function __construct(private readonly NetworkApi $network)
    {
    }

    /**
     * The identity of a segment: site + kind + name, `kind` in its WIRE spelling.
     *
     * Encoded as JSON so that no value of the three can be confused with a delimiter: the
     * server judges the values, and this key must not decide that two different triples are
     * one.
     */
    public static function segmentKey(string $site, string $kind, string $name): string
    {
        return (string) json_encode([$site, $kind, $name], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * The tenant's policy, as `get_policy` reads it (it always exists: the default until the
     * tenant first writes one).
     *
     * @return array<string,array<string,mixed>> {@see self::POLICY_KEY} => wire object
     */
    public function readPolicy(): array
    {
        return [self::POLICY_KEY => $this->network->getPolicy()->toArray()];
    }

    /**
     * Every segment of the tenant, walked to exhaustion.
     *
     * @return array<string,array<string,mixed>> segment key => wire object
     */
    public function readSegments(): array
    {
        $rows = [];
        $walk = ManagementTransport::walk(
            fn (PageRequest $page): Page => $this->network->listSegments($page),
            new PageRequest(0, self::SCAN_LIMIT),
        );
        foreach ($walk as $segment) {
            if ($segment instanceof Models\NetworkSegmentResponse) {
                $rows[self::segmentKey($segment->siteKey, $segment->kind->value, $segment->name)]
                    = $segment->toArray();
            }
        }

        return $rows;
    }

    /**
     * Every reply profile of the tenant, walked to exhaustion and matched to its segment by
     * `segment_id`. Each row also carries `id` (the segment's, which is the profile's address).
     *
     * @param array<string,array<string,mixed>> $segments {@see self::readSegments()}'s result.
     * @return array<string,array<string,mixed>> segment key => wire object
     */
    public function readProfiles(array $segments): array
    {
        $bySegmentId = [];
        foreach ($segments as $segmentKey => $row) {
            if (\is_string($row['id'] ?? null)) {
                $bySegmentId[$row['id']] = $segmentKey;
            }
        }

        $rows = [];
        $walk = ManagementTransport::walk(
            fn (PageRequest $page): Page => $this->network->listProfiles($page),
            new PageRequest(0, self::SCAN_LIMIT),
        );
        foreach ($walk as $profile) {
            if (!$profile instanceof Models\NetworkReplyProfile) {
                continue;
            }
            $segmentKey = $bySegmentId[$profile->segmentId] ?? null;
            if ($segmentKey !== null) {
                $rows[$segmentKey] = $profile->toArray() + ['id' => $profile->segmentId];
            }
        }

        return $rows;
    }

    /**
     * Creates or replaces the tenant's policy, returning the tenant id (a policy has no id of
     * its own). `replace_policy` sends the version `plan` read — `0` for a tenant that has
     * never written one, which is the first write.
     *
     * @param array<string,mixed> $fields The stated members (the whole declaration on a first write).
     */
    public function applyPolicy(array $fields, NetworkApplyState $state): string
    {
        $read = $state->rows[ManifestKind::NetworkPolicy->value][self::POLICY_KEY] ?? [];
        $written = $this->network->replacePolicy(new Models\ReplaceNetworkPolicyRequest(
            sessionTimeoutMaxSecs: self::int($fields, 'session_timeout_max_secs'),
            version: self::int($read, 'version'),
        ));

        return $written->tenantId;
    }

    /**
     * Creates or replaces one segment, returning its id and recording the write's `version`.
     *
     */
    public function applySegment(PlannedChange $change, ManifestEntity $entity, NetworkApplyState $state): string
    {
        $stated = $entity->fields;

        if ($change->action === ChangeAction::Create) {
            $written = $this->network->createSegment(new Models\CreateNetworkSegmentRequest(
                kind: Models\NetworkSegmentKind::from(self::string($stated, 'kind')),
                name: self::string($stated, 'name'),
                siteKey: self::string($stated, 'site_key'),
                vlanId: self::int($stated, 'vlan_id'),
                enabled: isset($stated['enabled']) ? (bool) $stated['enabled'] : null,
                filterIds: isset($stated['filter_ids']) ? self::strings($stated['filter_ids']) : null,
                rank: isset($stated['rank']) ? self::int($stated, 'rank') : null,
            ));
        } else {
            $read = $state->rows[ManifestKind::NetworkSegment->value][$entity->name] ?? [];
            $written = $this->network->replaceSegment((string) $change->id, new Models\ReplaceNetworkSegmentRequest(
                enabled: (bool) ($stated['enabled'] ?? $read['enabled'] ?? true),
                filterIds: self::strings($stated['filter_ids'] ?? $read['filter_ids'] ?? []),
                version: self::int($read, 'version'),
                vlanId: self::int($stated + $read, 'vlan_id'),
                rank: isset($stated['rank']) ? self::int($stated, 'rank') : (isset($read['rank']) ? self::int($read, 'rank') : null),
            ));
        }

        $state->segmentVersions[$entity->name] = $written->version;

        return $written->id;
    }

    /**
     * Creates or replaces one segment's reply profile, returning its id (the segment's).
     *
     * The profile is written against its segment's newest known `version`
     * ({@see NetworkApplyState}), and a replacement also carries the profile's own `version`
     * as `plan` read it.
     *
     * @param string $segmentKey The segment's key ({@see self::segmentKey()}).
     * @param string $segmentId  The segment's server id: read, or just returned by its write.
     */
    public function applyProfile(
        PlannedChange $change,
        ManifestEntity $entity,
        string $segmentKey,
        string $segmentId,
        NetworkApplyState $state,
    ): string {
        $stated = $entity->fields;
        $segmentVersion = $state->segmentVersions[$segmentKey] ?? null;
        if ($segmentVersion === null) {
            throw new ManifestException(sprintf(
                'manifest: could not resolve the version of the segment of profile "%s" — expected '
                . 'it to have been read or just written (§27.6.2 item 4)',
                $entity->key,
            ));
        }

        if ($change->action === ChangeAction::Create) {
            $written = $this->network->createProfile(new Models\CreateNetworkReplyProfileRequest(
                profile: new Models\NetworkReplyProfileInput(
                    sessionTimeoutSecs: self::int($stated, 'session_timeout_secs'),
                    filterId: isset($stated['filter_id']) ? self::string($stated, 'filter_id') : null,
                    idleTimeoutSecs: isset($stated['idle_timeout_secs']) ? self::int($stated, 'idle_timeout_secs') : null,
                    serviceType: isset($stated['service_type']) ? self::serviceType($stated['service_type']) : null,
                    terminationAction: isset($stated['termination_action']) ? self::terminationAction($stated['termination_action']) : null,
                ),
                segmentId: $segmentId,
                segmentVersion: $segmentVersion,
            ));

            return $written->segmentId;
        }

        $read = $state->rows[ManifestKind::NetworkProfile->value][$segmentKey] ?? [];
        // A member the manifest states replaces the read's (stated as none: left out); one it
        // does not state is carried from the read — silence is not an assertion (§27.6 rule 3).
        $member = static fn (string $wire): mixed => \array_key_exists($wire, $stated) ? $stated[$wire] : ($read[$wire] ?? null);
        $filterId = $member('filter_id');
        $idle = $member('idle_timeout_secs');
        $serviceType = $member('service_type');
        $termination = $member('termination_action');
        $written = $this->network->replaceProfile($segmentId, new Models\ReplaceNetworkReplyProfileRequest(
            profile: new Models\NetworkReplyProfileInput(
                sessionTimeoutSecs: self::int($stated + $read, 'session_timeout_secs'),
                dictionary: isset($read['dictionary']) ? self::string($read, 'dictionary') : null,
                filterId: $filterId === null ? null : (string) $filterId,
                idleTimeoutSecs: $idle === null ? null : (int) $idle,
                serviceType: $serviceType === null ? null : self::serviceType($serviceType),
                terminationAction: $termination === null ? null : self::terminationAction($termination),
            ),
            segmentVersion: $segmentVersion,
            version: self::int($read, 'version'),
        ));

        return $written->segmentId;
    }

    /** The wire spelling of a stated service type as the generated enum, or a refusal. */
    private static function serviceType(mixed $wire): Models\RadiusServiceType
    {
        $type = Models\RadiusServiceType::tryFrom((string) $wire);
        if ($type === null || $type === Models\RadiusServiceType::Unknown) {
            throw new ManifestException(sprintf('network profile: service_type "%s" is not one this SDK can send', (string) $wire));
        }

        return $type;
    }

    /** The wire spelling of a stated termination action as the generated enum, or a refusal. */
    private static function terminationAction(mixed $wire): Models\RadiusTerminationAction
    {
        $action = Models\RadiusTerminationAction::tryFrom((string) $wire);
        if ($action === null || $action === Models\RadiusTerminationAction::Unknown) {
            throw new ManifestException(sprintf('network profile: termination_action "%s" is not one this SDK can send', (string) $wire));
        }

        return $action;
    }

    /**
     * @param array<string,mixed> $fields
     */
    private static function int(array $fields, string $key): int
    {
        $value = $fields[$key] ?? null;
        if (!\is_int($value)) {
            throw new ManifestException(sprintf('manifest field "%s" must be an integer', $key));
        }

        return $value;
    }

    /**
     * @param array<string,mixed> $fields
     */
    private static function string(array $fields, string $key): string
    {
        $value = $fields[$key] ?? null;
        if (!\is_string($value)) {
            throw new ManifestException(sprintf('manifest field "%s" must be a string', $key));
        }

        return $value;
    }

    /**
     * @return list<string>
     */
    private static function strings(mixed $list): array
    {
        return array_values(array_map(static fn (mixed $v): string => (string) $v, (array) $list));
    }
}
