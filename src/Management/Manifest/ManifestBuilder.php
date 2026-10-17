<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

use Axiam\Sdk\Management\JsonNull;
use Axiam\Sdk\Management\Models;

/**
 * Fluent construction of a {@see ManagementManifest} (CONTRACT.md §27.6).
 *
 * One method per {@see ManifestKind}, each taking the manifest-local key first so a
 * declaration reads as "this thing, called this, looks like this". Nothing here talks to
 * the server: a builder produces a description, and describing a tenant is not the same
 * act as changing one.
 */
final class ManifestBuilder
{
    /** @var list<ManifestEntity> */
    private array $entities = [];

    /**
     * Declares a resource.
     *
     * @param string      $key      Manifest-local identity.
     * @param string      $name     The resource's name.
     * @param string      $type     Its `resource_type`.
     * @param string|null $parentKey The KEY of the parent resource, not its UUID — a
     *                               manifest cannot know a UUID that does not exist yet.
     * @param array<string,mixed>|null $metadata Free-form metadata. `null` (the
     *        default) means UNSTATED — this declaration says nothing about metadata,
     *        so it is never sent and never checked for drift. `[]` is a STATED empty
     *        object (CONTRACT 1.52 N6.5, C-12): sent on `Create`, and checked for
     *        drift on `Update` like any other stated value — distinct from `null`.
     */
    public function resource(
        string $key,
        string $name,
        string $type,
        ?string $parentKey = null,
        ?array $metadata = null,
    ): self {
        $fields = ['name' => $name, 'resource_type' => $type];
        if ($metadata !== null) {
            $fields['metadata'] = $metadata;
        }
        $this->entities[] = new ManifestEntity(
            ManifestKind::Resource,
            $key,
            $name,
            $fields,
            $parentKey !== null ? [$parentKey] : [],
            $parentKey !== null ? [$parentKey => ManifestKind::Resource] : [],
        );

        return $this;
    }

    /**
     * Declares a permission.
     *
     * @param string $key         Manifest-local identity.
     * @param string $action      The action this permission names (e.g. `documents:read`).
     * @param string $description Human-readable description.
     */
    public function permission(string $key, string $action, string $description): self
    {
        $this->entities[] = new ManifestEntity(
            ManifestKind::Permission,
            $key,
            $action,
            ['action' => $action, 'description' => $description],
        );

        return $this;
    }

    /**
     * Declares a role and the permissions granted to it.
     *
     * `$grants` maps a permission KEY to its effect — `'allow'` or `'deny'`. AXIAM's RBAC
     * is DENY-OVERRIDE, not most-specific-wins: an explicit deny beats every allow, at any
     * depth of the resource hierarchy and at equal specificity. A deny grant here is
     * therefore a strong statement, not a default that a narrower allow can reverse.
     *
     * @param string              $key         Manifest-local identity.
     * @param string              $name        The role's name.
     * @param string              $description Human-readable description.
     * @param bool                $isGlobal    Whether the role applies tenant-wide.
     * @param array<string,string> $grants     Permission key => `allow` | `deny`.
     */
    public function role(
        string $key,
        string $name,
        string $description,
        bool $isGlobal = false,
        array $grants = [],
    ): self {
        $this->entities[] = new ManifestEntity(
            ManifestKind::Role,
            $key,
            $name,
            [
                'name' => $name,
                'description' => $description,
                'is_global' => $isGlobal,
                'grants' => $grants,
            ],
            array_keys($grants),
        );

        return $this;
    }

    /**
     * Declares a group and the roles assigned to it.
     *
     * @param string $key         Manifest-local identity.
     * @param string $name        The group's name.
     * @param string $description Human-readable description.
     * @param list<string|RoleBinding> $roleKeys Roles this group carries — a bare role
     *        KEY (tenant-wide, exactly as before contract 1.51) or a {@see RoleBinding}
     *        scoped to a resource (`RoleBinding::at()`/`::atOnly()`, §27.6.1 addition 2).
     * @param array<string,mixed>|null $metadata Free-form metadata. `null` (the
     *        default) means UNSTATED; `[]` is a STATED empty object, distinct from
     *        `null` — see {@see self::resource()}'s identical `$metadata` doc
     *        (CONTRACT 1.52 N6.5, C-12).
     */
    public function group(
        string $key,
        string $name,
        string $description,
        array $roleKeys = [],
        ?array $metadata = null,
    ): self {
        $bindings = array_map(RoleBinding::from(...), $roleKeys);
        $fields = ['name' => $name, 'description' => $description, 'roles' => $bindings];
        if ($metadata !== null) {
            $fields['metadata'] = $metadata;
        }
        $expectedKinds = self::bindingDependencies($bindings);
        $this->entities[] = new ManifestEntity(
            ManifestKind::Group,
            $key,
            $name,
            $fields,
            array_keys($expectedKinds),
            $expectedKinds,
        );

        return $this;
    }

    /**
     * Declares a service account and the roles bound to it (CONTRACT.md §27.6.1
     * addition 3, contract 1.51).
     *
     * Reconciled by NAME, which the server does not keep unique — {@see ManifestApi}
     * refuses `plan()`/`apply()` before any write when more than one existing account
     * matches. `$description` is the only field an `Update` reconciles; `null` is silent,
     * exactly like an unstated resource `metadata`. `apply()` never rotates a secret: a
     * `Create`'s one-time `client_secret` is on {@see ApplyReport::createdServiceAccounts()}.
     *
     * @param string $key         Manifest-local identity, referred to by nothing else —
     *                            a service account cannot itself hold another service
     *                            account's role in contract 1.51.
     * @param string $name        The account's name — its natural key, unenforced.
     * @param string|null $description Human-readable description. `null` is silent.
     * @param list<string|RoleBinding> $roleKeys Roles bound to this account — a bare
     *        role KEY or a resource-scoped {@see RoleBinding}.
     */
    public function serviceAccount(
        string $key,
        string $name,
        ?string $description = null,
        array $roleKeys = [],
    ): self {
        $bindings = array_map(RoleBinding::from(...), $roleKeys);
        $fields = ['name' => $name, 'roles' => $bindings];
        if ($description !== null) {
            $fields['description'] = $description;
        }
        $expectedKinds = self::bindingDependencies($bindings);
        $this->entities[] = new ManifestEntity(
            ManifestKind::ServiceAccount,
            $key,
            $name,
            $fields,
            array_keys($expectedKinds),
            $expectedKinds,
        );

        return $this;
    }

    /**
     * Declares the tenant's `Session-Timeout` cap (CONTRACT.md §27.6.2, contract 1.62): the
     * `network` policy. A **singleton** — the tenant has exactly one, so it has no key, and a
     * manifest that declares two is refused when it is built. The policy always exists on the
     * server (the default, `version` 0, until the tenant first writes one), so it is never a
     * `Create`: it is `NoChange` or an `Update`, sent as `replace_policy` with the version
     * `plan` read. Planned and applied **before** the segments and profiles, because a
     * profile's timeout is checked against the cap at the write.
     *
     * @param int $sessionTimeoutMaxSecs The cap, in seconds. The server judges the range
     *        (300 to 86 400); the SDK does not.
     */
    public function networkPolicy(int $sessionTimeoutMaxSecs): self
    {
        $this->entities[] = new ManifestEntity(
            ManifestKind::NetworkPolicy,
            NetworkReconciler::POLICY_KEY,
            NetworkReconciler::POLICY_KEY,
            ['session_timeout_max_secs' => $sessionTimeoutMaxSecs],
        );

        return $this;
    }

    /**
     * Declares a network segment (CONTRACT.md §27.6.2, contract 1.62).
     *
     * Reconciled by its natural key **site + kind + name**, where `kind` is the WIRE spelling,
     * `access` or `quarantine` — the value `create_segment` writes and every read returns. The
     * SDK keeps no other spelling and no mapping to the server's `zones` path segment. Those
     * three never drift (a segment's kind, site and name do not change, §36.3 rule 4); every
     * other stated member is compared with the value as the read returns it.
     *
     * `$filterIds` is compared as a **set**: the same names in another order are `NoChange`,
     * and when the SDK does write the segment it sends them in the order stated here. A list
     * that repeats a name is refused when the manifest is built — it is a set, and a set has no
     * repeated member. `null` for an optional member is *unstated* (silent, §27.6 rule 3); on
     * an `Update` it is carried from the read.
     *
     * @param string                          $key       Manifest-local identity, referred to by
     *                                                   {@see self::networkProfile()}.
     * @param string                          $site      The wire `site_key`.
     * @param Models\NetworkSegmentKind|string $kind      `access` or `quarantine`; nothing else.
     * @param string                          $name      The segment's name within its site.
     * @param int                             $vlanId    The VLAN (the server checks 1 to 4094).
     * @param int|null                        $rank      Placement rank, for an `access` segment.
     * @param list<string>|null               $filterIds The segment's Filter-Id envelope.
     * @param bool|null                       $enabled   Whether the segment is a placement candidate.
     *
     * @throws ManifestException when `$kind` is neither `access` nor `quarantine`.
     */
    public function networkSegment(
        string $key,
        string $site,
        Models\NetworkSegmentKind|string $kind,
        string $name,
        int $vlanId,
        ?int $rank = null,
        ?array $filterIds = null,
        ?bool $enabled = null,
    ): self {
        $wireKind = $kind instanceof Models\NetworkSegmentKind ? $kind->value : $kind;
        if ($wireKind !== 'access' && $wireKind !== 'quarantine') {
            throw new ManifestException(sprintf(
                'network segment "%s": kind must be "access" or "quarantine", the wire spelling '
                . '(CONTRACT.md §27.6.2 item 1), not "%s"',
                $key,
                $wireKind,
            ));
        }

        $fields = ['site_key' => $site, 'kind' => $wireKind, 'name' => $name, 'vlan_id' => $vlanId];
        if ($rank !== null) {
            $fields['rank'] = $rank;
        }
        if ($filterIds !== null) {
            $fields['filter_ids'] = array_values(array_map('strval', $filterIds));
        }
        if ($enabled !== null) {
            $fields['enabled'] = $enabled;
        }
        $this->entities[] = new ManifestEntity(
            ManifestKind::NetworkSegment,
            $key,
            NetworkReconciler::segmentKey($site, $wireKind, $name),
            $fields,
            setFields: ['filter_ids'],
        );

        return $this;
    }

    /**
     * Declares a segment's reply profile (CONTRACT.md §27.6.2, contract 1.62).
     *
     * A profile has no name or id of its own: its natural key is **its segment**, named here by
     * the manifest-local key of a {@see self::networkSegment()} of the same manifest — and a
     * key the manifest does not declare is a dangling reference, refused when it is built. One
     * profile per segment.
     *
     * Every stated member is compared with the profile as the read returns it, the **effective**
     * one: a stored `session_timeout_secs` above a lowered cap reads as the cap, so a manifest
     * stating the cap is `NoChange` and one stating a value above it is an `Update` whose write
     * the server refuses (`403`) — the action's failure; `apply` stops and nothing is lowered
     * for you. An `Update` of a clamped profile that does not state its timeout carries the read's
     * effective value, so it stores the clamped value from then on (§36.3 rule 6); raise the cap
     * with {@see self::networkPolicy()} first to restore the stored one.
     *
     * `null` is *unstated*: silent on a `Create` and carried from the read on an `Update`.
     * {@see JsonNull::Null} is a member stated as *none*: left out of the body, which is how a
     * replacement clears an optional member.
     *
     * @param string                                          $segmentKey          The segment's manifest-local key.
     * @param int                                             $sessionTimeoutSecs  `Session-Timeout`; the server judges the range.
     * @param Models\RadiusTerminationAction|string|null      $terminationAction   `default` or `radius_request`.
     * @param int|JsonNull|null                               $idleTimeoutSecs     `Idle-Timeout`.
     * @param string|JsonNull|null                            $filterId            One of the segment's `filter_ids`.
     * @param Models\RadiusServiceType|string|JsonNull|null   $serviceType         `framed_user` (the only value there is).
     */
    public function networkProfile(
        string $segmentKey,
        int $sessionTimeoutSecs,
        Models\RadiusTerminationAction|string|null $terminationAction = null,
        int|JsonNull|null $idleTimeoutSecs = null,
        string|JsonNull|null $filterId = null,
        Models\RadiusServiceType|string|JsonNull|null $serviceType = null,
    ): self {
        $fields = ['session_timeout_secs' => $sessionTimeoutSecs];
        if ($terminationAction !== null) {
            $fields['termination_action'] = $terminationAction instanceof Models\RadiusTerminationAction
                ? $terminationAction->value
                : $terminationAction;
        }
        foreach (['idle_timeout_secs' => $idleTimeoutSecs, 'filter_id' => $filterId, 'service_type' => $serviceType] as $wire => $value) {
            if ($value === null) {
                continue;
            }
            $fields[$wire] = $value instanceof JsonNull
                ? null
                : ($value instanceof Models\RadiusServiceType ? $value->value : $value);
        }
        $this->entities[] = new ManifestEntity(
            ManifestKind::NetworkProfile,
            $segmentKey,
            $segmentKey,
            $fields,
            segment: $segmentKey,
        );

        return $this;
    }

    /**
     * The manifest-local keys a list of role bindings depends on, mapped to the KIND
     * each must resolve to: every bound role's key (a {@see ManifestKind::Role}), plus
     * every scoped binding's resource key (a {@see ManifestKind::Resource}) — so a
     * dangling OR wrong-kind reference to either is caught by {@see ManifestValidation}
     * before any request, exactly like a resource's `parent` (CONTRACT 1.52 N6.6, C-12:
     * "references resolve by kind" — a role key that names a group, say, is a dangling
     * reference too).
     *
     * @param list<RoleBinding> $bindings
     * @return array<string,ManifestKind>
     */
    private static function bindingDependencies(array $bindings): array
    {
        $kinds = [];
        foreach ($bindings as $binding) {
            $kinds[$binding->role] = ManifestKind::Role;
            if ($binding->resource !== null) {
                $kinds[$binding->resource] = ManifestKind::Resource;
            }
        }

        return $kinds;
    }

    /**
     * Finishes the manifest.
     *
     * Validates before returning, so an incoherent manifest is rejected at the point it
     * was written rather than at the point somebody applies it.
     *
     * @throws ManifestException when the manifest is incoherent.
     */
    public function build(): ManagementManifest
    {
        $manifest = new ManagementManifest($this->entities);
        ManifestValidation::assertValid($manifest);

        return $manifest;
    }
}
