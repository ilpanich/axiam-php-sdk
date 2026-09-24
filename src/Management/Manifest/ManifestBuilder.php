<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

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
     * @param array<string,mixed> $metadata Free-form metadata.
     */
    public function resource(
        string $key,
        string $name,
        string $type,
        ?string $parentKey = null,
        array $metadata = [],
    ): self {
        $fields = ['name' => $name, 'resource_type' => $type];
        if ($metadata !== []) {
            $fields['metadata'] = $metadata;
        }
        $this->entities[] = new ManifestEntity(
            ManifestKind::Resource,
            $key,
            $name,
            $fields,
            $parentKey !== null ? [$parentKey] : [],
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
     * @param array<string,mixed> $metadata Free-form metadata.
     */
    public function group(
        string $key,
        string $name,
        string $description,
        array $roleKeys = [],
        array $metadata = [],
    ): self {
        $bindings = array_map(RoleBinding::from(...), $roleKeys);
        $fields = ['name' => $name, 'description' => $description, 'roles' => $bindings];
        if ($metadata !== []) {
            $fields['metadata'] = $metadata;
        }
        $this->entities[] = new ManifestEntity(
            ManifestKind::Group,
            $key,
            $name,
            $fields,
            self::bindingDependencies($bindings),
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
        $this->entities[] = new ManifestEntity(
            ManifestKind::ServiceAccount,
            $key,
            $name,
            $fields,
            self::bindingDependencies($bindings),
        );

        return $this;
    }

    /**
     * The manifest-local keys a list of role bindings depends on: every bound role's key,
     * plus every scoped binding's resource key — so a dangling reference to either is
     * caught by {@see ManifestValidation} before any request, exactly like a resource's
     * `parent`.
     *
     * @param list<RoleBinding> $bindings
     * @return list<string>
     */
    private static function bindingDependencies(array $bindings): array
    {
        $keys = [];
        foreach ($bindings as $binding) {
            $keys[$binding->role] = true;
            if ($binding->resource !== null) {
                $keys[$binding->resource] = true;
            }
        }

        return array_keys($keys);
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
