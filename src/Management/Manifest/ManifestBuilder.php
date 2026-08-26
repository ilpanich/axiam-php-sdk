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
     * @param string       $key         Manifest-local identity.
     * @param string       $name        The group's name.
     * @param string       $description Human-readable description.
     * @param list<string> $roleKeys    Keys of roles this group carries.
     * @param array<string,mixed> $metadata Free-form metadata.
     */
    public function group(
        string $key,
        string $name,
        string $description,
        array $roleKeys = [],
        array $metadata = [],
    ): self {
        $fields = ['name' => $name, 'description' => $description, 'roles' => $roleKeys];
        if ($metadata !== []) {
            $fields['metadata'] = $metadata;
        }
        $this->entities[] = new ManifestEntity(
            ManifestKind::Group,
            $key,
            $name,
            $fields,
            $roleKeys,
        );

        return $this;
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
