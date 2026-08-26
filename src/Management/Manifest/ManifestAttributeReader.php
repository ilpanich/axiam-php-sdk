<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

use Axiam\Sdk\Attributes\ManagedGroup;
use Axiam\Sdk\Attributes\ManagedPermission;
use Axiam\Sdk\Attributes\ManagedResource;
use Axiam\Sdk\Attributes\ManagedRole;

/**
 * Builds a {@see ManagementManifest} from the `#[Managed*]` attributes on a class
 * (CONTRACT.md §27.6).
 *
 * This is the PHP idiom for the declarative layer, and it buys something the fluent
 * builder cannot: the declaration lives in version control as a type, so a tenant's shape
 * is reviewed like code, diffed like code, and can be referenced from anywhere in the
 * application by class name.
 *
 * The class is never instantiated and its methods are never called. Only its attributes
 * are read — so a manifest class can be an empty class body, and reading one has no side
 * effects beyond autoloading it.
 */
final class ManifestAttributeReader
{
    /**
     * Reads the manifest declared by `$className`'s attributes.
     *
     * @param class-string $className The annotated class.
     * @throws ManifestException when the class does not exist, or its declaration is
     *         incoherent (a dangling reference, a cycle, a duplicate key).
     */
    public static function read(string $className): ManagementManifest
    {
        if (!class_exists($className)) {
            throw new ManifestException(sprintf(
                'manifest class "%s" does not exist',
                $className,
            ));
        }

        $reflection = new \ReflectionClass($className);
        $builder = new ManifestBuilder();

        // Declaration order within the class is irrelevant: ManagementManifest::ordered()
        // derives the apply order, so an author can group these however reads best.
        foreach ($reflection->getAttributes(ManagedResource::class) as $attribute) {
            $declared = $attribute->newInstance();
            $builder->resource(
                $declared->key,
                $declared->name,
                $declared->type,
                $declared->parentKey,
                $declared->metadata,
            );
        }

        foreach ($reflection->getAttributes(ManagedPermission::class) as $attribute) {
            $declared = $attribute->newInstance();
            $builder->permission($declared->key, $declared->action, $declared->description);
        }

        foreach ($reflection->getAttributes(ManagedRole::class) as $attribute) {
            $declared = $attribute->newInstance();
            $builder->role(
                $declared->key,
                $declared->name,
                $declared->description,
                $declared->isGlobal,
                $declared->grants,
            );
        }

        foreach ($reflection->getAttributes(ManagedGroup::class) as $attribute) {
            $declared = $attribute->newInstance();
            $builder->group(
                $declared->key,
                $declared->name,
                $declared->description,
                $declared->roleKeys,
                $declared->metadata,
            );
        }

        return $builder->build();
    }
}
