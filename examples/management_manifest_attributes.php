<?php

declare(strict_types=1);

/**
 * examples/management_manifest_attributes.php — the same CONTRACT.md §27.6 manifest,
 * declared with PHP attributes instead of the fluent builder.
 *
 * This is the idiomatic PHP face of the declarative layer, and the one this SDK already
 * uses for §11 (`#[RequireAccess]`, `#[RequireRole]`). It buys something the builder
 * cannot: the tenant's shape lives in version control as a TYPE — reviewed like code,
 * diffed like code, and referenceable from anywhere by class name.
 *
 * The class is never instantiated and its methods are never called. Only its attributes
 * are read, so a manifest class can be an empty class body.
 *
 * Run: php examples/management_manifest_attributes.php
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\Attributes\ManagedGroup;
use Axiam\Sdk\Attributes\ManagedPermission;
use Axiam\Sdk\Attributes\ManagedResource;
use Axiam\Sdk\Attributes\ManagedRole;
use Axiam\Sdk\Management\Manifest\ManifestAttributeReader;
use Axiam\Sdk\Management\Manifest\ManifestException;

/**
 * The shape the `acme` tenant must be in.
 *
 * Declaration ORDER here is irrelevant — §27.6 requires the apply order to be DERIVED,
 * and it is: resources (parents before children), then permissions, then roles, then
 * groups. Group these however reads best.
 */
#[ManagedResource(key: 'root', name: 'acme', type: 'organization')]
#[ManagedResource(key: 'payroll', name: 'payroll', type: 'folder', parentKey: 'root')]
#[ManagedPermission(key: 'docs.read', action: 'documents:read', description: 'Read documents')]
#[ManagedPermission(key: 'docs.write', action: 'documents:write', description: 'Create and edit documents')]
#[ManagedRole(
    key: 'auditor',
    name: 'auditor',
    description: 'Read-only access for audit',
    grants: ['docs.read' => 'allow'],
)]
// The deny is load-bearing: AXIAM's RBAC is deny-override, so this beats every allow a
// contractor might pick up from anywhere else, at any depth of the resource hierarchy.
#[ManagedRole(
    key: 'contractor',
    name: 'contractor',
    description: 'External contributor',
    grants: ['docs.read' => 'allow', 'docs.write' => 'deny'],
)]
#[ManagedGroup(key: 'auditors', name: 'auditors', description: 'Internal audit', roleKeys: ['auditor'])]
#[ManagedGroup(key: 'externals', name: 'externals', description: 'Contractors', roleKeys: ['contractor'])]
final class AcmeTenant
{
}

try {
    $manifest = ManifestAttributeReader::read(AcmeTenant::class);

    echo "declared, in the order an apply would run:\n";
    foreach ($manifest->ordered() as $entity) {
        printf("  %-12s %s\n", $entity->kind->value, $entity->key);
    }

    echo "\nThis manifest is identical to the one in examples/management_manifest.php;\n";
    echo "hand it to \$client->management()->manifest()->plan() the same way.\n";
} catch (ManifestException $e) {
    // The reader validates exactly like the builder does — a group naming a role nobody
    // declares is refused here, not discovered halfway through an apply.
    fprintf(STDERR, "manifest is not applicable: %s\n", $e->getMessage());
    exit(2);
}
