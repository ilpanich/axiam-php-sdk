<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

/**
 * One role bound to a subject — a group or a service account — in one of the two shapes
 * §27.6.1 addition 2 allows (contract 1.51).
 *
 * A bare role key normalizes to a plain binding via {@see self::from()}, so
 * `->group('eng', 'Engineering', 'desc', roleKeys: ['auditor'])` keeps reading exactly as
 * it did before this class existed.
 *
 * # A subject holds a role at most once
 *
 * The server keys an assignment on `(subject, role)` with no resource component, and a
 * second assignment of the same role to the same subject is a `409` — whatever the
 * resource and whatever the flag. So a subject's bindings name each role ONCE: two scoped
 * bindings of one role, or a plain one and a scoped one, describe a state the server
 * cannot hold, and {@see ManifestValidation} refuses the manifest before any request,
 * naming the subject and the role.
 *
 * # Changing a binding
 *
 * The binding's natural key is `(subject, role)`; its resource and `inherit` are fields.
 * When either differs from the server, the action is an Update, performed as
 * **unassign, then assign** — there is no update endpoint — so between the two calls the
 * subject does not hold the role. If the assign fails, `apply()` assigns the previous
 * binding again and reports both results ({@see BindingRebindFailed}). The server
 * binding's `tenant_scope` (§5.2.3), which a manifest does not state, is carried across
 * unchanged.
 */
final class RoleBinding
{
    private function __construct(
        public readonly string $role,
        public readonly ?string $resource,
        public readonly bool $inherit,
    ) {
    }

    /** The role, with no resource — tenant-wide, and so with no inheritance question. */
    public static function role(string $roleKey): self
    {
        return new self($roleKey, null, true);
    }

    /** `$roleKey` at `$resourceKey`, reaching its descendants. */
    public static function at(string $roleKey, string $resourceKey): self
    {
        return new self($roleKey, $resourceKey, true);
    }

    /**
     * `$roleKey` at `$resourceKey` ONLY — "here and no further". Refused by the server
     * (`400`) for a role with `is_global: true`; {@see ManifestValidation} refuses it
     * first when that role is in the manifest.
     */
    public static function atOnly(string $roleKey, string $resourceKey): self
    {
        return new self($roleKey, $resourceKey, false);
    }

    /**
     * Normalizes a builder-supplied entry: a bare role key becomes a plain
     * {@see self::role()} binding; an already-built binding passes through unchanged.
     */
    public static function from(self|string $value): self
    {
        return $value instanceof self ? $value : self::role($value);
    }
}
