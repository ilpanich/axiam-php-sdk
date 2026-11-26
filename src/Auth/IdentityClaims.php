<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

/**
 * Reads the two claims a local role or scope guard decides on, from verified claims
 * (CONTRACT.md §11.2 rule 11, contract 1.68; N15, D-1) — the ONE place both framework
 * bridges ({@see \Axiam\Sdk\Laravel\AxiamMiddleware}, {@see \Axiam\Sdk\Symfony\AxiamAuthSubscriber})
 * get them from, so Laravel and Symfony cannot drift.
 *
 * The two claims are never derived from one another. Before contract 1.68 this SDK built the
 * identity's roles from `roles ?? scope`; a scope is chosen by the *client* and bounded only
 * by its registration, so any user signed in through a client registered for a scope named
 * like an application role passed that role's guard (N15).
 */
final class IdentityClaims
{
    /**
     * The `roles` claim, or `null` when the token has none usable.
     *
     * `null` — the claim is absent, or is not a JSON array of strings — and `[]` — the claim is
     * present and says the subject holds no role — are deliberately different results: both
     * fail every `require_role`, but one means "the application did not request the `roles`
     * scope" and the other "the user holds none" (§11.2 rule 11 (b)).
     *
     * Never reads `scope`, never falls back to any other claim.
     *
     * @param array<string,mixed> $claims Verified claims.
     *
     * @return list<string>|null
     */
    public static function roles(array $claims): ?array
    {
        $roles = $claims['roles'] ?? null;
        if (!is_array($roles) || !array_is_list($roles)) {
            return null;
        }
        foreach ($roles as $role) {
            if (!is_string($role)) {
                return null;
            }
        }

        return $roles;
    }

    /**
     * The `scope` claim as a list: the space-separated string of RFC 6749 §3.3, split on single
     * spaces, empty entries dropped. `null` when the claim is absent or not a string.
     *
     * @param array<string,mixed> $claims Verified claims.
     *
     * @return list<string>|null
     */
    public static function scopes(array $claims): ?array
    {
        $scope = $claims['scope'] ?? null;
        if (!is_string($scope)) {
            return null;
        }

        return array_values(array_filter(explode(' ', $scope), static fn (string $s): bool => $s !== ''));
    }
}
