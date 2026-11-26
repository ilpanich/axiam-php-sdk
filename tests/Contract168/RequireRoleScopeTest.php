<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract168;

use Axiam\Sdk\AccessEnforcer;
use Axiam\Sdk\Attributes\RequireRole;
use Axiam\Sdk\Attributes\RequireScope;
use Axiam\Sdk\Auth\IdentityClaims;
use Axiam\Sdk\AxiamClient;
use GuzzleHttp\Handler\MockHandler;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * Security audit 2026-11-14, N15 (CONTRACT.md §11.2 rule 11, contract 1.68; D-1): `require_role`
 * reads ONLY the `roles` claim and fails closed; `require_scope` reads ONLY `scope`. Before, the
 * identity's roles were `roles ?? scope`, so a token whose client had merely been registered for
 * a scope named like an application role passed that role's guard, and a genuine role holder
 * whose token lacked the scope was refused.
 *
 * This file covers the claim reading ({@see IdentityClaims}) and the decision
 * ({@see AccessEnforcer}); the same matrix end to end, through both framework bridges with real
 * signed tokens, is in {@see RequireRoleScopeBridgesMiddlewareTest}.
 */
final class RequireRoleScopeTest extends TestCase
{
    private function enforcer(): AccessEnforcer
    {
        return new AccessEnforcer(new AxiamClient('https://api.test', 'acme-tenant', transportHandler: new MockHandler([])));
    }

    /**
     * The identity the §10 guard would inject for these verified claims.
     *
     * @param array<string,mixed> $claims
     *
     * @return array{user_id: string, tenant_id: string, roles: list<string>|null, scopes: list<string>|null}
     */
    private static function identityFor(array $claims): array
    {
        return [
            'user_id' => 'user-1',
            'tenant_id' => 'acme-tenant',
            'roles' => IdentityClaims::roles($claims),
            'scopes' => IdentityClaims::scopes($claims),
        ];
    }

    private static function status(?JsonResponse $response): int
    {
        return $response === null ? 200 : $response->getStatusCode();
    }

    // ---- the claims ----------------------------------------------------------------

    public function testRolesAreNeverDerivedFromScope(): void
    {
        self::assertNull(IdentityClaims::roles(['scope' => 'openid admin']));
        self::assertNull(IdentityClaims::roles(['scope' => ['admin']]));
        self::assertSame(['editor'], IdentityClaims::roles(['scope' => 'openid admin', 'roles' => ['editor']]));
    }

    public function testRolesClaimShapes(): void
    {
        self::assertSame(['admin', 'editor'], IdentityClaims::roles(['roles' => ['admin', 'editor']]));
        self::assertSame([], IdentityClaims::roles(['roles' => []]), 'an empty array is "the user holds none", distinct from absent');
        self::assertNull(IdentityClaims::roles([]), 'absent');
        self::assertNull(IdentityClaims::roles(['roles' => 'admin']), 'a string is not a roles array');
        self::assertNull(IdentityClaims::roles(['roles' => 'admin editor']), 'and is not split on spaces');
        self::assertNull(IdentityClaims::roles(['roles' => ['admin', 7]]), 'a non-string member makes the claim unusable');
        self::assertNull(IdentityClaims::roles(['roles' => ['a' => 'admin']]), 'a JSON object is not an array');
        self::assertNull(IdentityClaims::roles(['roles' => (object) ['admin']]));
        self::assertNull(IdentityClaims::roles(['roles' => null]));
    }

    public function testScopesAreNeverDerivedFromRoles(): void
    {
        self::assertNull(IdentityClaims::scopes(['roles' => ['admin']]));
        self::assertSame(['openid', 'admin'], IdentityClaims::scopes(['scope' => 'openid admin']));
        self::assertSame(['openid', 'admin'], IdentityClaims::scopes(['scope' => 'openid  admin']), 'empty entries dropped');
        self::assertNull(IdentityClaims::scopes(['scope' => ['openid', 'admin']]), 'scope must be a string');
        self::assertNull(IdentityClaims::scopes(['scope' => 7]));
    }

    // ---- require_role --------------------------------------------------------------

    public function testScopeOpenidAdminWithNoRolesClaimIsRefusedByRequireRoleAdmin(): void
    {
        // The N15 bypass: the token says nothing about roles; its client was merely registered for "admin".
        $identity = self::identityFor(['scope' => 'openid admin']);

        self::assertSame(403, self::status($this->enforcer()->enforceRole($identity, new RequireRole('admin'))));
    }

    public function testRolesAdminPassesRequireRoleAdminWhateverTheScope(): void
    {
        $identity = self::identityFor(['scope' => 'openid', 'roles' => ['admin']]);

        self::assertNull($this->enforcer()->enforceRole($identity, new RequireRole('admin')));
    }

    public function testRequireScopeAdminPassesForTheFirstToken(): void
    {
        $identity = self::identityFor(['scope' => 'openid admin']);

        self::assertNull($this->enforcer()->enforceScope($identity, new RequireScope('admin')));
    }

    public function testEmptyRolesAndMalformedRolesAreRefused(): void
    {
        foreach ([['roles' => []], ['roles' => 'admin'], ['roles' => ['Admin']], ['roles' => ['administrator']]] as $claims) {
            self::assertSame(
                403,
                self::status($this->enforcer()->enforceRole(self::identityFor($claims), new RequireRole('admin'))),
                json_encode($claims),
            );
        }
    }

    public function testRequireRoleIsAnyOfAndExact(): void
    {
        $identity = self::identityFor(['roles' => ['viewer', 'owner']]);

        self::assertNull($this->enforcer()->enforceRole($identity, new RequireRole('admin', 'owner')));
        self::assertSame(403, self::status($this->enforcer()->enforceRole($identity, new RequireRole('admin', 'own'))));
    }

    public function testAnIdentityBuiltWithoutARolesMemberFailsClosed(): void
    {
        // An application that builds the identity itself and leaves `roles` out gets a 403, not a pass.
        self::assertSame(403, self::status($this->enforcer()->enforceRole(['user_id' => 'u', 'tenant_id' => 't'], new RequireRole('admin'))));
    }

    public function testUnauthenticatedIsStill401ForBothGuards(): void
    {
        self::assertSame(401, self::status($this->enforcer()->enforceRole(null, new RequireRole('admin'))));
        self::assertSame(401, self::status($this->enforcer()->enforceScope(null, new RequireScope('admin'))));
    }

    // ---- require_scope -------------------------------------------------------------

    public function testRolesNeverStandInForScopes(): void
    {
        $identity = self::identityFor(['roles' => ['admin'], 'scope' => 'openid']);

        self::assertSame(403, self::status($this->enforcer()->enforceScope($identity, new RequireScope('admin'))));
    }

    public function testNoScopeClaimIsRefused(): void
    {
        self::assertSame(403, self::status($this->enforcer()->enforceScope(self::identityFor(['roles' => ['admin']]), new RequireScope('admin'))));
        self::assertSame(403, self::status($this->enforcer()->enforceScope(self::identityFor(['scope' => ['admin']]), new RequireScope('admin'))));
    }

    public function testScopesMatchAsWholeEntriesNotSubstringsAndCaseSensitively(): void
    {
        $enforcer = $this->enforcer();

        self::assertSame(403, self::status($enforcer->enforceScope(self::identityFor(['scope' => 'administrator']), new RequireScope('admin'))));
        self::assertSame(403, self::status($enforcer->enforceScope(self::identityFor(['scope' => 'Admin']), new RequireScope('admin'))));
        self::assertSame(403, self::status($enforcer->enforceScope(self::identityFor(['scope' => 'admin:read']), new RequireScope('admin'))));
        self::assertNull($enforcer->enforceScope(self::identityFor(['scope' => 'openid read admin']), new RequireScope('write', 'admin')));
    }

    public function testRequireScopeAttributeKeepsItsScopes(): void
    {
        self::assertSame(['a', 'b'], (new RequireScope('a', 'b'))->scopes);
    }
}
