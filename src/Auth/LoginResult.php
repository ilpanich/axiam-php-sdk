<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

use Axiam\Sdk\Core\Sensitive;

/**
 * Result of `AxiamClient::login()` (CONTRACT.md §1, D-09).
 *
 * A readonly DTO — never thrown as an exception. **Three outcomes, not two.** Callers
 * MUST check both {@see self::$mfaRequired} and {@see self::$mfaSetupRequired} before
 * assuming a fully-authenticated session was established:
 *
 * - `$mfaRequired` — `$challengeToken` carries the opaque MFA challenge token to pass to
 *   `verifyMfa()`.
 * - `$mfaSetupRequired` (CONTRACT.md §25.2 rule 1) — the tenant requires MFA and this
 *   account has no factor yet, and `$setupToken` carries the token to pass to
 *   `mfaSetupEnroll()`/`mfaSetupConfirm()`. Not a failure, and not a session either: a
 *   client that only branches on `$mfaRequired` reports a successful login that has no
 *   session the moment a tenant turns required MFA on.
 * - neither — `$userId`/`$tenantId` describe the authenticated principal, and
 *   `$organizationLevel` says whether that principal can act across the whole
 *   organization (CONTRACT.md §5.2).
 *
 * Any token-carrying field MUST be typed {@see Sensitive} (CONTRACT.md §7 blanket
 * rule, mirrors the Java SDK's 20-03 `challengeToken` decision) — no raw token string
 * is ever exposed as a plain public property.
 */
final readonly class LoginResult
{
    /**
     * @param bool $organizationLevel Whether the account that just signed in is an
     *     **organization-level** principal (CONTRACT.md §5.2) — one whose record lives in
     *     its organization's reserved tenant, so its global grants apply in every tenant of
     *     that organization and it can act on a different one by sending a different
     *     `X-Axiam-Tenant` on the next request, with no re-login.
     *
     *     An ordinary tenant principal is a principal of exactly one tenant; changing the
     *     header for one of those produces a `403`. This flag is therefore what an
     *     application checks *before* offering a tenant switch, rather than discovering the
     *     answer from a failed request.
     *
     *     Derived from the login response, never asserted by the caller (§5.2 rule 2), and
     *     `false` in three cases that are all the safe direction: a server older than
     *     contract 1.31, and each of the two pending outcomes above, where no principal has
     *     been established yet.
     *
     *     Since contract 1.35 that reach can be narrowed per assignment, so this flag alone
     *     no longer decides what to offer: consult `$reachableTenantIds` as well
     *     (§5.2.3 rule 3).
     * @param string|null $actingTenantId The tenant this login **acts on** — CONTRACT.md
     *     §5.2.2. `null` on the two pending outcomes and against a server older than
     *     contract 1.34.
     * @param string|null $principalTenantId The tenant this principal's record **lives in**.
     *
     *     The same value as `$actingTenantId` for every ordinary principal; the two diverge
     *     only once an organization-level principal selects another tenant to act on. This is
     *     where the account's own credentials belong, and what a §23 registration record for
     *     *this* account must be sealed against — see
     *     {@see \Axiam\Sdk\AxiamClient::opaqueEnrollmentForSelf()}.
     *
     *     Falls back to `$actingTenantId` when the server omits it, which is exactly right
     *     there: a server older than contract 1.34 cannot switch the acting tenant, so the
     *     two cannot differ.
     * @param string|null $principalTenantSlug Slug of `$principalTenantId` —
     *     `"organization"` for an organization-level principal.
     * @param string|null $orgId The caller's organization as a UUID — CONTRACT.md §5.2.2
     *     rule 3. Read this rather than resolving a slug through
     *     `GET /api/v1/organizations`, which is `super-admin`-only and returns only the
     *     caller's own organization.
     * @param list<string>|null $reachableTenantIds The tenants this caller's roles reach,
     *     when narrowed — CONTRACT.md §5.2.3.
     *
     *     `null` means **unrestricted**, which is both the common case and the only thing a
     *     server older than contract 1.35 can mean. A present list is a deliberately narrowed
     *     organization-level account: confine any tenant switch to it, because naming
     *     anything outside is refused at the header.
     *
     *     Note the pairing with `$organizationLevel`: a narrowed account still reports
     *     `true` there, so gating on that flag alone offers tenants the server will refuse.
     */
    public function __construct(
        public bool $mfaRequired,
        public ?Sensitive $challengeToken = null,
        public ?string $userId = null,
        public ?string $tenantId = null,
        public bool $mfaSetupRequired = false,
        public ?Sensitive $setupToken = null,
        public bool $organizationLevel = false,
        public ?string $actingTenantId = null,
        public ?string $principalTenantId = null,
        public ?string $principalTenantSlug = null,
        public ?string $orgId = null,
        public ?array $reachableTenantIds = null,
    ) {
    }
}
