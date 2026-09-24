<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

use Axiam\Sdk\Grpc\Gen\IntrospectTokenResponse;

/**
 * The result of `AxiamClient::introspectToken()` — the RFC 7662 set, every field of the
 * wire `IntrospectTokenResponse` (CONTRACT.md §1.1.1 rule 3, contract 1.51).
 *
 * **`$active` is not permission to proceed.** Call {@see self::status()}, or
 * {@see self::verifyPossession()}; see {@see TokenStatus}'s own doc for why.
 */
final class TokenIntrospection
{
    use TokenBindingSupport;

    /**
     * @param bool                                  $active         Whether the token is
     *        active (valid and not expired).
     * @param string                                $sub            Subject UUID.
     * @param string                                $tenantId       Tenant UUID.
     * @param string                                $orgId          Organization UUID.
     * @param string                                $iss            Issuer.
     * @param int                                   $iat            Issued-at, seconds
     *        since the epoch.
     * @param int                                   $exp            Expiry, seconds
     *        since the epoch.
     * @param string                                $jti            Unique token id.
     * @param string                                $scope          Space-separated
     *        granted scopes (RFC 7662 §2.2). Empty when the token carries no scope claim.
     * @param string                                $clientId       The client the token
     *        was issued to, when it was issued to one.
     * @param string                                $tokenType      `"Bearer"` or
     *        `"DPoP"`. **Does not say whether the token is bound** — use
     *        {@see self::status()}.
     * @param array{'x5t#S256':?string,jkt:?string}|null $cnf       The RFC 7800/8705/9449
     *        confirmation. `null` means **unbound**; a present array with both members
     *        `null` is an empty confirmation, refused rather than read as unbound
     *        (§10.3 rule 3).
     * @param list<RptPermission>                   $permissions    UMA 2.0 (§20)
     *        permissions — present only on an RPT.
     * @param string                                $extExchangeIss X4 cross-domain
     *        provenance: the foreign issuer whose subject token bought this one, when
     *        there was one. Empty otherwise.
     */
    public function __construct(
        public readonly bool $active,
        public readonly string $sub,
        public readonly string $tenantId,
        public readonly string $orgId,
        public readonly string $iss,
        public readonly int $iat,
        public readonly int $exp,
        public readonly string $jti,
        public readonly string $scope,
        public readonly string $clientId,
        public readonly string $tokenType,
        public readonly ?array $cnf,
        public readonly array $permissions,
        public readonly string $extExchangeIss,
    ) {
    }

    /** Decodes the wire {@see IntrospectTokenResponse} into this typed value. */
    public static function fromWire(IntrospectTokenResponse $wire): self
    {
        $permissions = [];
        foreach ($wire->getPermissions() as $permission) {
            /** @var \Axiam\Sdk\Grpc\Gen\RptPermission $permission */
            $permissions[] = new RptPermission(
                resourceId: $permission->getResourceId(),
                resourceScopes: iterator_to_array($permission->getResourceScopes(), false),
                exp: (int) $permission->getExp(),
            );
        }

        return new self(
            active: $wire->getActive(),
            sub: $wire->getSub(),
            tenantId: $wire->getTenantId(),
            orgId: $wire->getOrgId(),
            iss: $wire->getIss(),
            iat: (int) $wire->getIat(),
            exp: (int) $wire->getExp(),
            jti: $wire->getJti(),
            scope: $wire->getScope(),
            clientId: $wire->getClientId(),
            tokenType: $wire->getTokenType(),
            cnf: self::cnfFromWire($wire->hasCnf() ? $wire->getCnf() : null),
            permissions: $permissions,
            extExchangeIss: $wire->getExtExchangeIss(),
        );
    }

    /**
     * Which of the §10.1 rule 9 cases this is, decided from `$active` and `$cnf` — never
     * from `$tokenType`.
     */
    public function status(): TokenStatus
    {
        return self::statusOf($this->active, $this->cnf);
    }

    /**
     * Whether the PRESENTER may use this token: `$active`, and every sender constraint
     * `$cnf` names satisfied by `$proofs` (§10.1 rule 9, §10.3 rule 2).
     *
     * @throws \Axiam\Sdk\Core\AuthError when the token is not active, or its `cnf` is
     *         not satisfied — including a present-but-empty `cnf`, which nothing
     *         satisfies.
     */
    public function verifyPossession(PresentedProofs $proofs): void
    {
        self::verifyPossessionOf($this->active, $this->cnf, $proofs);
    }
}
