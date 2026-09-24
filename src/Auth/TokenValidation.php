<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

use Axiam\Sdk\Grpc\Gen\ValidateTokenResponse;

/**
 * The result of `AxiamClient::validateToken()` — every field of the wire
 * `ValidateTokenResponse` (CONTRACT.md §1.1.1 rule 3, contract 1.51).
 *
 * **`$valid` is not permission to proceed.** Call {@see self::status()}, or
 * {@see self::verifyPossession()}; see {@see TokenStatus}'s own doc for why.
 */
final class TokenValidation
{
    use TokenBindingSupport;

    /**
     * @param bool                                  $valid     The server's verdict on
     *        signature, expiry and tenant — and nothing more. `false` for a token of
     *        another tenant, with every other field empty (§1.1.1 rule 6).
     * @param string                                $subjectId Subject UUID; empty when
     *        not valid.
     * @param string                                $tenantId  Tenant UUID; empty when
     *        not valid.
     * @param string                                $orgId     Organization UUID; empty
     *        when not valid.
     * @param int                                   $exp       Expiry, seconds since the
     *        epoch; `0` when not valid.
     * @param array{'x5t#S256':?string,jkt:?string}|null $cnf The RFC 7800 confirmation.
     *        `null` means **unbound**; a present array with both members `null` is an
     *        empty confirmation, refused rather than read as unbound (§10.3 rule 3).
     *        Always carried, whether or not the caller looks at it — the field is the
     *        reason this method exists.
     * @param string                                $tokenType `"Bearer"` or `"DPoP"`.
     *        **Does not say whether the token is bound**: a certificate-bound token is
     *        `"Bearer"` (§1.1.1 rule 5). Use {@see self::status()}.
     */
    public function __construct(
        public readonly bool $valid,
        public readonly string $subjectId,
        public readonly string $tenantId,
        public readonly string $orgId,
        public readonly int $exp,
        public readonly ?array $cnf,
        public readonly string $tokenType,
    ) {
    }

    /** Decodes the wire {@see ValidateTokenResponse} into this typed value. */
    public static function fromWire(ValidateTokenResponse $wire): self
    {
        return new self(
            valid: $wire->getValid(),
            subjectId: $wire->getSubjectId(),
            tenantId: $wire->getTenantId(),
            orgId: $wire->getOrgId(),
            exp: (int) $wire->getExp(),
            cnf: self::cnfFromWire($wire->hasCnf() ? $wire->getCnf() : null),
            tokenType: $wire->getTokenType(),
        );
    }

    /**
     * Which of the §10.1 rule 9 cases this is, decided from `$valid` and `$cnf` — never
     * from `$tokenType`.
     */
    public function status(): TokenStatus
    {
        return self::statusOf($this->valid, $this->cnf);
    }

    /**
     * Whether the PRESENTER may use this token: `$valid`, and every sender constraint
     * `$cnf` names satisfied by `$proofs` (§10.1 rule 9, §10.3 rule 2).
     *
     * @throws \Axiam\Sdk\Core\AuthError when the token is not valid, or its `cnf` is not
     *         satisfied — including a present-but-empty `cnf`, which nothing satisfies.
     */
    public function verifyPossession(PresentedProofs $proofs): void
    {
        self::verifyPossessionOf($this->valid, $this->cnf, $proofs);
    }
}
