<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

use Axiam\Sdk\Core\AuthError;

/**
 * Shared machinery behind {@see TokenValidation::status()}/`verifyPossession()` and
 * {@see TokenIntrospection::status()}/`verifyPossession()` (CONTRACT.md §10.1 rule 9,
 * §10.3, contract 1.51).
 *
 * Both wire messages carry an optional `CnfClaim`, and CONTRACT.md §10.3 rule 1 requires
 * that a gRPC-validating SDK apply EXACTLY the rule §10.1 already applies to a locally
 * verified token — never a second, looser implementation. Routing both through
 * {@see \Axiam\Sdk\Auth\JwksVerifier::verifyTokenBinding()} (the same primitive
 * `AxiamClient::verifyWithProofs()` uses) is what makes that true by construction: local
 * verification and gRPC validation share one rule-9 implementation, so the two cannot
 * disagree about whether a token is a bearer token (§10.1 rule 9 detail 4).
 */
trait TokenBindingSupport
{
    /**
     * §1.1.1 rule 5 / §10.3: boundness is decided from `cnf` alone, never from
     * `token_type` — the server reports `"Bearer"` for a certificate-bound token too.
     *
     * @param array{'x5t#S256':?string,jkt:?string}|null $cnf
     */
    private static function statusOf(bool $validOrActive, ?array $cnf): TokenStatus
    {
        if (!$validOrActive) {
            return TokenStatus::Inactive;
        }
        if ($cnf === null) {
            return TokenStatus::Bearer;
        }

        return self::namesNothingCheckable($cnf) ? TokenStatus::Unverifiable : TokenStatus::SenderConstrained;
    }

    /**
     * §10.3 rule 3: a `CnfClaim` present on the wire with BOTH members empty names no
     * method this SDK can check, and MUST be refused rather than read as unbound. Proto3
     * cannot distinguish "absent string" from "empty string" — this is the distinction
     * that survives: the message itself being absent (`$cnf === null`) is unbound, and a
     * present-but-empty one is not.
     *
     * @param array{'x5t#S256':?string,jkt:?string} $cnf
     */
    private static function namesNothingCheckable(array $cnf): bool
    {
        return ($cnf['x5t#S256'] ?? null) === null && ($cnf['jkt'] ?? null) === null;
    }

    /**
     * §10.1 rule 9 / §10.3 rule 2: whether the PRESENTER may use this token — `valid`/
     * `active`, and every sender constraint its `cnf` names satisfied by `$proofs`.
     *
     * `$proofs` are what YOUR connection established — the peer certificate's thumbprint,
     * a DPoP proof you verified — never values taken from a request header the caller
     * controls. An unbound valid token is accepted with or without proofs.
     *
     * @param array{'x5t#S256':?string,jkt:?string}|null $cnf
     *
     * @throws AuthError when the token is not valid/active, or when its `cnf` is not
     *         satisfied — including a present-but-empty `cnf`, which nothing satisfies.
     */
    private static function verifyPossessionOf(bool $validOrActive, ?array $cnf, PresentedProofs $proofs): void
    {
        if (!$validOrActive) {
            throw new AuthError(
                'the token is not valid/active (expired, revoked, badly signed, or of another tenant) — '
                . 'CONTRACT.md §1.1.1 rule 6'
            );
        }

        $claims = ['cnf' => $cnf];
        if (!JwksVerifier::verifyTokenBinding($claims, $proofs)) {
            throw new AuthError(
                'the token is sender-constrained and the presented proofs do not satisfy its `cnf` '
                . '(CONTRACT.md §10.1 rule 9, §10.3 rule 2)'
            );
        }
    }

    /**
     * Builds the `['x5t#S256' => ?string, 'jkt' => ?string]` shape from a wire `CnfClaim`,
     * or `null` when the message itself is absent. An empty proto3 string is normalized to
     * `null` per member, so {@see self::namesNothingCheckable()} and
     * {@see \Axiam\Sdk\Auth\JwksVerifier::verifyTokenBinding()} agree on what "not set" means.
     *
     * @return array{'x5t#S256':?string,jkt:?string}|null
     */
    private static function cnfFromWire(?\Axiam\Sdk\Grpc\Gen\CnfClaim $wire): ?array
    {
        if ($wire === null) {
            return null;
        }

        $x5t = $wire->getX5TS256();
        $jkt = $wire->getJkt();

        return [
            'x5t#S256' => $x5t !== '' ? $x5t : null,
            'jkt' => $jkt !== '' ? $jkt : null,
        ];
    }
}
