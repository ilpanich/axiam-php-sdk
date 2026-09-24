<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

/**
 * What a `validateToken`/`introspectToken` result means for the presenter — the three
 * cases CONTRACT.md §10.1 rule 9 and §10.3 distinguish (contract 1.51).
 *
 * `valid`/`active` alone answers "does the signature, expiry and tenant check out?" — it
 * does NOT answer "may whoever handed me this token use it?" That second question is
 * what this enum is for, and reading `valid`/`active` as the whole answer is precisely
 * the defect §10.3 rule 2 exists to name: a resource server that treats `valid: true` as
 * "usable as presented" has converted a sender-constrained token back into a bearer
 * token, discarding the protection the operator turned on.
 */
enum TokenStatus
{
    /**
     * `valid`/`active` is `false`: expired, badly signed, revoked, or a token of
     * **another tenant** — the server reports that as inactive, never as an error
     * (§1.1.1 rule 6).
     */
    case Inactive;

    /** Valid, and carries no `cnf`: an ordinary bearer token. Whoever holds it may use it. */
    case Bearer;

    /**
     * Valid, and sender-constrained: `cnf` names at least one method this SDK can check.
     * Usable only by a presenter who proves possession — call
     * {@see TokenValidation::verifyPossession()} / {@see TokenIntrospection::verifyPossession()}
     * with the proofs from your own connection.
     */
    case SenderConstrained;

    /**
     * Valid, but its `cnf` names **no** method this SDK can check — an empty `CnfClaim`,
     * which proto3 is the only way to spell (§10.3 rule 3). Refused, never read as
     * unbound: nothing satisfies `verifyPossession()` for this status.
     */
    case Unverifiable;
}
