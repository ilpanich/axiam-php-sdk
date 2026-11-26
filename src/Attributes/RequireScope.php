<?php

declare(strict_types=1);

namespace Axiam\Sdk\Attributes;

use Attribute;

/**
 * Declarative local OAuth2-scope check (CONTRACT.md §11.2 rule 11 (d), contract 1.68; N15) —
 * the canonical `require_scope(scope...)`.
 *
 * Like {@see RequireRole} it is metadata read by the framework-specific enforcement listener
 * ({@see \Axiam\Sdk\Symfony\AxiamAccessAttributeListener},
 * {@see \Axiam\Sdk\Laravel\AxiamAccessMiddleware}), which delegates to
 * {@see \Axiam\Sdk\AccessEnforcer::enforceScope()}, and it is a LOCAL check: it reads the
 * verified token's `scope` claim (the space-separated list of RFC 6749 §3.3) and never makes a
 * server round-trip. It passes when the token's scopes contain at least one of
 * {@see self::$scopes} (whole entries, exact and case-sensitive — `administrator` does not
 * satisfy `admin`); a route that needs several scopes stacks the attribute.
 *
 * It reads ONLY `scope`. A scope says what the *client* was authorised to ask for, not what
 * the *user* holds: it is coarser than {@see RequireAccess}, which is the authoritative check,
 * and it is no substitute for {@see RequireRole}, which reads only the `roles` claim.
 *
 * An unauthenticated request is a 401; a token with no `scope` claim, or one that is not a
 * string, or whose scopes do not contain any required scope, is a 403.
 */
#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]
final class RequireScope
{
    /** @var list<string> */
    public readonly array $scopes;

    /**
     * @param string ...$scopes One or more OAuth2 scope names; the check passes when the
     *                          token's `scope` claim contains at least one of them.
     */
    public function __construct(string ...$scopes)
    {
        $this->scopes = array_values($scopes);
    }
}
