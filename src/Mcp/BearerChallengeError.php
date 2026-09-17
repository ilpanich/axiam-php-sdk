<?php

declare(strict_types=1);

namespace Axiam\Sdk\Mcp;

/**
 * The three RFC 6750 §3.1 error codes a `WWW-Authenticate: Bearer` challenge may name
 * (CONTRACT.md §28.4) — the complete vocabulary; nothing else, not even a well-formed
 * OAuth error code such as `invalid_grant`, is accepted by {@see Mcp::bearerChallenge()}.
 *
 * Class constants rather than a backed `enum`, matching {@see \Axiam\Sdk\Rest\ReasonCode}'s
 * own rationale: {@see Mcp::bearerChallenge()} takes this as an input it validates and
 * refuses, never a value it reads back off the wire, so there is nothing here an enum's
 * `from()`/`tryFrom()` would need to tolerate.
 */
final class BearerChallengeError
{
    /** Available to a caller building its own challenge for its own `400` (CONTRACT.md §28.4). Never emitted by this SDK's own guards. */
    public const INVALID_REQUEST = 'invalid_request';

    /** A credential was presented and rejected — the ONLY reason this SDK's own guards ever name (CONTRACT.md §28.4). */
    public const INVALID_TOKEN = 'invalid_token';

    /** A `require_access` call that named a `scope` was denied with `reason_code: "no_grant"` (CONTRACT.md §28.5 rule 5). */
    public const INSUFFICIENT_SCOPE = 'insufficient_scope';

    private function __construct()
    {
    }
}
