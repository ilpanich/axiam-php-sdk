<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * What a verified back-channel logout token names (CONTRACT.md §12.7.3).
 *
 * Deliberately **not** a bare `bool`: the RP has to know *which* session to end, and a
 * verifier that only says "valid" would force the caller to re-parse the token
 * themselves, with none of the checks this type is proof of.
 */
final class VerifiedLogoutToken
{
    /**
     * @param string|null $sid The session that ended. **When non-`null`, end only this session** — falling back to "every session for `$sub`" is over-reach the AXIAM server itself refuses to make.
     * @param string|null $sub The subject whose session ended.
     * @param string $jti Replay identifier. **The RP dedups on this, not the SDK.** Back-channel delivery is at-least-once with retry, so a valid token legitimately arrives twice; the SDK has no durable store and an in-memory guard would silently drop a real second logout after a restart. Surfaced, never consumed.
     */
    public function __construct(
        public readonly ?string $sid,
        public readonly ?string $sub,
        public readonly string $jti,
    ) {
    }
}
