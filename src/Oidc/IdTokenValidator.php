<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\AuthError;

/**
 * ID-token claim validation — CONTRACT.md §12.4, OIDC Core §3.1.3.7.
 *
 * PURE logic only: no network, no JWT decoding, no crypto beyond a constant-time
 * compare. The signature half of §12.4 (rules 1–2: `alg` allowlist, `kid` lookup,
 * Ed25519 verification, single JWKS re-fetch) lives in
 * {@see \Axiam\Sdk\Auth\JwksVerifier::verifyIdTokenSignature()} — the SAME verifier the
 * §10 middleware already uses (§12 forbids forking it). This class holds rules 3–6
 * (issuer, audience, time, nonce) plus the reason-code vocabulary, so both halves can be
 * unit-tested independently, mirroring the TypeScript reference's
 * `oidcIdToken.ts`/`node/jwks.ts` split.
 *
 * Every failure raises {@see AuthError} carrying one of the seven stable reason codes
 * below (CONTRACT.md §12.3 rule 3). Rule 7 (all-or-nothing discard) is enforced by the
 * caller — `AxiamClient::oidcExchange()` never returns a token set whose ID token failed
 * here, so `access_token`/`refresh_token` from the same response are dropped with it.
 */
final class IdTokenValidator
{
    /** §12.4 rule 1 — the only algorithm this SDK accepts for an ID token. */
    public const ID_TOKEN_ALG = 'EdDSA';

    /**
     * Maximum (and default) permitted clock skew in seconds for ID-token time claims.
     * CONTRACT.md §12.4 rule 5 caps this at 60s and forbids any configuration above the
     * bound.
     */
    public const MAX_CLOCK_SKEW_SEC = 60;

    // --- CONTRACT.md §12.3 rule 3 — stable, machine-readable reason codes -------------
    public const REASON_INVALID_ALG = 'invalid_alg';
    public const REASON_UNKNOWN_KID = 'unknown_kid';
    public const REASON_INVALID_SIGNATURE = 'invalid_signature';
    public const REASON_INVALID_ISSUER = 'invalid_issuer';
    public const REASON_INVALID_AUDIENCE = 'invalid_audience';
    public const REASON_TOKEN_EXPIRED = 'token_expired';
    public const REASON_NONCE_MISMATCH = 'nonce_mismatch';

    private function __construct()
    {
        // Static-only utility class.
    }

    /**
     * Build the `AuthError` for a §12.4 failure: a stable machine-readable `$reason`
     * code plus a human-readable message that — per §12.3 rule 3 and §2's construction
     * rules — never embeds the token, a claim value that could carry secret material, or
     * the expected nonce.
     */
    public static function failure(string $reason, string $message): AuthError
    {
        return new AuthError(sprintf('id_token validation failed (%s): %s', $reason, $message), reason: $reason);
    }

    /**
     * Resolve the effective clock skew: the caller's value clamped into
     * `[0, MAX_CLOCK_SKEW_SEC]`, or the maximum when unset.
     */
    public static function resolveClockSkewSec(?int $clockSkewSec): int
    {
        if ($clockSkewSec === null) {
            return self::MAX_CLOCK_SKEW_SEC;
        }

        return min(max($clockSkewSec, 0), self::MAX_CLOCK_SKEW_SEC);
    }

    /**
     * §12.4 rules 3–6 — issuer, audience, time and nonce checks over an
     * already-signature-verified claim set. Returns the claims unchanged on success;
     * throws the matching {@see AuthError} reason code on the first failure.
     *
     * @param array<string,mixed> $claims       The verified JWT payload.
     * @param string              $issuer       The discovery document's `issuer` (§12.4 rule 3).
     * @param string              $clientId     The relying party's own `client_id` (§12.4 rule 4).
     * @param string|null         $nonce        The nonce to check against, or `null` to skip rule 6 (`oidcRefresh`/`loginClientCredentials`).
     * @param int|null            $clockSkewSec Permitted clock skew in seconds; clamped to {@see self::MAX_CLOCK_SKEW_SEC}.
     * @param int|null            $nowSec       Current time in epoch seconds — injectable so tests can pin it.
     *
     * @return array<string,mixed>
     */
    public static function checkClaims(
        array $claims,
        string $issuer,
        string $clientId,
        ?string $nonce = null,
        ?int $clockSkewSec = null,
        ?int $nowSec = null,
    ): array {
        $skew = self::resolveClockSkewSec($clockSkewSec);
        $now = $nowSec ?? time();

        // Rule 3 — exact string comparison. No normalization, no trailing-slash
        // tolerance, no prefix matching.
        $iss = $claims['iss'] ?? null;
        if (!is_string($iss) || $iss !== $issuer) {
            throw self::failure(self::REASON_INVALID_ISSUER, 'iss does not equal the discovery document issuer');
        }

        // Rule 4 — aud must contain our client_id; with multiple audiences an azp claim
        // must be present and equal to it.
        $audClaim = $claims['aud'] ?? null;
        $audiences = is_array($audClaim) ? array_values($audClaim) : [$audClaim];
        if (!in_array($clientId, $audiences, true)) {
            throw self::failure(self::REASON_INVALID_AUDIENCE, 'aud does not contain this client_id');
        }
        if (count($audiences) > 1 && ($claims['azp'] ?? null) !== $clientId) {
            throw self::failure(
                self::REASON_INVALID_AUDIENCE,
                'aud holds multiple audiences and azp is absent or does not equal this client_id',
            );
        }

        // Rule 5 — exp must be in the future, iat must not be in the future, nbf is
        // honored when present; all within $skew seconds. `exp` is treated as REQUIRED:
        // a token with no expiry could never satisfy "exp must be in the future", so its
        // absence is an expiry failure rather than a free pass.
        $exp = $claims['exp'] ?? null;
        if (!is_int($exp) && !is_float($exp)) {
            throw self::failure(self::REASON_TOKEN_EXPIRED, 'exp claim is missing or not a number');
        }
        if ($exp + $skew <= $now) {
            throw self::failure(self::REASON_TOKEN_EXPIRED, 'exp is in the past');
        }

        $iat = $claims['iat'] ?? null;
        if (!is_int($iat) && !is_float($iat)) {
            throw self::failure(self::REASON_TOKEN_EXPIRED, 'iat claim is missing or not a number');
        }
        if ($iat - $skew > $now) {
            throw self::failure(self::REASON_TOKEN_EXPIRED, 'iat is in the future');
        }

        $nbf = $claims['nbf'] ?? null;
        if ((is_int($nbf) || is_float($nbf)) && $nbf - $skew > $now) {
            throw self::failure(self::REASON_TOKEN_EXPIRED, 'nbf is in the future');
        }

        // Rule 6 — mandatory for oidcExchange, skipped when the caller supplied no
        // expected nonce (oidcRefresh / loginClientCredentials).
        if ($nonce !== null) {
            $claimedNonce = $claims['nonce'] ?? null;
            if (!is_string($claimedNonce) || !self::constantTimeEquals($claimedNonce, $nonce)) {
                throw self::failure(self::REASON_NONCE_MISMATCH, 'nonce claim is absent or does not match the request nonce');
            }
        }

        return $claims;
    }

    /**
     * Constant-time string equality, used for the `nonce` comparison §12.4 rule 6
     * requires. Mirrors {@see \Axiam\Sdk\Amqp\Hmac::verify()}'s use of `hash_equals()`.
     */
    public static function constantTimeEquals(string $a, string $b): bool
    {
        return hash_equals($a, $b);
    }
}
