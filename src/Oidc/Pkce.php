<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\Sensitive;

/**
 * PKCE + CSPRNG primitives for the OIDC relying-party flow (CONTRACT.md §12.1
 * "`oidc_begin` inputs and construction", RFC 7636).
 *
 * `random_bytes()` + `hash('sha256', ..., true)` + base64url (via `strtr`/`rtrim` on
 * `base64_encode`) cover everything needed — PHP's own standard library, so §12 adds NO
 * new runtime dependency (plan §6 acceptance criterion 4).
 *
 * **S256 ONLY.** `plain` is not implemented, not reachable, and not configurable: there
 * is no code path in this SDK that can emit `code_challenge_method=plain`.
 */
final class Pkce
{
    /**
     * The only PKCE code-challenge method this SDK emits (RFC 7636 §4.2, CONTRACT.md
     * §12.1 rule 3). `plain` is intentionally absent.
     */
    public const CODE_CHALLENGE_METHOD_S256 = 'S256';

    /**
     * Entropy, in bytes, of a generated `state` / `nonce` / `code_verifier`.
     *
     * §12.1 rule 1 requires at least 16 bytes (128 bits) and RECOMMENDS 32; rule 2
     * RECOMMENDS 32 bytes for the verifier, which base64url-encodes to exactly 43
     * characters — the minimum RFC 7636 §4.1 length, drawn only from the unreserved set
     * `[A-Za-z0-9-._~]`.
     */
    public const CSPRNG_BYTES = 32;

    private function __construct()
    {
        // Static-only utility class.
    }

    /**
     * Generate a URL-safe random token: `$bytes` CSPRNG bytes, base64url-encoded
     * **without** padding (RFC 4648 §5).
     *
     * Used for both `state` and `nonce`, which §12.3 rule 2 classes as **non-secret**:
     * they are returned as plain strings, are echoed through the browser's address bar
     * by construction, and are safe to log.
     */
    public static function randomUrlSafeToken(int $bytes = self::CSPRNG_BYTES): string
    {
        return self::base64UrlEncode(random_bytes($bytes));
    }

    /**
     * Generate a fresh PKCE `code_verifier` (RFC 7636 §4.1): 32 CSPRNG bytes
     * base64url-encoded without padding, i.e. 43 characters from the unreserved set.
     *
     * Returned already wrapped in {@see Sensitive} — §12.5 makes the verifier secret
     * **for its whole lifetime**, including while it sits in the {@see AuthorizationRequest}
     * handed back to the caller and in any {@see OidcStateStoreInterface} entry.
     */
    public static function generateCodeVerifier(): Sensitive
    {
        return new Sensitive(self::randomUrlSafeToken(self::CSPRNG_BYTES));
    }

    /**
     * Derive the PKCE `code_challenge` from a verifier:
     * `BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))`, unpadded (RFC 7636 §4.2,
     * CONTRACT.md §12.1 rule 3).
     *
     * Verified against the RFC 7636 Appendix B test vector in
     * `tests/OidcPkceTest.php`, which every SDK MUST carry (§12.1 rule 3).
     *
     * The challenge is a one-way digest and is **not** secret — it travels in the
     * authorization URL — so it is returned as a plain string.
     */
    public static function computeCodeChallenge(string $codeVerifier): string
    {
        return self::base64UrlEncode(hash('sha256', $codeVerifier, true));
    }

    /** Base64url (RFC 4648 §5), unpadded. */
    public static function base64UrlEncode(string $binary): string
    {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }
}
