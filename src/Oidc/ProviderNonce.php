<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\Sensitive;

/**
 * The pair a native sign-in needs (CONTRACT.md §37.4): the **raw** nonce AXIAM wants, and
 * the **hashed** one the provider's SDK wants.
 *
 * Give {@see self::$hashed} to the provider's SDK as *its* nonce; the provider's ID token
 * then carries that hex string in its `nonce` claim. Give {@see self::$raw} to
 * {@see \Axiam\Sdk\AxiamClient::loginWithProviderIdToken()}, which sends it byte for byte —
 * the server hashes it and compares. Swapping the two is invisible at the call site and
 * comes back as the same generic `invalid_grant` as every other refusal, which is why this
 * pair exists.
 *
 * `$raw` is a credential (§37.6): with the provider's token it signs the user in. It is a
 * {@see Sensitive}, so `var_dump()`, `print_r()`, `json_encode()` and string conversion
 * never show it; hold it only for the length of the attempt. `$hashed` is not secret — it
 * travels to the provider and into the token.
 */
final readonly class ProviderNonce
{
    /**
     * @param Sensitive $raw    At least 32 CSPRNG bytes, base64url without padding (ASCII, 43 characters).
     * @param string    $hashed Lower-case hexadecimal SHA-256 of the bytes of the raw value (64 characters).
     */
    public function __construct(
        public Sensitive $raw,
        public string $hashed,
    ) {
    }

    /**
     * Generate a fresh pair. Pure local computation: no network I/O, and nothing is
     * stored anywhere (§37.4 rule 4, §12.3 rule 1).
     */
    public static function generate(): self
    {
        $raw = Pkce::randomUrlSafeToken(Pkce::CSPRNG_BYTES);

        return new self(new Sensitive($raw), self::hash($raw));
    }

    /**
     * `SHA-256` of the bytes of `$raw` as sent (its ASCII bytes), as lower-case hexadecimal
     * (§37.4 rule 2). Exposed for the fixed-vector test of the hashing step.
     */
    public static function hash(string $raw): string
    {
        return hash('sha256', $raw);
    }
}
