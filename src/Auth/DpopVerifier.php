<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

use Axiam\Sdk\Core\AuthError;
use Firebase\JWT\BeforeValidException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

/**
 * DPoP proof verification — CONTRACT.md §21.7.2 (RFC 9449), contract 1.16.
 *
 * The resource-server half of DPoP: given the `DPoP` header a caller presented,
 * decide whether it proves possession for **this** request and **this** access
 * token, and return the key thumbprint that
 * {@see JwksVerifier::verifyTokenBinding()} then matches against the token's
 * `cnf.jkt`.
 *
 * ## Why this lives in the SDK
 *
 * §21.7.2 is a ten-check list, and the contract is blunt about partial
 * implementations: *"Partial verification is worse than none, because it produces
 * a guard that reports success."* Nine of the ten look optional until someone
 * builds an attack out of the one that was skipped, so they belong in one audited
 * place rather than in every application that guards an endpoint.
 *
 * The two most often missing, and what they cost:
 *
 *  - **`typ`** — without pinning it to `dpop+jwt`, any *other* JWT signed by the
 *    same key (an access token, an ID token) is replayable as a proof.
 *  - **`ath`** — without it, a proof captured on one request can be re-aimed at a
 *    different token held by the same key. `ath` binds the proof to the token
 *    rather than merely to the key.
 *
 * ## The algorithm comes from the key, never from the header
 *
 * `alg: none` and RSA-public-key-as-HMAC-secret are the same bug wearing different
 * clothes: *the token told the verifier how to check the token*. This class derives
 * the expected algorithm from the embedded key's own `kty`/`crv` and hands that one
 * algorithm to the decoder, so an HMAC verifier is never a candidate.
 *
 * `firebase/php-jwt` additionally refuses a header whose `alg` disagrees with the
 * key it was given, so a lying `alg` header is *rejected* here rather than ignored
 * — the same posture as the Rust SDK, and stricter than Python's and TypeScript's.
 * Either way the header never selects the algorithm.
 *
 * ## PS256 needs phpseclib
 *
 * `firebase/php-jwt` implements RSASSA-PSS through `phpseclib/phpseclib`, because
 * PHP's own `openssl_verify()` has no PSS padding. phpseclib is already in this
 * SDK's dependency graph, so all three permitted algorithms work out of the box; on
 * an installation where it is somehow absent, a PS256 proof fails closed (rejected)
 * rather than being waved through.
 */
final class DpopVerifier
{
    /**
     * §21.7.2 check 7 — the `iat` acceptance window, applied in **both** directions.
     *
     * RFC 9449 recommends a small window without fixing a number; 60 seconds is the
     * contract's RECOMMENDED value. A named constant, because a bare `60` three call
     * frames deep is a number nobody ever revisits.
     */
    public const IAT_LEEWAY_SECONDS = 60;

    /**
     * RFC 9449 §4.3 — private key material that must never appear in a proof's
     * embedded public `jwk`. `k` is the symmetric-key member: its presence means the
     * "public key" is a shared secret.
     *
     * @var list<string>
     */
    private const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'];

    /**
     * Verify a DPoP proof against this request — all ten §21.7.2 checks.
     *
     * Returns the proof key's RFC 7638 thumbprint (`jkt`) on success. Feed it to
     * {@see JwksVerifier::verifyTokenBinding()} as the DPoP half of
     * {@see PresentedProofs}; returning it rather than `true` is deliberate, so the
     * value a guard passes onward could only have come from a proof that actually
     * verified.
     *
     * @param string      $proof   The raw `DPoP` header value.
     * @param DpopRequest $request The method, URI and access token this proof must match.
     * @param JtiStore    $store   The replay guard. Required — there is no default,
     *   because every default here is either a silent skip of replay protection or a
     *   per-process store masquerading as a global one.
     *
     * @throws AuthError On any failing check.
     *
     * @return string The proof key's `jkt`.
     */
    public static function verifyProof(string $proof, DpopRequest $request, JtiStore $store): string
    {
        if ($proof === '') {
            throw new AuthError('DPoP proof is missing or empty');
        }
        // RFC 9449 §4.2 makes exactly one proof the rule. Rejecting beats picking the
        // first, which is how a verifier and a downstream parser end up reading
        // different proofs.
        if (str_contains($proof, ',') || preg_match('/\s/', trim($proof)) === 1) {
            throw new AuthError('DPoP header must carry exactly one proof');
        }

        $header = self::rawHeader($proof);

        // Check 1 — typ. First, because it is what stops any other JWT signed by the
        // same key from standing in as a proof.
        $typ = $header['typ'] ?? null;
        if (!is_string($typ) || strtolower($typ) !== 'dpop+jwt') {
            throw new AuthError("DPoP proof typ header must be 'dpop+jwt'");
        }

        // Check 3 (first half) — the header carries a public jwk.
        $jwk = $header['jwk'] ?? null;
        if (!is_array($jwk)) {
            throw new AuthError("DPoP proof header must carry a public 'jwk'");
        }

        // Check 4 — no private material, tested against the RAW header JSON, because
        // many JWK libraries quietly drop d/p/q when parsing into a public-key type —
        // the check would then pass by virtue of the library having hidden the
        // evidence.
        foreach (self::PRIVATE_JWK_MEMBERS as $member) {
            if (array_key_exists($member, $jwk)) {
                throw new AuthError(
                    "DPoP proof jwk carries private key material ({$member}) — RFC 9449 §4.3"
                );
            }
        }

        // Check 2 — algorithm from the key, never from the header.
        $alg = self::expectedAlg($jwk);

        // Check 3 (second half) — the signature verifies under that key.
        try {
            /** @var array<string,mixed> $jwk */
            $key = JWK::parseKey($jwk, $alg);
        } catch (\Throwable $e) {
            throw new AuthError('DPoP proof jwk is not a usable public key: ' . $e->getMessage());
        }
        if ($key === null) {
            throw new AuthError('DPoP proof jwk is not a usable public key');
        }

        try {
            $claims = (array) JWT::decode($proof, $key);
        } catch (BeforeValidException $e) {
            // firebase/php-jwt rejects a FUTURE iat before this class reaches check 7.
            // Re-shaped here so freshness always reports as freshness, in one voice,
            // whichever layer noticed it.
            throw new AuthError(
                'DPoP proof iat is outside the ' . $request->leewaySeconds . 's freshness window'
            );
        } catch (\Throwable $e) {
            throw new AuthError('DPoP proof signature or claims are invalid: ' . $e->getMessage());
        }

        // Check 5 — htm.
        $htm = $claims['htm'] ?? null;
        if (!is_string($htm) || $htm !== $request->httpMethod) {
            throw new AuthError('DPoP proof htm does not match the request method');
        }

        // Check 6 — htu, with query and fragment stripped from BOTH sides and nothing
        // else touched.
        $htu = $claims['htu'] ?? null;
        $expectedHtu = self::canonicalHtu($request->httpUri);
        if (!is_string($htu) || self::canonicalHtu($htu) !== $expectedHtu) {
            throw new AuthError('DPoP proof htu does not match the request URI');
        }

        // Check 7 — iat freshness, in both directions. A proof from the future is as
        // suspect as a stale one: it is how a one-sided skew allowance becomes a
        // long-lived proof.
        $iat = $claims['iat'] ?? null;
        if (!is_int($iat) && !is_float($iat)) {
            throw new AuthError('DPoP proof iat must be a number');
        }
        $now = $request->nowUnix ?? time();
        if (abs($now - (int) $iat) > $request->leewaySeconds) {
            throw new AuthError(
                'DPoP proof iat is outside the ' . $request->leewaySeconds . 's freshness window'
            );
        }

        // Check 9 — ath ties the proof to this specific access token.
        $ath = $claims['ath'] ?? null;
        if (!is_string($ath) || $ath === '') {
            throw new AuthError('DPoP proof is missing the ath claim');
        }
        if (!hash_equals(self::accessTokenHash($request->accessToken), $ath)) {
            throw new AuthError('DPoP proof ath does not match the presented access token');
        }

        // Check 10 — the thumbprint that ties the proof to the token's cnf.
        $jkt = self::thumbprintS256($jwk);
        if ($request->expectedJkt !== null && !hash_equals($request->expectedJkt, $jkt)) {
            throw new AuthError("DPoP proof key does not match the token's cnf.jkt");
        }

        // Check 8 — jti single-use. LAST on purpose: claiming a jti is a mutation, and
        // doing it before the cheap checks would let an attacker burn arbitrary jti
        // values out of the store with proofs that were never going to verify.
        $jti = $claims['jti'] ?? null;
        if (!is_string($jti) || $jti === '') {
            throw new AuthError('DPoP proof is missing a non-empty jti');
        }
        if (!$store->claim($jti, (int) $iat + $request->leewaySeconds)) {
            throw new AuthError('DPoP proof jti has already been used (replay)');
        }

        return $jkt;
    }

    /**
     * Compute the RFC 7638 SHA-256 thumbprint of a JWK — the `jkt`.
     *
     * Only the members RFC 7638 names for the key type take part, serialised as
     * compact JSON with lexicographically ordered keys. Members outside that set
     * (`kid`, `use`, `alg`, `x5c`) are excluded by the spec, which is what makes the
     * thumbprint stable across two encodings of the same key.
     *
     * @param array<string,mixed> $jwk The public key to fingerprint.
     *
     * @throws AuthError If the key type is unsupported or a required member is missing.
     *
     * @return string The 43-character base64url thumbprint.
     */
    public static function thumbprintS256(array $jwk): string
    {
        $get = static function (string $member) use ($jwk): string {
            $value = $jwk[$member] ?? null;
            if (!is_string($value) || $value === '') {
                throw new AuthError("DPoP proof jwk is missing the required member '{$member}'");
            }

            return $value;
        };

        // Built by hand rather than through json_encode of a map, so RFC 7638's member
        // set and their ordering are visible where they are required rather than
        // depending on PHP's array-ordering behaviour.
        $kty = $jwk['kty'] ?? null;
        $canonical = match ($kty) {
            'RSA' => sprintf(
                '{"e":%s,"kty":"RSA","n":%s}',
                json_encode($get('e')),
                json_encode($get('n'))
            ),
            'EC' => sprintf(
                '{"crv":%s,"kty":"EC","x":%s,"y":%s}',
                json_encode($get('crv')),
                json_encode($get('x')),
                json_encode($get('y'))
            ),
            'OKP' => sprintf(
                '{"crv":%s,"kty":"OKP","x":%s}',
                json_encode($get('crv')),
                json_encode($get('x'))
            ),
            default => throw new AuthError('DPoP proof jwk has an unsupported kty'),
        };

        return self::base64UrlEncode(hash('sha256', $canonical, true));
    }

    /**
     * Compute the `ath` claim value for an access token — RFC 9449 §4.2.
     *
     * base64url-unpadded SHA-256 over the token's bytes exactly as they travelled in
     * the `Authorization` header, not over anything decoded out of them.
     *
     * @param string $accessToken The token as it arrived.
     *
     * @return string The 43-character base64url hash.
     */
    public static function accessTokenHash(string $accessToken): string
    {
        return self::base64UrlEncode(hash('sha256', $accessToken, true));
    }

    /**
     * Reduce a URI to its `htu` comparison form — §21.7.2 check 6.
     *
     * Query and fragment removed, and **nothing else**. No case folding, no
     * default-port elision, no percent-decoding, no trailing-slash fixing: a
     * normalising comparison is precisely where two unequal URIs become equal, and an
     * attacker who finds such a pair can aim a proof at an endpoint it was never
     * minted for.
     *
     * @param string $uri The URI to reduce.
     *
     * @return string The same URI without its query string or fragment.
     */
    public static function canonicalHtu(string $uri): string
    {
        $withoutFragment = explode('#', $uri, 2)[0];

        return explode('?', $withoutFragment, 2)[0];
    }

    /**
     * §21.7.2 check 2 — derive the algorithm from the key itself.
     *
     * This is why the proof header's `alg` never selects anything: the key's own type
     * determines how a signature over it can be checked, and that is not a matter the
     * presenter gets an opinion on.
     *
     * @param array<string,mixed> $jwk The embedded public key.
     *
     * @throws AuthError If the key type is outside the three permitted algorithms.
     *
     * @return string The JWS algorithm name.
     */
    private static function expectedAlg(array $jwk): string
    {
        $kty = $jwk['kty'] ?? null;
        $crv = $jwk['crv'] ?? null;

        if ($kty === 'RSA') {
            return 'PS256';
        }
        if ($kty === 'EC' && $crv === 'P-256') {
            return 'ES256';
        }
        if ($kty === 'OKP' && $crv === 'Ed25519') {
            return 'EdDSA';
        }

        throw new AuthError(
            'DPoP proof key type is not permitted by CONTRACT.md §21.7.2 '
            . '(permitted: ES256, EdDSA, PS256)'
        );
    }

    /**
     * Decode the proof's header as raw JSON, for check 4.
     *
     * @param string $proof The compact JWS.
     *
     * @throws AuthError If the proof is not a three-segment JWS with a JSON header.
     *
     * @return array<string,mixed> The decoded header.
     */
    private static function rawHeader(string $proof): array
    {
        $segments = explode('.', $proof);
        if (count($segments) !== 3) {
            throw new AuthError('DPoP proof is not a compact JWS with three segments');
        }

        $decoded = self::base64UrlDecode($segments[0]);
        if ($decoded === false) {
            throw new AuthError('DPoP proof header is not valid base64url');
        }

        $header = json_decode($decoded, true);
        if (!is_array($header)) {
            throw new AuthError('DPoP proof header is not a JSON object');
        }

        /** @var array<string,mixed> $header */
        return $header;
    }

    /**
     * Encode bytes as unpadded base64url (RFC 7515 §2).
     *
     * @param string $raw The bytes to encode.
     *
     * @return string The unpadded base64url text.
     */
    private static function base64UrlEncode(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * Decode unpadded base64url text.
     *
     * @param string $text The base64url text.
     *
     * @return string|false The decoded bytes, or false when the input is not base64url.
     */
    private static function base64UrlDecode(string $text): string|false
    {
        $padded = str_pad($text, (int) (ceil(strlen($text) / 4) * 4), '=', STR_PAD_RIGHT);

        return base64_decode(strtr($padded, '-_', '+/'), true);
    }
}
