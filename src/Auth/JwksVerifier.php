<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AxiamException;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Local EdDSA/Ed25519 JWKS verification (CONTRACT.md D-08).
 *
 * Keys are sourced via OIDC discovery (`GET /.well-known/openid-configuration` ->
 * `jwks_uri`, falling back to `{baseUrl}/oauth2/jwks` if discovery is unavailable or
 * omits `jwks_uri`), TTL-cached, and refetched exactly once when an unknown `kid` is
 * encountered before failing closed.
 *
 * {@see self::verify()} applies the COMPLETE CONTRACT.md §10.1 "minimum
 * local-verification set", every rule of which fails closed:
 *
 *  1. **signature** — Pitfall 5 / T-alg-confusion: the header `alg` is pinned to
 *     `EdDSA` BEFORE any key lookup is attempted, so `alg: none` and HS-family
 *     confusion are rejected without ever consulting a key. A token never gets to
 *     choose its own verification algorithm.
 *  2. **`exp` — REQUIRED.** A token with no `exp`, or an `exp` that is not a JSON
 *     number, is rejected. An absent `exp` is a *permanent credential*, never "no
 *     expiry constraint" — treating it as the latter is the `SEC-080` defect.
 *  3. **`nbf`** — honoured when present; an `nbf` in the future is rejected. An absent
 *     `nbf` is valid.
 *  4. **`tenant_id` — REQUIRED and asserted.** Pitfall 3 / T-cross-tenant:
 *     `GET /oauth2/jwks` is organization-wide, not tenant-scoped, so a validly-signed
 *     token for a different tenant under the same organization must still be rejected.
 *     The claim is checked AFTER signature verification succeeds; an absent claim, or
 *     an empty expected tenant, fails closed.
 *  5. **`iss`** — checked only when this verifier was constructed with an expected
 *     issuer. Unset by default.
 *  6. **`aud`** — checked only when this verifier was constructed with an expected
 *     audience. Unset by default; both RFC 7519 shapes (single string, array) honoured.
 *  7. **clock skew** — {@see self::CLOCK_SKEW_LEEWAY_SECONDS}, a named 60-second
 *     constant applied to rules 2 and 3, deliberately not operator-configurable.
 *
 * What `firebase/php-jwt` does versus what §10.1 requires: `JWT::decode()` validates
 * `nbf`/`iat`/`exp` and rejects a non-numeric `exp` — but ONLY when the claim is
 * present (`isset($payload->exp) && ...`). A token with **no** `exp` at all sails
 * straight through it, which is precisely the `SEC-080` gap. Its `is_numeric()` test
 * also accepts a quoted `"1700000000"`, which is a JSON string, not an RFC 7519
 * NumericDate. And its `JWT::$leeway` is a public mutable static that any code in the
 * process can set to an unbounded value, which §10.1 rule 7 forbids. This class
 * therefore enforces rules 2, 3 and 7 itself rather than inheriting the library's
 * behaviour, and pins `JWT::$leeway` to its own named constant for the duration of each
 * decode so a global override cannot widen the window.
 *
 * Deliberately does NOT use firebase/php-jwt's `CachedKeySet` convenience class — it
 * requires a PSR-18 client + PSR-17 request factory + PSR-6 cache pool, a dependency
 * chain D-07 explicitly avoids. This hand-rolled TTL cache mirrors every sibling SDK's
 * own JWKS-cache shape (e.g. the Python SDK's `_jwks.py`).
 *
 * `verify()` never throws on attacker-controlled token input — malformed/short/
 * non-3-part tokens, unknown algorithms, unknown kids, bad signatures, and every §10.1
 * claim-policy failure all return `null` (fail closed). The only thrown exception is
 * the `ext-sodium`-missing guard, which is an environment/deployment misconfiguration,
 * not attacker input.
 */
final class JwksVerifier
{
    /**
     * The single, named, bounded clock-skew allowance applied to the `exp` and `nbf`
     * checks (CONTRACT.md §10.1 rule 7 — RECOMMENDED 60 s).
     *
     * Deliberately a class constant and not a constructor parameter: §10.1 requires the
     * leeway be "a named constant, not an inline literal" and forbids it being
     * "operator-configurable to an unbounded value". Exposing it as a knob is the exact
     * failure mode the rule exists to prevent — and `firebase/php-jwt`'s own public
     * mutable `JWT::$leeway` static is that knob, which is why this class pins it for
     * the duration of every decode instead of trusting whatever the process has set.
     */
    public const CLOCK_SKEW_LEEWAY_SECONDS = 60;

    /** @var array<string,\Firebase\JWT\Key>|null */
    private ?array $keysByKid = null;

    private int $fetchedAt = 0;

    /**
     * Guzzle-promise-based single-flight guard (D-08/D-09, RESEARCH Pitfall 6):
     * concurrent `verify()`-triggered refetches within ONE process/coroutine
     * await this SAME in-flight promise instead of each independently issuing
     * their own discovery+JWKS request. Reset to `null` once the shared fetch
     * settles (success or failure), so the next cache-miss burst starts exactly
     * one new fetch.
     *
     * Classic-FPM vacuity (RESEARCH Pitfall 6): this guard is only observable
     * via Guzzle's async interface (`sendAsync`/`requestAsync` +
     * `Promise\Utils::settle`) or a long-running coroutine runtime
     * (Swoole/RoadRunner) — see {@see JwksSingleFlightTest}. Under classic
     * synchronous PHP-FPM, each HTTP request is served by its own worker
     * PROCESS with no shared memory or event loop between processes, so there
     * is only ever one in-flight fetch per process by construction and no
     * possible race to coalesce. That is not a defect and is not "fixable"
     * without a cross-process shared cache — explicitly out of this phase's
     * scope (single-flight WITHIN one process, not cross-process caching).
     */
    private ?PromiseInterface $inFlightFetch = null;

    /**
     * @param string      $expectedIssuer   The `iss` value this verifier requires
     *                                      (CONTRACT.md §10.1 rule 5). CONDITIONAL:
     *                                      `null` (the default) means no issuer check
     *                                      is performed at all; once supplied, a token
     *                                      whose `iss` differs — or which carries no
     *                                      `iss` — is rejected. There is no default and
     *                                      no hardcoded AXIAM issuer.
     * @param string|null $expectedAudience The `aud` value this verifier requires
     *                                      (CONTRACT.md §10.1 rule 6). CONDITIONAL:
     *                                      `null` (the default) means no audience check
     *                                      at all; once supplied, a token whose `aud`
     *                                      does not contain it — including one with no
     *                                      `aud` at all — is rejected. A guard fronting
     *                                      a user-facing resource server should
     *                                      generally expect `axiam:user`.
     */
    public function __construct(
        private readonly ClientInterface $http,
        private readonly string $baseUrl,
        private readonly int $cacheTtlSeconds = 300,
        private readonly ?string $expectedIssuer = null,
        private readonly ?string $expectedAudience = null,
    ) {
    }

    /**
     * Verifies a token against the COMPLETE CONTRACT.md §10.1 minimum local-verification
     * set — see the class docblock for the seven rules and for what `firebase/php-jwt`
     * does versus what §10.1 requires.
     *
     * @param string $expectedTenantId The configured tenant the token's `tenant_id` must
     *                                 equal (§10.1 rule 4). An empty string fails closed:
     *                                 with nothing to compare against, the check would be
     *                                 vacuous, and a vacuous tenant check is how a token
     *                                 from another tenant gets in.
     *
     * @return array<string,mixed>|null Verified claims, or null on any verification
     *                                   failure (never throws on attacker input).
     */
    public function verify(string $jwt, string $expectedTenantId): ?array
    {
        if ($expectedTenantId === '') {
            // §10.1 rule 4: "no configured tenant to compare against MUST fail closed".
            return null;
        }

        if (!extension_loaded('sodium')) {
            // ext-sodium is compiled into PHP core by default since 7.2, but a small
            // subset of minimal/distroless builds compile --without-sodium. Fail with
            // a clear, actionable error rather than a cryptic "Call to undefined
            // function" fatal deep inside firebase/php-jwt's EdDSA branch.
            throw new AxiamException(
                'ext-sodium is required for EdDSA JWT verification but is not loaded'
            );
        }

        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            return null;
        }

        $header = $this->decodeHeader($parts[0]);
        if ($header === null || ($header['alg'] ?? null) !== 'EdDSA') {
            // Alg-pin BEFORE key lookup (Pitfall 5) — never trust the token to select
            // its own verifier, and never attempt a key lookup for a rejected alg.
            return null;
        }

        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '') {
            return null;
        }

        $this->ensureFresh($kid);
        if (!isset($this->keysByKid[$kid])) {
            return null; // unknown kid even after a forced refetch
        }

        // Pin firebase/php-jwt's public mutable $leeway static to OUR named, bounded
        // constant for the duration of this one decode, restoring it immediately after.
        // Left alone, any code in the process could set it to an unbounded value and
        // silently widen this SDK's exp/nbf window — exactly what §10.1 rule 7 forbids.
        $originalLeeway = JWT::$leeway;
        JWT::$leeway = self::CLOCK_SKEW_LEEWAY_SECONDS;
        try {
            $decoded = JWT::decode($jwt, $this->keysByKid);
        } catch (\Throwable) {
            return null;
        } finally {
            JWT::$leeway = $originalLeeway;
        }
        $claims = (array) $decoded;

        return $this->applyClaimPolicy($claims, $expectedTenantId) ? $claims : null;
    }

    /**
     * Applies CONTRACT.md §10.1 rules 2–6 to already signature-verified claims (rule 1
     * is the alg pin, enforced before any key lookup; rule 7's leeway is applied inside
     * this method and around the decode above).
     *
     * Every rule fails closed. A required claim that is absent, unparseable, or of the
     * wrong JSON type is a rejection; "the claim was missing so there was nothing to
     * check" is never treated as success. That conflation is precisely the `SEC-080`
     * defect this method exists to prevent — and it is why rules 2 and 3 are re-checked
     * here rather than left to `JWT::decode()`, whose own `exp` gate is conditional on
     * the claim being PRESENT.
     *
     * @param array<string,mixed> $claims
     *
     * @return bool True to accept; false to REJECT.
     */
    private function applyClaimPolicy(array $claims, string $expectedTenantId): bool
    {
        // Rule 4 — tenant_id: REQUIRED and asserted. The JWKS is organization-wide, not
        // tenant-scoped (Pitfall 3), so signature validity alone does NOT imply tenant
        // authorization. Checked strictly AFTER signature verification succeeds. The
        // empty-expectation case is already rejected by verify()'s guard clause.
        $tenantId = $claims['tenant_id'] ?? null;
        if (!is_string($tenantId) || $tenantId !== $expectedTenantId) {
            self::warnOnceIfTenantComparandLooksLikeASlug($tenantId, $expectedTenantId);

            return false;
        }

        $now = time();

        // Rule 2 — exp: REQUIRED. Absent, or present but not a JSON number, is a
        // rejection. An absent exp is a permanent credential, not an absent constraint.
        $exp = self::numericDate($claims['exp'] ?? null);
        if ($exp === null || ($now - self::CLOCK_SKEW_LEEWAY_SECONDS) >= $exp) {
            return false;
        }

        // Rule 3 — nbf: honoured when present, absent is valid. Present-but-malformed is
        // still a rejection (wrong JSON type => reject), which is why "absent" and
        // "unparseable" are distinguished here rather than collapsed.
        if (array_key_exists('nbf', $claims) && $claims['nbf'] !== null) {
            $nbf = self::numericDate($claims['nbf']);
            if ($nbf === null || $nbf > ($now + self::CLOCK_SKEW_LEEWAY_SECONDS)) {
                return false;
            }
        }

        // Rule 5 — iss: checked ONLY when an expected issuer was configured.
        if ($this->expectedIssuer !== null && ($claims['iss'] ?? null) !== $this->expectedIssuer) {
            return false;
        }

        // Rule 6 — aud: checked ONLY when an expected audience was configured. RFC 7519
        // §4.1.3 permits a single string or an array of strings; an absent aud can never
        // contain the expectation, so it fails closed with no special case.
        if ($this->expectedAudience !== null && !self::audienceContains($claims['aud'] ?? null, $this->expectedAudience)) {
            return false;
        }

        return true;
    }

    /** Guards {@see self::warnOnceIfTenantComparandLooksLikeASlug()} to one emission per process. */
    private static bool $tenantComparandWarningEmitted = false;

    /**
     * Deployment-footgun diagnostic (§13.4 observation 6). AXIAM access tokens always carry
     * the tenant **UUID** in `tenant_id`, but this SDK's client is configured with a tenant
     * **slug** (`tenant_slug` is what `login()` sends). An integrator who passes that same
     * slug to a guard gets a comparand that can never match, so the guard rejects 100% of
     * traffic — fail-closed and therefore not a vulnerability, but indistinguishable at the
     * call site from "the token was bad", which is a miserable thing to debug.
     *
     * Emits a single `E_USER_WARNING` naming the actual cause. Deliberately:
     *
     *  - **once per process** — so it is a configuration diagnostic, not a log-flood sink;
     *  - **keyed on the SHAPE of the configured value**, which is operator-controlled, not
     *    on anything an attacker supplies, so it cannot be triggered on demand;
     *  - **after the rejection is already decided** — this only ever explains a failure, it
     *    never influences one. The security behaviour is byte-for-byte unchanged.
     */
    private static function warnOnceIfTenantComparandLooksLikeASlug(mixed $claimed, string $expected): void
    {
        if (self::$tenantComparandWarningEmitted) {
            return;
        }

        // Only the specific confusable case: the token names a UUID tenant and the guard was
        // configured with something that is not a UUID at all. A UUID-vs-UUID mismatch is a
        // genuine cross-tenant rejection and must stay silent.
        if (!is_string($claimed) || !self::looksLikeUuid($claimed) || self::looksLikeUuid($expected)) {
            return;
        }

        self::$tenantComparandWarningEmitted = true;
        trigger_error(
            'AXIAM: the tenant this guard was configured with ("' . $expected . '") is not a UUID, '
            . 'but access tokens carry the tenant UUID in their `tenant_id` claim, so this guard '
            . 'will reject every request. Configure the guard with the tenant UUID, not the slug. '
            . '(CONTRACT.md §10.1 rule 4; this warning is emitted once per process and does not '
            . 'affect the rejection itself.)',
            E_USER_WARNING,
        );
    }

    /**
     * CONTRACT.md §10.1 **rule 9** — enforce a token's sender constraint against the
     * certificate the caller presented on **this** connection (RFC 8705 §3 / RFC 7800,
     * contract 1.15).
     *
     * A token carrying `cnf` is **not** a bearer token. Accepting one without proving the
     * caller holds the named key converts it straight back into one, discarding the whole
     * protection the operator turned on — which is why this is a rule and not a
     * recommendation.
     *
     * The four cases:
     *
     * | token's `cnf`            | `$presentedThumbprint`   | result  |
     * |--------------------------|--------------------------|---------|
     * | absent                   | anything                 | `true`  |
     * | `x5t#S256`               | equal                    | `true`  |
     * | `x5t#S256`               | different, or `null`     | `false` |
     * | present, no `x5t#S256`   | anything                 | `false` |
     *
     * The first row is why adopting this rule breaks nothing: an **unbound** token is
     * still accepted whether or not a certificate is present. Rule 9 constrains tokens
     * that claim a constraint; it does not make certificates mandatory.
     *
     * The last row is the one that is easy to get wrong. A `cnf` naming a confirmation
     * method this SDK cannot check — a DPoP `jkt`, say — is an *unverifiable constraint*,
     * never *no constraint*. Read the other way, a sender-constrained token silently
     * degrades to a bearer token the day a newer AXIAM issues a confirmation this SDK
     * predates.
     *
     * **The thumbprint must come from the transport.** Under PHP-FPM behind an mTLS
     * terminator that is typically `$_SERVER['SSL_CLIENT_CERT']` converted to DER and
     * fingerprinted with {@see self::certificateThumbprintS256()} — and only where that
     * variable is set by a proxy **you** control. Never from a caller-settable request
     * header: a forgeable input makes the whole mechanism decorative.
     *
     * Returns `bool` rather than throwing, matching {@see self::verify()}: this class
     * never throws on attacker input.
     *
     * @param array<string,mixed> $claims             Verified claims from {@see self::verify()}.
     * @param string|null         $presentedThumbprint RFC 8705 §3.1 `x5t#S256` of the peer
     *                                                 certificate, or null if none.
     */
    public static function verifyCertificateBinding(array $claims, ?string $presentedThumbprint): bool
    {
        $cnf = $claims['cnf'] ?? null;
        if ($cnf === null) {
            // An ordinary bearer token. Accepted with or without a certificate.
            return true;
        }
        if (!is_array($cnf)) {
            return false;
        }

        $expected = $cnf['x5t#S256'] ?? null;
        if (!is_string($expected) || $expected === '') {
            // A confirmation naming a method this SDK cannot verify. Fail closed.
            return false;
        }
        if ($presentedThumbprint === null || $presentedThumbprint === '') {
            return false;
        }

        // Constant-time. The thumbprint is usually public — it derives from a certificate
        // sent in the clear during the handshake — so this is defence in depth. It matters
        // most for a self-signed client, where the registered thumbprint is the whole
        // credential.
        return hash_equals($expected, $presentedThumbprint);
    }

    /**
     * Compute the RFC 8705 §3.1 `x5t#S256` thumbprint of a DER client certificate:
     * base64url-encoded SHA-256, **without** padding.
     *
     * Unpadded is not a style choice — RFC 7515 §2 defines base64url in JOSE as omitting
     * `=`, and a padded value will not compare equal to what AXIAM put in the token.
     *
     * @param string $der Raw DER bytes of the peer's leaf certificate. To convert a PEM
     *                    (what `SSL_CLIENT_CERT` carries), strip the armour and
     *                    base64-decode the body.
     */
    public static function certificateThumbprintS256(string $der): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $der, true)), '+/', '-_'), '=');
    }

    /** Canonical 8-4-4-4-12 hex form; shape only, no version/variant validation. */
    private static function looksLikeUuid(string $value): bool
    {
        return preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i', $value) === 1;
    }

    /**
     * Reads an RFC 7519 NumericDate ("A JSON numeric value"), returning null when the
     * claim is absent, JSON null, or of any type other than a number.
     *
     * A quoted `"1700000000"` is a JSON string, not a NumericDate, and is rejected
     * rather than coerced — note that `firebase/php-jwt`'s own `is_numeric()` guard
     * would accept it.
     *
     * `json_decode()` (used by php-jwt) maps a JSON number onto a PHP int or float and
     * nothing else, so an int|float test here is exactly a "was a JSON number" test.
     */
    private static function numericDate(mixed $value): ?int
    {
        if (!is_int($value) && !is_float($value)) {
            return null;
        }
        if (is_float($value) && (is_nan($value) || is_infinite($value))) {
            return null;
        }

        // RFC 7519 permits a non-integer NumericDate; truncate toward zero, the same
        // rounding every sibling SDK applies.
        return (int) $value;
    }

    /**
     * Whether an `aud` claim contains $expected, honouring both RFC 7519 shapes (a
     * single string, or an array of strings).
     */
    private static function audienceContains(mixed $aud, string $expected): bool
    {
        if (is_string($aud)) {
            return $aud === $expected;
        }
        if (is_array($aud)) {
            foreach ($aud as $entry) {
                if (is_string($entry) && $entry === $expected) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * §12.4 rules 1–2 (CONTRACT.md, OIDC/SSO relying-party helpers) — algorithm and
     * Ed25519 signature verification for an OIDC ID token, reusing this SAME verifier's
     * key cache and single-refetch-on-unknown-`kid` behavior (§12 forbids forking the
     * JWKS verifier the §10 middleware already uses).
     *
     * Deliberately distinct from {@see self::verify()}: an ID token carries no
     * `tenant_id` claim to check (that check is specific to AXIAM's own access tokens),
     * and §12.4 requires a stable machine-readable failure reason rather than a bare
     * `null`, so this method THROWS {@see AuthError} (with `invalid_alg`, `unknown_kid`,
     * or `invalid_signature` in {@see AuthError::getReason()}) instead of returning one.
     * Issuer/audience/time/nonce (§12.4 rules 3–6) are the caller's job —
     * {@see \Axiam\Sdk\Oidc\IdTokenValidator::checkClaims()} — since they need
     * expectations (issuer, client_id, nonce) this verifier has no reason to know about.
     *
     * @return array<string,mixed> Decoded claims — signature-verified, but NOT yet
     *                              issuer/audience/time/nonce-checked.
     */
    public function verifyIdTokenSignature(string $jwt): array
    {
        if (!extension_loaded('sodium')) {
            throw new AxiamException(
                'ext-sodium is required for EdDSA JWT verification but is not loaded'
            );
        }

        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new AuthError('id_token is not a well-formed JWT (expected 3 dot-separated segments)', 'invalid_signature');
        }

        $header = $this->decodeHeader($parts[0]);
        $alg = is_array($header) ? ($header['alg'] ?? null) : null;
        // §12.4 rule 1: the alg check is read from the header and enforced BEFORE any
        // key lookup — `none` is rejected by this SAME equality test as every other
        // non-EdDSA value, with no special case and no separate code path.
        if ($alg !== 'EdDSA') {
            throw new AuthError(
                sprintf('expected alg "EdDSA", got %s', is_string($alg) ? sprintf('"%s"', $alg) : 'no alg header'),
                'invalid_alg',
            );
        }

        $kid = is_array($header) ? ($header['kid'] ?? null) : null;
        if (!is_string($kid) || $kid === '') {
            // Port brief addendum item 12: "unknown_kid also covers 'no kid header at
            // all', not just 'no matching key'" — no re-fetch is useful here (there is no
            // kid value a fresh JWKS document could possibly satisfy), so this fails
            // immediately with the same reason code.
            throw new AuthError('id_token has no kid header', 'unknown_kid');
        }

        $this->ensureFresh($kid);
        if (!isset($this->keysByKid[$kid])) {
            throw new AuthError(sprintf('id_token kid "%s" is unknown, even after a JWKS refetch', $kid), 'unknown_kid');
        }

        // firebase/php-jwt's own JWT::decode() enforces exp/nbf/iat internally (via the
        // static $leeway it consults), throwing ExpiredException/BeforeValidException
        // BEFORE ever returning the claims. This method's job is ONLY §12.4 rules 1–2
        // (alg + signature) — time/issuer/audience/nonce (rules 3–6) are
        // IdTokenValidator::checkClaims()'s job, over the claims of a token that may be
        // signature-valid but time-invalid. A momentary, try/finally-scoped $leeway
        // override neutralizes firebase/php-jwt's own time gate for the duration of
        // this ONE decode call (restored immediately after, so it can never leak into
        // this class's own self::verify() call for AXIAM's own access tokens, nor into
        // any concurrent decode within the same process) so an expired-but-genuinely-
        // signed token still reaches IdTokenValidator and is correctly rejected with
        // `token_expired`, never misreported as `invalid_signature`.
        $originalLeeway = JWT::$leeway;
        JWT::$leeway = PHP_INT_MAX >> 2;
        try {
            $decoded = JWT::decode($jwt, $this->keysByKid);
        } catch (\Throwable $e) {
            throw new AuthError('id_token signature verification failed: ' . $e->getMessage(), 'invalid_signature');
        } finally {
            JWT::$leeway = $originalLeeway;
        }

        return (array) $decoded;
    }

    /** @return array<string,mixed>|null */
    private function decodeHeader(string $headerSegment): ?array
    {
        $decoded = base64_decode(strtr($headerSegment, '-_', '+/'), true);
        if ($decoded === false) {
            return null;
        }

        try {
            $header = json_decode($decoded, true, flags: JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return is_array($header) ? $header : null;
    }

    /**
     * Synchronous entry point used by {@see verify()} — waits on the same
     * in-flight guard {@see ensureFreshAsync()} builds, so a burst of
     * synchronous `verify()` calls sharing one event loop (e.g. Guzzle's
     * curl-multi-driven `wait()`) still only ever resolves ONE underlying
     * fetch (D-09).
     */
    private function ensureFresh(string $unknownKid): void
    {
        $this->ensureFreshAsync($unknownKid)->wait();
    }

    /**
     * Async in-flight guard (D-08): if the cache is already fresh, returns an
     * already-resolved promise with no HTTP call at all. If a fetch triggered
     * by a concurrent caller is already underway, returns that SAME promise
     * instead of issuing a second discovery+JWKS request. Otherwise starts
     * exactly one new fetch and stores it as the shared in-flight promise
     * until it settles.
     *
     * Exercised directly (bypassing `verify()`/`wait()`) by
     * {@see JwksSingleFlightTest} via `sendAsync`-style concurrency to prove
     * the guard is meaningful under Guzzle's async interface (RESEARCH
     * Pitfall 6) — never touches `firebase/php-jwt`'s verification call.
     */
    private function ensureFreshAsync(string $unknownKid): PromiseInterface
    {
        $expired = (time() - $this->fetchedAt) > $this->cacheTtlSeconds;
        $unknown = !isset($this->keysByKid[$unknownKid]);
        if ($this->keysByKid !== null && !$expired && !$unknown) {
            return Create::promiseFor(null);
        }

        if ($this->inFlightFetch !== null) {
            // A fetch triggered by a concurrent caller is already underway —
            // join it instead of issuing a new discovery+JWKS request.
            return $this->inFlightFetch;
        }

        $fetch = $this->resolveJwksUriAsync()
            ->then(fn (string $jwksUri): PromiseInterface => $this->http->requestAsync('GET', $jwksUri))
            ->then(function (ResponseInterface $response): void {
                $jwksJson = json_decode((string) $response->getBody(), true);
                if (is_array($jwksJson)) {
                    $this->keysByKid = JWK::parseKeySet($jwksJson);
                    $this->fetchedAt = time();
                }
            })
            ->otherwise(function (\Throwable $e): void {
                // Fetch/parse failure (network, JSON, or key-parse) — leave
                // the existing cache (if any) untouched; verify() will fail
                // closed on a still-unknown kid.
            });

        // Reset the guard once settled so the NEXT cache-miss burst starts a
        // fresh single-flight fetch rather than replaying this one forever.
        $this->inFlightFetch = $fetch->then(function (): void {
            // The upstream chain resolves to void, so there is no value to
            // propagate — just clear the single-flight guard. (Returning the
            // void $value tripped PHPStan's return.void under the promises v2
            // typing pulled in by guzzle ^8.0.)
            $this->inFlightFetch = null;
        });

        return $this->inFlightFetch;
    }

    /**
     * Resolve `jwks_uri` fresh via OIDC discovery (cheap, avoids a second
     * hardcoded path constant drifting from the server's actual
     * configuration), falling back to the conventional `/oauth2/jwks` path on
     * any discovery failure.
     */
    private function resolveJwksUriAsync(): PromiseInterface
    {
        return $this->http->requestAsync('GET', '/.well-known/openid-configuration')
            ->then(function (ResponseInterface $response): string {
                $discovery = json_decode((string) $response->getBody(), true);
                if (is_array($discovery)
                    && is_string($discovery['jwks_uri'] ?? null)
                    && $discovery['jwks_uri'] !== ''
                    && $this->isSameOriginHttps($discovery['jwks_uri'])
                ) {
                    return $discovery['jwks_uri'];
                }

                return $this->baseUrl . '/oauth2/jwks';
            })
            ->otherwise(fn (): string => $this->baseUrl . '/oauth2/jwks');
    }

    /**
     * Anti-key-substitution / anti-SSRF guard (SDK-19): the discovery document
     * is fetched over the network and its `jwks_uri` is fetched next, then its
     * keys are trusted to verify EdDSA signatures. If the discovery response is
     * attacker-influenced, an unvalidated `jwks_uri` would let an attacker point
     * key resolution at a host of their choosing (substituting their own signing
     * keys) or coerce the client into fetching an arbitrary internal URL (SSRF).
     *
     * We therefore only honour a discovered `jwks_uri` that is same-origin with
     * the configured `baseUrl`: it MUST be an absolute `https` URL whose host
     * (case-insensitive) and port match `baseUrl`'s. Anything else — a relative
     * path, a plaintext `http` URL, or an off-host absolute URL — is rejected by
     * the caller, which falls back to the conventional `{baseUrl}/oauth2/jwks`
     * (the path every sibling SDK hardcodes). This keeps key resolution pinned
     * to the trusted origin regardless of what discovery returns.
     */
    private function isSameOriginHttps(string $candidate): bool
    {
        $candidateParts = parse_url($candidate);
        $baseParts = parse_url($this->baseUrl);
        if (!is_array($candidateParts) || !is_array($baseParts)) {
            return false;
        }

        // Require an absolute https URL — a relative path (no scheme/host) or a
        // plaintext http URL never qualifies. Scheme comparison is
        // case-insensitive per RFC 3986 (`HTTPS` == `https`).
        $candidateScheme = $candidateParts['scheme'] ?? null;
        if (!is_string($candidateScheme) || strcasecmp($candidateScheme, 'https') !== 0) {
            return false;
        }

        $candidateHost = $candidateParts['host'] ?? null;
        $baseHost = $baseParts['host'] ?? null;
        if (!is_string($candidateHost) || !is_string($baseHost) || $baseHost === '') {
            return false;
        }

        // Same host (case-insensitive, mirroring SessionState::isBaseHost in the
        // sibling SDKs) AND same effective port — together with the https scheme
        // check above this is a same-origin comparison.
        if (strcasecmp($candidateHost, $baseHost) !== 0) {
            return false;
        }

        return ($candidateParts['port'] ?? null) === ($baseParts['port'] ?? null);
    }
}
