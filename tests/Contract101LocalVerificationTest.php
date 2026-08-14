<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Auth\JwksVerifier;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * CONTRACT.md §10.1 "Minimum local-verification set (normative)" — the complete required
 * negative-test set for {@see JwksVerifier::verify()}, the single local-verification
 * implementation every §10 guard in this SDK routes through.
 *
 * This suite exists because `SEC-071` and `SEC-080` were the SAME defect found
 * independently in two SDKs: each verified a different SUBSET of the token, and each
 * subset looked complete in isolation. Coverage of one rule proves nothing about the
 * others, so all seven are asserted here together against the committed real Ed25519
 * keypair and JWKS fixtures.
 *
 * Several cases below are specifically the places `firebase/php-jwt` does NOT cover:
 * `JWT::decode()` validates `exp` only when the claim is present, accepts a quoted
 * numeric `exp` via `is_numeric()`, and exposes `JWT::$leeway` as a publicly mutable
 * unbounded static.
 */
final class Contract101LocalVerificationTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/Fixtures';
    private const TENANT = 'acme-tenant';

    /** @return array<string,mixed> */
    private function jwks(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_jwks.json'), true);
        self::assertIsArray($decoded);

        return $decoded;
    }

    /** @return array{0:string,1:string} [raw 64-byte secret key, kid]. */
    private function keypair(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_keypair.json'), true);
        self::assertIsArray($decoded);

        return [(string) base64_decode(strtr($decoded['secret_key_b64url'], '-_', '+/'), true), $decoded['kid']];
    }

    /**
     * Builds a verifier whose transport serves exactly one discovery + one JWKS
     * response. An empty queue makes any attempted key lookup blow up loudly ("Mock
     * queue is empty") instead of silently returning null — which is how the rule-1
     * tests below prove the alg pin runs BEFORE any fetch.
     *
     * @param list<Response> $queue
     */
    private function verifier(array $queue, ?string $issuer = null, ?string $audience = null): JwksVerifier
    {
        $client = new Client(['handler' => HandlerStack::create(new MockHandler($queue))]);

        return new JwksVerifier($client, 'https://api.test', 300, $issuer, $audience);
    }

    /** @return list<Response> */
    private function servedKeys(): array
    {
        return [
            new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks'])),
            new Response(200, [], (string) json_encode($this->jwks())),
        ];
    }

    /**
     * Signs an ARBITRARY claims payload with the committed fixture key — the shape
     * needed to express "no exp at all", "exp is a string", and the rest.
     *
     * @param array<string,mixed> $claims
     */
    private function sign(array $claims, string $alg = 'EdDSA'): string
    {
        [$secretKey, $kid] = $this->keypair();
        $key = $alg === 'EdDSA' ? base64_encode($secretKey) : 'attacker-chosen-hmac-secret-at-least-32-bytes-long';

        return JWT::encode($claims, $key, $alg, $kid);
    }

    /**
     * Signs a payload with ext-sodium directly, bypassing `JWT::encode()`'s own claim
     * validation — the only way to mint a token whose `exp` is genuinely non-numeric,
     * since `JWT::encode()` refuses to produce one.
     *
     * @param array<string,mixed> $claims
     */
    private function signRaw(array $claims): string
    {
        [$secretKey, $kid] = $this->keypair();
        $header = $this->base64url((string) json_encode(['typ' => 'JWT', 'alg' => 'EdDSA', 'kid' => $kid]));
        $payload = $this->base64url((string) json_encode($claims));
        $signature = sodium_crypto_sign_detached("{$header}.{$payload}", $secretKey);

        return "{$header}.{$payload}." . $this->base64url($signature);
    }

    private function base64url(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    /** @return array<string,mixed> */
    private function validClaims(): array
    {
        return ['sub' => 'user-1', 'tenant_id' => self::TENANT, 'exp' => time() + 900];
    }

    // --- Rule 1: signature, alg pinned to EdDSA BEFORE key lookup -------------------

    public function testRule1AlgNoneIsRejectedWithoutAnyKeyLookup(): void
    {
        [, $kid] = $this->keypair();
        $header = $this->base64url((string) json_encode(['alg' => 'none', 'typ' => 'JWT', 'kid' => $kid]));
        $payload = $this->base64url((string) json_encode($this->validClaims()));

        // Empty queue: any key lookup would throw instead of returning null.
        self::assertNull($this->verifier([])->verify("{$header}.{$payload}.", self::TENANT));
    }

    public function testRule1Hs256TokenBearingAnEdDsaKidIsRejectedWithoutAnyKeyLookup(): void
    {
        // A REAL HMAC signature, under a kid the JWKS genuinely serves as an Ed25519
        // key — the classic algorithm-confusion attempt.
        $token = $this->sign($this->validClaims(), 'HS256');

        self::assertNull($this->verifier([])->verify($token, self::TENANT));
    }

    // --- Rule 2: exp is REQUIRED ---------------------------------------------------

    public function testRule2ExpiredTokenIsRejected(): void
    {
        // Beyond CLOCK_SKEW_LEEWAY_SECONDS, so the leeway cannot excuse it.
        $token = $this->sign(['sub' => 'user-1', 'tenant_id' => self::TENANT, 'exp' => time() - 7200]);

        self::assertNull($this->verifier($this->servedKeys())->verify($token, self::TENANT));
    }

    public function testRule2TokenWithNoExpClaimAtAllIsRejected(): void
    {
        // The SEC-080 defect verbatim, and the exact gap firebase/php-jwt leaves open:
        // its expiry gate is `isset($payload->exp) && ...`, so a token with no exp
        // sails straight through it. An absent exp is a PERMANENT credential.
        $token = $this->sign(['sub' => 'user-1', 'tenant_id' => self::TENANT]);

        self::assertNull($this->verifier($this->servedKeys())->verify($token, self::TENANT));
    }

    public function testRule2NonNumericExpIsRejected(): void
    {
        $token = $this->signRaw(['sub' => 'user-1', 'tenant_id' => self::TENANT, 'exp' => 'not-a-number']);

        self::assertNull($this->verifier($this->servedKeys())->verify($token, self::TENANT));
    }

    public function testRule2NumericStringExpIsRejected(): void
    {
        // A quoted "1700000000" is a JSON string, not an RFC 7519 NumericDate.
        // firebase/php-jwt's own is_numeric() guard would let this through.
        $token = $this->sign(['sub' => 'user-1', 'tenant_id' => self::TENANT, 'exp' => (string) (time() + 900)]);

        self::assertNull($this->verifier($this->servedKeys())->verify($token, self::TENANT));
    }

    public function testRule2NullExpIsRejected(): void
    {
        $token = $this->sign(['sub' => 'user-1', 'tenant_id' => self::TENANT, 'exp' => null]);

        self::assertNull($this->verifier($this->servedKeys())->verify($token, self::TENANT));
    }

    // --- Rule 3: nbf honoured when present, absent is valid ------------------------

    public function testRule3NbfInTheFutureIsRejected(): void
    {
        $token = $this->sign($this->validClaims() + ['nbf' => time() + 7200]);

        self::assertNull($this->verifier($this->servedKeys())->verify($token, self::TENANT));
    }

    public function testRule3NbfAlreadyPassedIsAccepted(): void
    {
        $token = $this->sign($this->validClaims() + ['nbf' => time() - 300]);

        self::assertIsArray($this->verifier($this->servedKeys())->verify($token, self::TENANT));
    }

    public function testRule3AbsentNbfIsAccepted(): void
    {
        $token = $this->sign($this->validClaims());

        self::assertIsArray($this->verifier($this->servedKeys())->verify($token, self::TENANT));
    }

    // --- Rule 4: tenant_id REQUIRED and asserted -----------------------------------

    public function testRule4TokenForADifferentTenantIsRejected(): void
    {
        $token = $this->sign(['sub' => 'user-1', 'tenant_id' => 'some-other-tenant', 'exp' => time() + 900]);

        self::assertNull($this->verifier($this->servedKeys())->verify($token, self::TENANT));
    }

    public function testRule4TokenWithNoTenantIdClaimIsRejected(): void
    {
        $token = $this->sign(['sub' => 'user-1', 'exp' => time() + 900]);

        self::assertNull($this->verifier($this->servedKeys())->verify($token, self::TENANT));
    }

    public function testRule4NoConfiguredTenantFailsClosed(): void
    {
        // A perfectly good token, and it must STILL be rejected: with nothing to assert
        // tenant_id against, the check would be vacuous — and a vacuous tenant check is
        // exactly how a token from another tenant gets in. Empty queue proves the
        // rejection happens before any network work at all.
        $token = $this->sign($this->validClaims());

        self::assertNull($this->verifier([])->verify($token, ''));
    }

    // --- Rule 5: iss checked only when configured ----------------------------------

    public function testRule5UnconfiguredIssuerIsNotChecked(): void
    {
        $token = $this->sign($this->validClaims() + ['iss' => 'https://whoever.example.com']);

        self::assertIsArray($this->verifier($this->servedKeys())->verify($token, self::TENANT));
    }

    public function testRule5ConfiguredIssuerMatchingIsAccepted(): void
    {
        $token = $this->sign($this->validClaims() + ['iss' => 'https://axiam.example.com']);
        $verifier = $this->verifier($this->servedKeys(), 'https://axiam.example.com');

        self::assertIsArray($verifier->verify($token, self::TENANT));
    }

    public function testRule5ConfiguredIssuerMismatchIsRejected(): void
    {
        $token = $this->sign($this->validClaims() + ['iss' => 'https://evil.example.com']);
        $verifier = $this->verifier($this->servedKeys(), 'https://axiam.example.com');

        self::assertNull($verifier->verify($token, self::TENANT));
    }

    public function testRule5ConfiguredIssuerButTokenHasNoIssFailsClosed(): void
    {
        $token = $this->sign($this->validClaims());
        $verifier = $this->verifier($this->servedKeys(), 'https://axiam.example.com');

        self::assertNull($verifier->verify($token, self::TENANT));
    }

    // --- Rule 6: aud checked only when configured ----------------------------------

    public function testRule6UnconfiguredAudienceIsNotChecked(): void
    {
        $token = $this->sign($this->validClaims() + ['aud' => 'someone-elses-api']);

        self::assertIsArray($this->verifier($this->servedKeys())->verify($token, self::TENANT));
    }

    public function testRule6ConfiguredAudienceSingleStringMatchIsAccepted(): void
    {
        $token = $this->sign($this->validClaims() + ['aud' => 'axiam:user']);
        $verifier = $this->verifier($this->servedKeys(), null, 'axiam:user');

        self::assertIsArray($verifier->verify($token, self::TENANT));
    }

    public function testRule6ConfiguredAudienceArrayContainingMatchIsAccepted(): void
    {
        $token = $this->sign($this->validClaims() + ['aud' => ['some-other-api', 'axiam:user']]);
        $verifier = $this->verifier($this->servedKeys(), null, 'axiam:user');

        self::assertIsArray($verifier->verify($token, self::TENANT));
    }

    public function testRule6ConfiguredAudienceMismatchIsRejected(): void
    {
        $token = $this->sign($this->validClaims() + ['aud' => ['axiam:service']]);
        $verifier = $this->verifier($this->servedKeys(), null, 'axiam:user');

        self::assertNull($verifier->verify($token, self::TENANT));
    }

    public function testRule6ConfiguredAudienceButTokenHasNoAudFailsClosed(): void
    {
        $token = $this->sign($this->validClaims());
        $verifier = $this->verifier($this->servedKeys(), null, 'axiam:user');

        self::assertNull($verifier->verify($token, self::TENANT));
    }

    // --- Rule 7: named, bounded clock skew -----------------------------------------

    public function testRule7ClockSkewLeewayIsTheRecommended60Seconds(): void
    {
        self::assertSame(60, JwksVerifier::CLOCK_SKEW_LEEWAY_SECONDS);
    }

    public function testRule7NbfWithinTheNamedSkewIsTolerated(): void
    {
        $token = $this->sign($this->validClaims() + ['nbf' => time() + 30]);

        self::assertIsArray($this->verifier($this->servedKeys())->verify($token, self::TENANT));
    }

    public function testRule7ExpJustPastWithinTheNamedSkewIsTolerated(): void
    {
        $token = $this->sign(['sub' => 'user-1', 'tenant_id' => self::TENANT, 'exp' => time() - 30]);

        self::assertIsArray($this->verifier($this->servedKeys())->verify($token, self::TENANT));
    }

    public function testRule7GlobalJwtLeewayCannotWidenTheWindow(): void
    {
        // firebase/php-jwt's JWT::$leeway is a public mutable static any code in the
        // process can set. §10.1 rule 7 forbids an operator-configurable unbounded
        // skew, so this verifier pins it to its own constant for the duration of each
        // decode. A token expired well beyond the 60 s leeway must stay rejected even
        // with a huge global leeway set, and the global value must be restored after.
        $original = JWT::$leeway;
        JWT::$leeway = 86400;
        try {
            $token = $this->sign(['sub' => 'user-1', 'tenant_id' => self::TENANT, 'exp' => time() - 7200]);

            self::assertNull($this->verifier($this->servedKeys())->verify($token, self::TENANT));
            self::assertSame(86400, JWT::$leeway, 'the global leeway must be restored after the decode');
        } finally {
            JWT::$leeway = $original;
        }
    }

    // --- Rule 9: sender-constrained (certificate-bound) access tokens ---------------
    //
    // CONTRACT.md §10.1 rule 9 (contract 1.15, RFC 8705 §3 / RFC 7800). A token carrying
    // `cnf` is not a bearer token and must not be accepted as one.
    //
    // Three negatives and one positive. The POSITIVE is the one that matters most: rule 9
    // must not become "every caller must present a certificate", which would break every
    // deployment that does not use mTLS at all.

    /** A real 43-character base64url x5t#S256, and a different one. */
    private const THUMBPRINT = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
    private const OTHER_THUMBPRINT = 'bWluZS1ub3QteW91cnMtdGhpcy1pcy00My1jaGFyc18';

    /** The regression test that keeps rule 9 from becoming a certificate mandate. */
    public function testRule9UnboundTokenIsAcceptedWithOrWithoutACertificate(): void
    {
        $unbound = $this->validClaims();
        self::assertTrue(JwksVerifier::verifyCertificateBinding($unbound, null));
        self::assertTrue(JwksVerifier::verifyCertificateBinding($unbound, self::THUMBPRINT));
    }

    public function testRule9BoundTokenIsAcceptedWithItsOwnCertificate(): void
    {
        $bound = $this->validClaims() + ['cnf' => ['x5t#S256' => self::THUMBPRINT]];
        self::assertTrue(JwksVerifier::verifyCertificateBinding($bound, self::THUMBPRINT));
    }

    public function testRule9BoundTokenIsRejectedWithNoCertificate(): void
    {
        $bound = $this->validClaims() + ['cnf' => ['x5t#S256' => self::THUMBPRINT]];
        self::assertFalse(JwksVerifier::verifyCertificateBinding($bound, null));
        self::assertFalse(JwksVerifier::verifyCertificateBinding($bound, ''));
    }

    public function testRule9BoundTokenIsRejectedWithADifferentCertificate(): void
    {
        $bound = $this->validClaims() + ['cnf' => ['x5t#S256' => self::THUMBPRINT]];
        self::assertFalse(JwksVerifier::verifyCertificateBinding($bound, self::OTHER_THUMBPRINT));
    }

    /**
     * The subtle one. A `cnf` naming a confirmation method this SDK cannot check is an
     * unverifiable constraint, never *no* constraint — read the other way, a
     * sender-constrained token silently degrades to a bearer token the day a newer AXIAM
     * issues a confirmation this SDK predates.
     */
    public function testRule9UnverifiableConfirmationIsRejectedNotIgnored(): void
    {
        $dpopish = $this->validClaims()
            + ['cnf' => ['jkt' => '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I']];
        self::assertFalse(JwksVerifier::verifyCertificateBinding($dpopish, null));
        self::assertFalse(JwksVerifier::verifyCertificateBinding($dpopish, self::THUMBPRINT));
    }

    /**
     * `verify()` deliberately does not apply rule 9 — it has no transport to ask for a
     * peer certificate. Asserted so the split cannot be collapsed by accident: a resource
     * server accepting bound tokens must call `verifyCertificateBinding()` as well.
     */
    public function testRule9VerifyDoesNotApplyItButCarriesTheClaimThrough(): void
    {
        $token = $this->sign($this->validClaims() + ['cnf' => ['x5t#S256' => self::THUMBPRINT]]);
        $claims = $this->verifier($this->servedKeys())->verify($token, self::TENANT);

        self::assertIsArray($claims);
        // Nested objects come back as stdClass from firebase/php-jwt — asserting
        // the real shape here is the point, since an implementation that only
        // handles arrays rejects every bound token.
        self::assertInstanceOf(\stdClass::class, $claims['cnf']);
        self::assertSame(self::THUMBPRINT, $claims['cnf']->{'x5t#S256'});
        self::assertTrue(JwksVerifier::verifyCertificateBinding($claims, self::THUMBPRINT));
        self::assertFalse(JwksVerifier::verifyCertificateBinding($claims, null));
    }

    /**
     * The shape regression. `verify()` returns nested claims as `stdClass`, so a
     * rule-9 implementation that only accepts `array` rejects every legitimately
     * bound token — rule 9 inverted into a denial-of-service on exactly the
     * clients the operator went to the trouble of binding.
     */
    public function testRule9AcceptsTheStdClassShapeVerifyActuallyReturns(): void
    {
        $cnf = new \stdClass();
        $cnf->{'x5t#S256'} = self::THUMBPRINT;
        $claims = $this->validClaims() + ['cnf' => $cnf];

        self::assertTrue(JwksVerifier::verifyCertificateBinding($claims, self::THUMBPRINT));
        self::assertFalse(JwksVerifier::verifyCertificateBinding($claims, self::OTHER_THUMBPRINT));
        self::assertFalse(JwksVerifier::verifyCertificateBinding($claims, null));
    }

    /**
     * RFC 7515 §2 base64url: unpadded, `-`/`_` rather than `+`/`/`. A padded or
     * standard-base64 value will not compare equal to what AXIAM put in the token.
     */
    public function testRule9ThumbprintHelperProducesUnpaddedBase64Url(): void
    {
        $der = str_repeat("\x42", 512);
        $tp = JwksVerifier::certificateThumbprintS256($der);

        self::assertSame(43, strlen($tp));
        self::assertStringNotContainsString('=', $tp);
        self::assertStringNotContainsString('+', $tp);
        self::assertStringNotContainsString('/', $tp);
        self::assertSame($tp, JwksVerifier::certificateThumbprintS256($der));
    }
}
