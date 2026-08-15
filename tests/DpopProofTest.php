<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Auth\DpopRequest;
use Axiam\Sdk\Auth\DpopVerifier;
use Axiam\Sdk\Auth\InMemoryJtiStore;
use Axiam\Sdk\Core\AuthError;
use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;

/**
 * CONTRACT.md §21.7.2 — DPoP proof verification, all ten checks.
 *
 * Each check gets a negative test, because §21.7.2's whole premise is that a verifier
 * missing one of them still reports success. A suite that only proved a good proof
 * passes would not distinguish this class from returning the thumbprint
 * unconditionally.
 */
final class DpopProofTest extends TestCase
{
    private const METHOD = 'POST';
    private const URI = 'https://rs.example.com/v1/things';
    private const TOKEN = 'eyJhbGciOiJFZERTQSJ9.e30.sig';

    private InMemoryJtiStore $store;

    /** @var array{0:string,1:array<string,string>} Raw secret key, public JWK. */
    private array $key;

    private static int $jtiSeq = 0;

    /**
     * Fresh store and keypair per test.
     */
    protected function setUp(): void
    {
        $this->store = new InMemoryJtiStore();
        $this->key = self::newKey();
    }

    /**
     * Generate an Ed25519 keypair as (raw secret key, public JWK).
     *
     * @return array{0:string,1:array<string,string>} The secret key and its public JWK.
     */
    private static function newKey(): array
    {
        $pair = sodium_crypto_sign_keypair();

        return [
            sodium_crypto_sign_secretkey($pair),
            [
                'kty' => 'OKP',
                'crv' => 'Ed25519',
                'x' => self::b64u(sodium_crypto_sign_publickey($pair)),
            ],
        ];
    }

    /**
     * Encode bytes as unpadded base64url.
     *
     * @param string $raw The bytes to encode.
     *
     * @return string The unpadded base64url text.
     */
    private static function b64u(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * Build the default proof claims, with overrides applied (null removes a claim).
     *
     * @param array<string,mixed> $overrides Claims to replace or remove.
     *
     * @return array<string,mixed> The claim set.
     */
    private static function claims(array $overrides = []): array
    {
        $claims = [
            'htm' => self::METHOD,
            'htu' => self::URI,
            'iat' => time(),
            'jti' => 'jti-' . (++self::$jtiSeq),
            'ath' => DpopVerifier::accessTokenHash(self::TOKEN),
        ];
        foreach ($overrides as $k => $v) {
            if ($v === null) {
                unset($claims[$k]);
            } else {
                $claims[$k] = $v;
            }
        }

        return $claims;
    }

    /**
     * Sign a proof by hand, so a test can put anything at all in the header —
     * including the private material and bogus `alg` values a cooperative library
     * would refuse to emit.
     *
     * @param string              $secretKey Raw Ed25519 secret key.
     * @param array<string,mixed> $header    The JOSE header.
     * @param array<string,mixed> $claims    The payload.
     *
     * @return string The compact JWS.
     */
    private static function sign(string $secretKey, array $header, array $claims): string
    {
        $input = self::b64u((string) json_encode($header))
            . '.' . self::b64u((string) json_encode($claims));

        return $input . '.' . self::b64u(sodium_crypto_sign_detached($input, $secretKey));
    }

    /**
     * The header for a well-formed proof, with overrides applied.
     *
     * @param array<string,mixed> $jwk       The public JWK to embed.
     * @param array<string,mixed> $overrides Header members to replace or remove.
     *
     * @return array<string,mixed> The JOSE header.
     */
    private static function header(array $jwk, array $overrides = []): array
    {
        $header = ['typ' => 'dpop+jwt', 'alg' => 'EdDSA', 'jwk' => $jwk];
        foreach ($overrides as $k => $v) {
            if ($v === null) {
                unset($header[$k]);
            } else {
                $header[$k] = $v;
            }
        }

        return $header;
    }

    /**
     * A well-formed proof for the current key.
     *
     * @return string The compact JWS.
     */
    private function goodProof(): string
    {
        return self::sign($this->key[0], self::header($this->key[1]), self::claims());
    }

    /**
     * The request every test verifies against.
     *
     * @return DpopRequest The default request.
     */
    private function request(): DpopRequest
    {
        return new DpopRequest(self::METHOD, self::URI, self::TOKEN);
    }

    // ---------------------------------------------------------------------
    // The happy path
    // ---------------------------------------------------------------------

    /**
     * A well-formed proof verifies and hands back its thumbprint — returning the
     * thumbprint rather than `true` is what lets a guard pass a value onward that
     * could only have come from a verified proof.
     */
    public function testWellFormedProofVerifiesAndReturnsThumbprint(): void
    {
        $jkt = DpopVerifier::verifyProof($this->goodProof(), $this->request(), $this->store);

        self::assertSame(DpopVerifier::thumbprintS256($this->key[1]), $jkt);
        self::assertSame(43, strlen($jkt));
    }

    /**
     * Query and fragment come off both sides of the `htu` comparison.
     */
    public function testQueryAndFragmentAreStrippedFromBothSides(): void
    {
        $request = new DpopRequest(self::METHOD, self::URI . '?page=2#frag', self::TOKEN);

        self::assertSame(
            DpopVerifier::thumbprintS256($this->key[1]),
            DpopVerifier::verifyProof($this->goodProof(), $request, $this->store)
        );
    }

    // ---------------------------------------------------------------------
    // One negative test per check
    // ---------------------------------------------------------------------

    /**
     * Check 1 — without pinning `typ`, any other JWT signed by the same key (an
     * access token, an ID token) is replayable as a proof.
     */
    public function testCheck1ProofWithoutDpopTypIsRefused(): void
    {
        $proof = self::sign(
            $this->key[0],
            self::header($this->key[1], ['typ' => 'JWT']),
            self::claims()
        );

        $this->expectException(AuthError::class);
        $this->expectExceptionMessageMatches('/typ/');
        DpopVerifier::verifyProof($proof, $this->request(), $this->store);
    }

    /**
     * Check 1 — the `typ` comparison is case-insensitive (RFC 9110 §11.1).
     */
    public function testCheck1TypComparisonIsCaseInsensitive(): void
    {
        $proof = self::sign(
            $this->key[0],
            self::header($this->key[1], ['typ' => 'DPoP+JWT']),
            self::claims()
        );

        self::assertNotSame('', DpopVerifier::verifyProof($proof, $this->request(), $this->store));
    }

    /**
     * Check 2 — the public-key-as-HMAC-secret forgery, run for real.
     *
     * The attacker holds no private key. They take the *public* key out of a proof
     * they observed, use its raw bytes as an HMAC secret, sign a proof of their own
     * with `HS256`, and embed the same public `jwk`. A verifier that reads `alg` from
     * the header computes HMAC with that public key, gets a match, and reports success
     * — the signature is valid, just not proof of anything.
     */
    public function testCheck2PublicKeyAsHmacSecretForgeryIsRefused(): void
    {
        $publicBytes = (string) base64_decode(strtr($this->key[1]['x'], '-_', '+/'), false);
        $forged = JWT::encode(
            self::claims(),
            $publicBytes,
            'HS256',
            null,
            ['typ' => 'dpop+jwt', 'jwk' => $this->key[1]]
        );

        $this->expectException(AuthError::class);
        DpopVerifier::verifyProof($forged, $this->request(), $this->store);
    }

    /**
     * Check 2 — a key type outside the three permitted algorithms is refused.
     */
    public function testCheck2UnpermittedKeyTypeIsRefused(): void
    {
        $proof = self::sign(
            $this->key[0],
            self::header($this->key[1], [
                'jwk' => ['kty' => 'EC', 'crv' => 'P-521', 'x' => 'AA', 'y' => 'AA'],
            ]),
            self::claims()
        );

        $this->expectException(AuthError::class);
        $this->expectExceptionMessageMatches('/not permitted/');
        DpopVerifier::verifyProof($proof, $this->request(), $this->store);
    }

    /**
     * Check 3 — a proof with no embedded `jwk` is refused.
     */
    public function testCheck3ProofWithNoJwkIsRefused(): void
    {
        $proof = self::sign(
            $this->key[0],
            self::header($this->key[1], ['jwk' => null]),
            self::claims()
        );

        $this->expectException(AuthError::class);
        $this->expectExceptionMessageMatches("/public 'jwk'/");
        DpopVerifier::verifyProof($proof, $this->request(), $this->store);
    }

    /**
     * Check 3 — a proof signed by a different key than the one it embeds is refused.
     */
    public function testCheck3ForeignSignatureIsRefused(): void
    {
        $other = self::newKey();
        $forged = self::sign($other[0], self::header($this->key[1]), self::claims());

        $this->expectException(AuthError::class);
        DpopVerifier::verifyProof($forged, $this->request(), $this->store);
    }

    /**
     * Check 4 — RFC 9449 §4.3 private key material, tested against the RAW header
     * JSON because many JWK libraries silently drop these members when parsing into a
     * public-key type; the check would then pass because the library hid the evidence.
     */
    public function testCheck4PrivateKeyMaterialIsRefused(): void
    {
        foreach (['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'] as $member) {
            $leaky = $this->key[1];
            $leaky[$member] = 'c2VjcmV0';
            $proof = self::sign(
                $this->key[0],
                self::header($this->key[1], ['jwk' => $leaky]),
                self::claims()
            );

            try {
                DpopVerifier::verifyProof($proof, $this->request(), $this->store);
                self::fail("member {$member} was not caught");
            } catch (AuthError $e) {
                self::assertStringContainsString('private key material', $e->getMessage());
            }
        }
    }

    /**
     * Check 5 — a proof minted for another HTTP method is refused.
     */
    public function testCheck5ProofForAnotherMethodIsRefused(): void
    {
        $proof = self::sign(
            $this->key[0],
            self::header($this->key[1]),
            self::claims(['htm' => 'GET'])
        );

        $this->expectException(AuthError::class);
        $this->expectExceptionMessageMatches('/htm/');
        DpopVerifier::verifyProof($proof, $this->request(), $this->store);
    }

    /**
     * Check 6 — a proof minted for another URI is refused.
     */
    public function testCheck6ProofForAnotherUriIsRefused(): void
    {
        $proof = self::sign(
            $this->key[0],
            self::header($this->key[1]),
            self::claims(['htu' => 'https://rs.example.com/v1/other'])
        );

        $this->expectException(AuthError::class);
        $this->expectExceptionMessageMatches('/htu/');
        DpopVerifier::verifyProof($proof, $this->request(), $this->store);
    }

    /**
     * Check 6 — `htu` is compared without normalisation. A normalising comparison is
     * where two unequal URIs become equal; only query and fragment come off, and case,
     * default ports and trailing slashes are left exactly as they are.
     */
    public function testCheck6HtuIsComparedWithoutNormalisation(): void
    {
        self::assertSame('https://a.example/p', DpopVerifier::canonicalHtu('https://a.example/p?q=1#f'));
        self::assertNotSame(
            DpopVerifier::canonicalHtu('https://A.example/P'),
            DpopVerifier::canonicalHtu('https://a.example/p')
        );
        self::assertNotSame(
            DpopVerifier::canonicalHtu('https://a.example:443/p'),
            DpopVerifier::canonicalHtu('https://a.example/p')
        );
        self::assertNotSame(
            DpopVerifier::canonicalHtu('https://a.example/p/'),
            DpopVerifier::canonicalHtu('https://a.example/p')
        );
    }

    /**
     * Check 7 — both directions. A proof from the future is as suspect as a stale one:
     * it is how a one-sided skew allowance becomes a long-lived proof.
     */
    public function testCheck7StaleOrFutureProofIsRefused(): void
    {
        $now = time();

        foreach ([-DpopVerifier::IAT_LEEWAY_SECONDS - 5, DpopVerifier::IAT_LEEWAY_SECONDS + 5] as $offset) {
            $proof = self::sign(
                $this->key[0],
                self::header($this->key[1]),
                self::claims(['iat' => $now + $offset])
            );
            $request = new DpopRequest(
                self::METHOD,
                self::URI,
                self::TOKEN,
                null,
                DpopVerifier::IAT_LEEWAY_SECONDS,
                $now
            );

            try {
                DpopVerifier::verifyProof($proof, $request, $this->store);
                self::fail("offset {$offset} was accepted");
            } catch (AuthError $e) {
                self::assertStringContainsString('freshness window', $e->getMessage());
            }
        }
    }

    /**
     * Check 8 — freshness bounds the window; the `jti` guard is what makes the window
     * unusable. Without this the same proof works repeatedly for a full minute.
     */
    public function testCheck8ReplayedProofIsRefused(): void
    {
        $proof = $this->goodProof();
        DpopVerifier::verifyProof($proof, $this->request(), $this->store);

        $this->expectException(AuthError::class);
        $this->expectExceptionMessageMatches('/replay/');
        DpopVerifier::verifyProof($proof, $this->request(), $this->store);
    }

    /**
     * Check 8 — the `jti` claim is a mutation, so it runs last. Claiming it earlier
     * would let an attacker burn arbitrary `jti` values out of the store using proofs
     * that were never going to verify, turning the replay guard into a
     * denial-of-service surface against legitimate proofs.
     */
    public function testCheck8JtiIsClaimedOnlyAfterEveryOtherCheckPasses(): void
    {
        $doomed = self::sign(
            $this->key[0],
            self::header($this->key[1]),
            self::claims(['htm' => 'GET', 'jti' => 'precious'])
        );

        try {
            DpopVerifier::verifyProof($doomed, $this->request(), $this->store);
            self::fail('the doomed proof was accepted');
        } catch (AuthError $e) {
            self::assertStringContainsString('htm', $e->getMessage());
        }

        self::assertTrue(
            $this->store->claim('precious', time() + 60),
            'a failed proof must not burn its jti'
        );
    }

    /**
     * Check 9 — without `ath`, a proof captured on one request can be re-aimed at a
     * different token held by the same key.
     */
    public function testCheck9ProofAimedAtAnotherTokenIsRefused(): void
    {
        $proof = self::sign(
            $this->key[0],
            self::header($this->key[1]),
            self::claims(['ath' => DpopVerifier::accessTokenHash('some.other.token')])
        );

        $this->expectException(AuthError::class);
        $this->expectExceptionMessageMatches('/ath/');
        DpopVerifier::verifyProof($proof, $this->request(), $this->store);
    }

    /**
     * Check 9 — a proof carrying no `ath` at all is refused.
     */
    public function testCheck9ProofWithNoAthIsRefused(): void
    {
        $proof = self::sign(
            $this->key[0],
            self::header($this->key[1]),
            self::claims(['ath' => null])
        );

        $this->expectException(AuthError::class);
        $this->expectExceptionMessageMatches('/ath/');
        DpopVerifier::verifyProof($proof, $this->request(), $this->store);
    }

    /**
     * Check 10 — the step that ties the proof to the token; the other nine are what
     * make the proof mean anything.
     */
    public function testCheck10ProofByTheWrongKeyIsRefused(): void
    {
        $other = self::newKey();
        $request = $this->request()->withExpectedJkt(DpopVerifier::thumbprintS256($other[1]));

        $this->expectException(AuthError::class);
        $this->expectExceptionMessageMatches('/cnf\.jkt/');
        DpopVerifier::verifyProof($this->goodProof(), $request, $this->store);
    }

    // ---------------------------------------------------------------------
    // Thumbprint and framing
    // ---------------------------------------------------------------------

    /**
     * The RFC 7638 appendix A worked example. A thumbprint implementation that is
     * self-consistent but wrong agrees with itself on every round trip, so the only
     * useful test is against a published vector.
     */
    public function testThumbprintMatchesRfc7638AppendixA(): void
    {
        self::assertSame(
            'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
            DpopVerifier::thumbprintS256([
                'kty' => 'RSA',
                'n' => '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7'
                    . 'aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXA'
                    . 'rwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7'
                    . 'd0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lF'
                    . 'd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
                'e' => 'AQAB',
            ])
        );
    }

    /**
     * The RFC 8037 appendix A.3 Ed25519 thumbprint vector.
     */
    public function testThumbprintMatchesRfc8037Ed25519Vector(): void
    {
        self::assertSame(
            'kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k',
            DpopVerifier::thumbprintS256([
                'kty' => 'OKP',
                'crv' => 'Ed25519',
                'x' => '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo',
            ])
        );
    }

    /**
     * `kid`/`use`/`alg`/`x5c` are excluded by RFC 7638 — which is exactly what makes
     * the thumbprint stable across two different encodings of the same key.
     */
    public function testThumbprintIgnoresMembersOutsideTheRfc7638Set(): void
    {
        $decorated = $this->key[1] + ['kid' => 'abc', 'use' => 'sig', 'alg' => 'EdDSA'];

        self::assertSame(
            DpopVerifier::thumbprintS256($this->key[1]),
            DpopVerifier::thumbprintS256($decorated)
        );
    }

    /**
     * RFC 9449 §4.2 makes exactly one proof the rule. Rejecting beats picking the
     * first, which is how a verifier and a downstream parser end up reading different
     * proofs.
     */
    public function testHeaderCarryingTwoProofsIsRefused(): void
    {
        $proof = $this->goodProof();

        $this->expectException(AuthError::class);
        $this->expectExceptionMessageMatches('/exactly one proof/');
        DpopVerifier::verifyProof($proof . ',' . $proof, $this->request(), $this->store);
    }

    /**
     * Malformed input fails closed as an AuthError rather than some other throwable.
     */
    public function testMalformedProofsAreRefused(): void
    {
        foreach (['', 'not-a-jwt', 'a.b', 'a.b.c.d', '!!!.###.$$$'] as $junk) {
            try {
                DpopVerifier::verifyProof($junk, $this->request(), $this->store);
                self::fail("accepted {$junk}");
            } catch (AuthError $e) {
                self::assertNotSame('', $e->getMessage());
            }
        }
    }
}
