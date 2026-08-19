<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Srp\BcMathBackend;
use Axiam\Sdk\Srp\BigIntBackend;
use Axiam\Sdk\Srp\GmpBackend;
use Axiam\Sdk\Srp\Srp;
use Axiam\Sdk\Srp\SrpClientSession;
use Axiam\Sdk\Srp\SrpGroup;
use Axiam\Sdk\Srp\SrpKdfParams;
use PHPUnit\Framework\TestCase;

/**
 * CONTRACT.md §23.7 conformance for the SRP-6a client.
 *
 * `srp-test-vectors.json` is generated from the AXIAM server implementation and vendored into every
 * SDK. Eleven independent SRP implementations do not interoperate by accident; this is the file
 * that says whether this one does.
 *
 * §23.7 rule 1 requires every intermediate to be reproduced, not only the final proof — an SDK that
 * gets `u` wrong should find out at `u` rather than at "login sometimes fails".
 *
 * Every arithmetic test runs against **each** available backend rather than whichever
 * {@see Srp::detect()} happens to prefer: `ext-gmp` and `ext-bcmath` are two independent
 * implementations of the same interface, and a bug in the one this runtime does not prefer would
 * otherwise ship untested.
 */
final class SrpVectorsTest extends TestCase
{
    /**
     * Every bignum backend this runtime can actually run.
     *
     * @return array<string,array{BigIntBackend}>
     */
    public static function backends(): array
    {
        $out = [];
        if (GmpBackend::isAvailable()) {
            $out['gmp'] = [new GmpBackend()];
        }
        if (BcMathBackend::isAvailable()) {
            $out['bcmath'] = [new BcMathBackend()];
        }
        if ($out === []) {
            // Not a silent skip: a runtime with neither extension cannot exercise any of the
            // arithmetic, and a green suite that quietly tested nothing is worse than a red one.
            // The refusal path IS tested — see testSrpAvailableReportsFalseWithoutABignumExtension.
            $out['none'] = [new NullBackendMarker()];
        }

        return $out;
    }

    /** @return list<array<string,string>> */
    private static function vectors(): array
    {
        $dir = __DIR__;
        while (true) {
            $candidate = $dir . '/srp-test-vectors.json';
            if (is_file($candidate)) {
                /** @var array{vectors: list<array<string,string>>} $parsed */
                $parsed = json_decode((string) file_get_contents($candidate), true);

                return $parsed['vectors'];
            }
            $parent = \dirname($dir);
            if ($parent === $dir) {
                self::fail('srp-test-vectors.json not found in any parent directory');
            }
            $dir = $parent;
        }
    }

    /** @return list<array{array<string,string>,BigIntBackend}> */
    public static function vectorsAndBackends(): array
    {
        $out = [];
        foreach (self::backends() as $name => [$backend]) {
            if ($backend instanceof NullBackendMarker) {
                continue;
            }
            foreach (self::vectors() as $vector) {
                $out[$vector['group'] . '/' . $vector['identity'] . '/' . $name] = [$vector, $backend];
            }
        }

        return $out === [] ? ['no backend' => [[], new NullBackendMarker()]] : $out;
    }

    private function skipWithoutBackend(BigIntBackend $backend): void
    {
        if ($backend instanceof NullBackendMarker) {
            self::markTestSkipped('neither ext-gmp nor ext-bcmath is loaded (CONTRACT.md §23.8)');
        }
    }

    // -----------------------------------------------------------------------
    // §23.8 — the conditional posture that is PHP's alone
    // -----------------------------------------------------------------------

    /**
     * PHP is the one AXIAM SDK language where the capability probe genuinely answers `false`, and
     * §23.8 requires it to report rather than throw — an application must be able to choose a login
     * path before attempting one.
     */
    public function testSrpAvailabilityTracksTheRuntimeExtensions(): void
    {
        $expected = GmpBackend::isAvailable() || BcMathBackend::isAvailable();
        self::assertSame($expected, Srp::detect() !== null);
    }

    /**
     * Argon2id is refused rather than approximated.
     *
     * §23.5's SRP salt is 32 bytes; libsodium's `sodium_crypto_pwhash` — the only Argon2id in PHP
     * that accepts a caller-supplied salt at all — requires exactly 16. Folding would produce a
     * well-formed `x` that no AXIAM server agrees with, and the user would be told their password
     * is wrong. §23.3 rule 4's NetworkError is the honest answer.
     */
    public function testArgon2idIsRefusedWithAnExplanationRatherThanApproximated(): void
    {
        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/argon2id/');
        Srp::deriveX('alice', 'pw', str_repeat("\x00", 32), new SrpKdfParams(Srp::KDF_ARGON2ID, 2, 19456, 1));
    }

    // -----------------------------------------------------------------------
    // §23.7 rule 4 — group constants
    // -----------------------------------------------------------------------

    /**
     * A transcription slip in a modulus is a silent, total break: client and server would still
     * agree with each other while the discrete-log hardness the protocol rests on quietly vanished.
     * A round-trip test cannot catch it, because both sides share the same wrong constant.
     *
     * @dataProvider backends
     */
    public function testEveryGroupIsASafePrimeOfTheAdvertisedWidth(BigIntBackend $backend): void
    {
        $this->skipWithoutBackend($backend);
        foreach (SrpGroup::all() as $group) {
            $n = $group->modulusHex;
            self::assertSame($group->byteLength * 8, $backend->bitLength($n), $group->wireName . ' width');
            self::assertTrue($backend->isProbablePrime($n), $group->wireName . ' modulus is not prime');

            // A safe prime: N = 2q + 1 with q prime.
            $q = $backend->shiftRight1($backend->subMod($n, '1', $backend->mul($n, $n)));
            self::assertTrue($backend->isProbablePrime($q), $group->wireName . ' is not a safe prime');

            // g generates the order-q subgroup iff g^q == N-1 for a safe prime.
            self::assertSame(
                Srp::pad($backend->subMod($n, '1', $backend->mul($n, $n)), $group->byteLength),
                Srp::pad($backend->modPow(dechex($group->generator), $q, $n), $group->byteLength),
                $group->wireName . ': g does not generate the large subgroup',
            );
        }
    }

    public function testAnUnrecognisedGroupIsRefusedRatherThanGuessed(): void
    {
        // Guessing would mean computing in a group whose safety this SDK has not verified —
        // potentially one whose discrete log the server knows. NetworkError, not AuthError: a
        // client capability gap reported as an auth failure would send a user to reset a working
        // password.
        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/rfc5054_1024/');
        SrpGroup::fromWire('rfc5054_1024');
    }

    // -----------------------------------------------------------------------
    // §23.3 rule 1 — PAD()
    // -----------------------------------------------------------------------

    public function testPadLeftPadsToTheGroupWidth(): void
    {
        self::assertSame('00000001', Srp::pad('1', 4));
        self::assertSame('0102', Srp::pad('0102', 2));
    }

    public function testPadRefusesAnOverWideValueRatherThanTruncating(): void
    {
        // Silently dropping high bytes would produce a wrong hash that still looked well-formed.
        $this->expectException(NetworkError::class);
        Srp::pad('0102030405', 2);
    }

    // -----------------------------------------------------------------------
    // §23.7 rules 1–3 — the vectors
    // -----------------------------------------------------------------------

    /**
     * Guards the fixture itself: if these stop holding, everything below silently stops testing the
     * two things it was built to test.
     */
    public function testTheFixturesCoverTheCasesTheyExistFor(): void
    {
        $vectors = self::vectors();
        self::assertNotEmpty($vectors);

        $salts = array_column($vectors, 'salt');
        $xs = array_column($vectors, 'x');
        $identities = array_column($vectors, 'identity');
        self::assertNotEmpty(
            array_filter($salts, static fn (string $s): bool => str_starts_with($s, '00')),
            '§23.7 rule 2: no vector has a leading-zero salt',
        );
        self::assertNotEmpty(
            array_filter($xs, static fn (string $s): bool => str_starts_with($s, '00')),
            '§23.7 rule 2: no vector has a leading-zero x',
        );
        self::assertNotEmpty(
            array_filter($identities, static fn (string $s): bool => $s !== '' && !mb_check_encoding($s, 'ASCII')),
            '§23.7 rule 3: no vector has a non-ASCII identity',
        );
        $groups = array_column($vectors, 'group');
        foreach (SrpGroup::all() as $group) {
            self::assertContains($group->wireName, $groups, 'no vector covers ' . $group->wireName);
        }
    }

    /**
     * @param array<string,string> $v
     *
     * @dataProvider vectorsAndBackends
     */
    public function testEveryVectorReproducesEveryIntermediate(array $v, BigIntBackend $backend): void
    {
        $this->skipWithoutBackend($backend);
        $srp = Srp::over($backend);
        $group = SrpGroup::fromWire($v['group']);
        $n = $group->modulusHex;
        $x = $backend->mod($v['x'], $n);

        // k = H(N | PAD(g))
        self::assertSame($v['k'], Srp::pad(Srp::multiplier($group), 32), 'k');

        // v = g^x mod N
        self::assertSame($v['verifier'], $srp->computeVerifier($group, Srp::hexToBytes($v['x'])), 'verifier');

        // A = g^a mod N
        $aPub = $backend->modPow(dechex($group->generator), $v['a_priv'], $n);
        self::assertSame($v['a_pub'], Srp::pad($aPub, $group->byteLength), 'A');

        // B = (k*v + g^b) mod N
        $verifier = $backend->modPow(dechex($group->generator), $x, $n);
        $bPub = $backend->addMod(
            $backend->mulMod(Srp::multiplier($group), $verifier, $n),
            $backend->modPow(dechex($group->generator), $v['b_priv'], $n),
            $n,
        );
        self::assertSame($v['b_pub'], Srp::pad($bPub, $group->byteLength), 'B');

        // u = H(PAD(A) | PAD(B))
        $u = Srp::hash(
            Srp::hexToBytes(Srp::pad($aPub, $group->byteLength)),
            Srp::hexToBytes(Srp::pad($bPub, $group->byteLength)),
        );
        self::assertSame($v['u'], Srp::pad($u, 32), 'u');

        // S and K, from the client's derivation.
        $kgx = $backend->mulMod(Srp::multiplier($group), $backend->modPow(dechex($group->generator), $x, $n), $n);
        $base = $backend->subMod($bPub, $kgx, $n);
        $s = $backend->modPow($base, $backend->add($v['a_priv'], $backend->mul($u, $x)), $n);
        self::assertSame($v['session_secret'], Srp::pad($s, $group->byteLength), 'S');
        self::assertSame(
            $v['session_key'],
            Srp::hash(Srp::hexToBytes(Srp::pad($s, $group->byteLength))),
            'K',
        );
    }

    /**
     * Drives the real session rather than the helpers, with `a` pinned to the vector's value —
     * otherwise this would only test the internals.
     *
     * @param array<string,string> $v
     *
     * @dataProvider vectorsAndBackends
     */
    public function testEveryVectorProducesTheContractProofsThroughThePublicApi(
        array $v,
        BigIntBackend $backend,
    ): void {
        $this->skipWithoutBackend($backend);
        $srp = Srp::over($backend);
        $session = SrpClientSession::withFixedEphemeral($srp, SrpGroup::fromWire($v['group']), $v['a_priv']);
        self::assertSame($v['a_pub'], $session->clientPublic, 'A');

        $proofs = $session->finish($v['identity'], $v['salt'], $v['b_pub'], Srp::hexToBytes($v['x']));
        self::assertSame($v['client_proof'], $proofs->clientProof, 'M1');
        self::assertSame($v['server_proof'], $proofs->expectedServerProof, 'M2');
    }

    // -----------------------------------------------------------------------
    // §23.3 protocol refusals
    // -----------------------------------------------------------------------

    /**
     * §23.7 rule 6, with no network round trip. The classic SRP break: a client that accepts
     * `B ≡ 0` derives a predictable `S` and would authenticate against a server that never knew the
     * verifier.
     *
     * @dataProvider backends
     */
    public function testAServerPublicValueCongruentToZeroIsRefused(BigIntBackend $backend): void
    {
        $this->skipWithoutBackend($backend);
        $group = SrpGroup::fromWire('rfc5054_2048');
        $session = SrpClientSession::begin(Srp::over($backend), $group);

        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/invalid public value/');
        $session->finish('alice', str_repeat('00', 32), str_repeat('0', $group->byteLength * 2), str_repeat("\x00", 32));
    }

    /** @dataProvider backends */
    public function testEveryExchangeUsesAFreshClientEphemeral(BigIntBackend $backend): void
    {
        $this->skipWithoutBackend($backend);
        $srp = Srp::over($backend);
        $group = SrpGroup::fromWire('rfc5054_2048');
        self::assertNotSame(
            SrpClientSession::begin($srp, $group)->clientPublic,
            SrpClientSession::begin($srp, $group)->clientPublic,
        );
    }

    public function testAnUnknownKdfIsRefusedRatherThanSubstituted(): void
    {
        // Substituting the other KDF derives a different x and surfaces as "invalid password" —
        // the single most misleading failure available.
        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/scrypt/');
        Srp::deriveX('alice', 'pw', str_repeat("\x00", 32), new SrpKdfParams('scrypt', 1));
    }

    public function testAMalformedHexFieldIsRefusedRatherThanSilentlyTruncated(): void
    {
        $this->expectException(NetworkError::class);
        Srp::hexToBytes('zz', 'salt');
    }

    // -----------------------------------------------------------------------
    // KDF
    // -----------------------------------------------------------------------

    /**
     * Every one of these must change the output, or a verifier would be replayable against a
     * different account or a different salt.
     */
    public function testTheKdfBindsIdentityPasswordAndSalt(): void
    {
        $params = new SrpKdfParams(Srp::KDF_PBKDF2_SHA256, 1000);
        $salt = str_repeat("\x0a", 32);
        $base = Srp::deriveX('alice', 'pw', $salt, $params);

        self::assertSame(32, \strlen($base));
        self::assertSame($base, Srp::deriveX('alice', 'pw', $salt, $params));
        self::assertNotSame($base, Srp::deriveX('bob', 'pw', $salt, $params));
        self::assertNotSame($base, Srp::deriveX('alice', 'pw2', $salt, $params));
        self::assertNotSame($base, Srp::deriveX('alice', 'pw', str_repeat("\x0b", 32), $params));
    }

    /**
     * §23.7 rule 3 pins the UTF-8 encoding of the identity, which is why a non-ASCII vector exists.
     */
    public function testTheKdfTreatsAMangledNonAsciiIdentityAsADifferentAccount(): void
    {
        $params = new SrpKdfParams(Srp::KDF_PBKDF2_SHA256, 1000);
        $salt = str_repeat("\x00", 32);
        self::assertNotSame(
            Srp::deriveX("ren\u{c3}\u{a9}e", 'pw', $salt, $params),
            Srp::deriveX('renée', 'pw', $salt, $params),
        );
    }

    public function testKdfDefaultsMatchAxiamsOwnCosts(): void
    {
        $argon = (new SrpKdfParams('', 0))->withDefaults();
        self::assertSame(Srp::KDF_ARGON2ID, $argon->kdf);
        self::assertSame(2, $argon->iterations);
        self::assertSame(19456, $argon->memoryKib);
        self::assertSame(1, $argon->parallelism);

        $pbkdf2 = (new SrpKdfParams(Srp::KDF_PBKDF2_SHA256, 0))->withDefaults();
        self::assertSame(600000, $pbkdf2->iterations);
        self::assertSame(0, $pbkdf2->memoryKib);
    }

    // -----------------------------------------------------------------------
    // §23.3 rule 6 — server proof comparison
    // -----------------------------------------------------------------------

    public function testTheServerProofComparisonAcceptsAMatchAndRejectsEverythingElse(): void
    {
        $proof = self::vectors()[0]['server_proof'];
        self::assertTrue(Srp::verifyServerProof($proof, $proof));
        self::assertFalse(Srp::verifyServerProof($proof, substr($proof, 0, -1) . '0'));
        self::assertFalse(Srp::verifyServerProof($proof, substr($proof, 0, 32)));
        self::assertFalse(Srp::verifyServerProof($proof, ''));
        self::assertFalse(Srp::verifyServerProof($proof, null));
    }

    // -----------------------------------------------------------------------
    // §23.3 rule 11 — enrolment salts
    // -----------------------------------------------------------------------

    public function testEnrolmentSaltsAre32FreshBytes(): void
    {
        // A reused salt would make every verifier in a tenant equally attackable with one
        // precomputation.
        $first = Srp::generateSalt();
        self::assertSame(32, \strlen($first));
        self::assertNotSame($first, Srp::generateSalt());
    }
}

/**
 * Stands in for a backend on a runtime that has neither extension, so the data providers can still
 * name a case and {@see SrpVectorsTest::skipWithoutBackend()} can skip it explicitly.
 *
 * Every method throws: this is never meant to compute anything, and a silent zero would let a test
 * pass against arithmetic that never ran.
 */
final class NullBackendMarker implements BigIntBackend
{
    public function name(): string
    {
        return 'none';
    }

    public function modPow(string $baseHex, string $exponentHex, string $modulusHex): string
    {
        throw new \LogicException('no bignum backend');
    }

    public function mulMod(string $aHex, string $bHex, string $modulusHex): string
    {
        throw new \LogicException('no bignum backend');
    }

    public function addMod(string $aHex, string $bHex, string $modulusHex): string
    {
        throw new \LogicException('no bignum backend');
    }

    public function mul(string $aHex, string $bHex): string
    {
        throw new \LogicException('no bignum backend');
    }

    public function add(string $aHex, string $bHex): string
    {
        throw new \LogicException('no bignum backend');
    }

    public function subMod(string $aHex, string $bHex, string $modulusHex): string
    {
        throw new \LogicException('no bignum backend');
    }

    public function mod(string $aHex, string $modulusHex): string
    {
        throw new \LogicException('no bignum backend');
    }

    public function isZero(string $hex): bool
    {
        throw new \LogicException('no bignum backend');
    }

    public function bitLength(string $hex): int
    {
        throw new \LogicException('no bignum backend');
    }

    public function isProbablePrime(string $hex): bool
    {
        throw new \LogicException('no bignum backend');
    }

    public function shiftRight1(string $hex): string
    {
        throw new \LogicException('no bignum backend');
    }
}
