<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Opaque\KsfParams;
use Axiam\Sdk\Opaque\LoginExchange;
use Axiam\Sdk\Opaque\Opaque;
use Axiam\Sdk\Opaque\OpaqueLibrary;
use Axiam\Sdk\Opaque\RegistrationExchange;
use Axiam\Sdk\Tests\Fakes\FakeOpaqueNative;
use PHPUnit\Framework\TestCase;

/**
 * The binding to `libaxiam_opaque_ffi`.
 *
 * §23.1 forbids this SDK from implementing OPAQUE, so there is no cryptography here to test.
 * What these cover is the layer above the ABI: single-use exchanges, the key-stretching function
 * the *server* named being the one used, which failure means what, and an absent library
 * reporting rather than resembling a wrong password.
 *
 * Pointer ownership lives in `FfiOpaqueNative` and needs the real shared library to exercise;
 * that class is deliberately the thinnest in the package for exactly that reason.
 */
final class OpaqueBindingTest extends TestCase
{
    private const KE2 = 'ke2-hex';
    private const REGISTRATION_RESPONSE = 'resp-hex';

    private FakeOpaqueNative $lib;

    /**
     * Minted per run rather than written down. Nothing here depends on the value — only on the
     * two differing — and a literal that reads like a credential is a finding for every secret
     * scanner that looks at this repository, which trains people to wave those findings through.
     */
    private string $password;

    private string $otherPassword;

    protected function setUp(): void
    {
        $this->lib = new FakeOpaqueNative();
        OpaqueLibrary::setForTests($this->lib);
        $this->password = 'correct-' . bin2hex(random_bytes(8));
        $this->otherPassword = 'incorrect-' . bin2hex(random_bytes(8));
    }

    protected function tearDown(): void
    {
        OpaqueLibrary::resetForTests();
    }

    private static function argon2id(): KsfParams
    {
        return KsfParams::fromWire([
            'ksf' => 'argon2id',
            'memory_kib' => 19456,
            'iterations' => 2,
            'parallelism' => 1,
        ]);
    }

    private static function scrypt(): KsfParams
    {
        return KsfParams::fromWire(['ksf' => 'scrypt', 'log_n' => 15, 'r' => 8, 'p' => 1]);
    }

    // -----------------------------------------------------------------
    // Availability (§23.2) -- reporting, never throwing
    // -----------------------------------------------------------------

    public function testAvailableIsTrueWhenTheLibraryIsPresent(): void
    {
        self::assertTrue(Opaque::available());
    }

    public function testAnAbsentLibraryReportsFalseRatherThanThrowing(): void
    {
        OpaqueLibrary::setForTests(null);
        self::assertFalse(Opaque::available());
    }

    public function testAnAbsentLibraryNamesTheArtifactNotThePassword(): void
    {
        OpaqueLibrary::setForTests(null);

        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/libaxiam_opaque_ffi.*AXIAM_OPAQUE_LIBRARY/s');
        Opaque::startLogin($this->password);
    }

    public function testTheRealLoaderReportsAbsentAndMemoizesThat(): void
    {
        // No libaxiam_opaque_ffi is installed in CI, so this exercises the genuine
        // load failure path -- including that retrying it is not a per-login
        // filesystem walk.
        OpaqueLibrary::resetForTests();
        putenv(OpaqueLibrary::PATH_ENV . '=/nonexistent/libaxiam_opaque_ffi_absent.so');

        try {
            self::assertNull(OpaqueLibrary::load());
            self::assertNull(OpaqueLibrary::load());
        } finally {
            putenv(OpaqueLibrary::PATH_ENV);
            OpaqueLibrary::resetForTests();
        }
    }

    public function testThePathOverrideWinsOverThePlatformDefault(): void
    {
        putenv(OpaqueLibrary::PATH_ENV . '=/opt/axiam/libopaque.so');

        try {
            self::assertSame(['/opt/axiam/libopaque.so'], OpaqueLibrary::candidatePaths());
        } finally {
            putenv(OpaqueLibrary::PATH_ENV);
        }
    }

    public function testThePlatformDefaultNamesTheLibrary(): void
    {
        putenv(OpaqueLibrary::PATH_ENV);
        self::assertStringContainsString('axiam_opaque_ffi', OpaqueLibrary::candidatePaths()[0]);
    }

    // -----------------------------------------------------------------
    // KsfParams -- absence preserved, bounds enforced (§23.4 rules 2-5)
    // -----------------------------------------------------------------

    public function testFromWirePreservesAbsenceRatherThanDefaultingToZero(): void
    {
        $params = self::argon2id();

        self::assertSame(19456, $params->memoryKib);
        // scrypt's fields do not apply. Reading them as 0 would stretch at the
        // wrong cost and fail against a record that is perfectly good.
        self::assertNull($params->logN);
        self::assertNull($params->r);
        self::assertNull($params->p);
    }

    public function testFromWireCoercesNumericStrings(): void
    {
        $params = KsfParams::fromWire(['ksf' => 'scrypt', 'log_n' => '15', 'r' => '8', 'p' => '1']);

        self::assertSame([15, 8, 1], [$params->logN, $params->r, $params->p]);
    }

    public function testACostTheNamedFunctionNeedsButTheServerOmittedIsRefused(): void
    {
        $params = KsfParams::fromWire([
            'ksf' => 'argon2id',
            'iterations' => 2,
            'parallelism' => 1,
        ]);

        try {
            $params->build($this->lib);
            self::fail('expected a NetworkError');
        } catch (NetworkError $e) {
            self::assertStringContainsString('without `memory_kib`', $e->getMessage());
        }

        self::assertSame(0, $this->lib->ksfAlive);
    }

    /**
     * @return list<array{0: string, 1: string, 2: int}>
     */
    public static function outOfBandCosts(): array
    {
        return [
            ['argon2id', 'memory_kib', 4096],
            ['argon2id', 'memory_kib', 2097152],
            ['argon2id', 'iterations', 0],
            ['argon2id', 'iterations', 99],
            ['argon2id', 'parallelism', 64],
            ['scrypt', 'log_n', 13],
            ['scrypt', 'log_n', 21],
            ['scrypt', 'r', 0],
            ['scrypt', 'p', 17],
        ];
    }

    /** @dataProvider outOfBandCosts */
    public function testACostOutsideTheAcceptedBandIsRefusedNamingTheField(
        string $ksf,
        string $field,
        int $value,
    ): void {
        // A server is trusted to name its own policy, not to name a cost that
        // would wedge every device an account owns.
        $wire = $ksf === 'argon2id'
            ? ['ksf' => 'argon2id', 'memory_kib' => 19456, 'iterations' => 2, 'parallelism' => 1]
            : ['ksf' => 'scrypt', 'log_n' => 15, 'r' => 8, 'p' => 1];
        $wire[$field] = $value;

        try {
            KsfParams::fromWire($wire)->build($this->lib);
            self::fail('expected a NetworkError');
        } catch (NetworkError $e) {
            self::assertStringContainsString($field, $e->getMessage());
        }

        self::assertSame(0, $this->lib->ksfAlive);
    }

    /** @return list<array{0: string}> */
    public static function unknownFunctions(): array
    {
        return [['bcrypt'], ['pbkdf2_sha256'], ['']];
    }

    /** @dataProvider unknownFunctions */
    public function testAnUnrecognisedFunctionIsRefusedNeverSubstituted(string $ksf): void
    {
        // Substituting produces a well-formed randomized password no AXIAM server
        // agrees with, which surfaces to the user as a wrong password.
        //
        // pbkdf2_sha256 is in this list on purpose: it was SRP's PHP-only fallback,
        // and it is not an OPAQUE key-stretching function at all.
        $this->expectException(NetworkError::class);
        KsfParams::fromWire(['ksf' => $ksf])->build($this->lib);
    }

    public function testANullKsfHandleReportsTheLibrarysOwnMessage(): void
    {
        $this->lib->fail('ksf_argon2id');

        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/argon2id parameters rejected/');
        self::argon2id()->build($this->lib);
    }

    public function testBothKeyStretchingFunctionsAreReachable(): void
    {
        foreach ([self::argon2id(), self::scrypt()] as $params) {
            $this->lib->ksfFree($params->build($this->lib));
        }

        self::assertSame(0, $this->lib->ksfAlive);
    }

    // -----------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------

    public function testARegistrationRoundTripLeavesNothingAlive(): void
    {
        $exchange = Opaque::startRegistration($this->password);
        self::assertSame(
            'req:' . $this->password,
            FakeOpaqueNative::decode($exchange->request())
        );

        $record = $exchange->finish($this->password, self::REGISTRATION_RESPONSE, self::argon2id());

        self::assertStringStartsWith(
            \sprintf('record:%s:%s:', $this->password, self::REGISTRATION_RESPONSE),
            FakeOpaqueNative::decode($record)
        );
        self::assertSame(0, $this->lib->ksfAlive);
        self::assertSame(0, $this->lib->statesAlive());
    }

    public function testAFailedRegistrationStartReportsTheLibrarysMessage(): void
    {
        $this->lib->fail('registration_start');

        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/registration could not be started/');
        Opaque::startRegistration($this->password);
    }

    public function testAFailedRegistrationFinishStillConsumedTheHandle(): void
    {
        $this->lib->fail('registration_finish');
        $exchange = Opaque::startRegistration($this->password);

        try {
            $exchange->finish($this->password, self::REGISTRATION_RESPONSE, self::argon2id());
            self::fail('expected a NetworkError');
        } catch (NetworkError $e) {
            self::assertStringContainsString('the envelope could not be sealed', $e->getMessage());
        }

        // The library consumes the state whether it succeeds or fails, so the
        // binding must not free it again -- and must not leak the ksf either.
        self::assertSame(0, $this->lib->statesAlive());
        self::assertSame(0, $this->lib->ksfAlive);
    }

    // -----------------------------------------------------------------
    // Login
    // -----------------------------------------------------------------

    public function testALoginRoundTripLeavesNothingAlive(): void
    {
        $exchange = Opaque::startLogin($this->password);
        self::assertSame('ke1:' . $this->password, FakeOpaqueNative::decode($exchange->ke1()));

        $ke3 = $exchange->finish($this->password, self::KE2, self::scrypt());

        self::assertStringStartsWith(
            \sprintf('ke3:%s:%s:', $this->password, self::KE2),
            FakeOpaqueNative::decode($ke3)
        );
        // The fake encodes the handle it was given; scrypt handles start 0xb, so
        // this is also the assertion that the server-named function was the one used.
        self::assertStringEndsWith(
            ':' . dechex(0xB0000 + 15 + 8 + 1),
            FakeOpaqueNative::decode($ke3)
        );
        self::assertSame(0, $this->lib->ksfAlive);
        self::assertSame(0, $this->lib->statesAlive());
    }

    public function testAFailedLoginStartReportsTheLibrarysMessage(): void
    {
        $this->lib->fail('login_start');

        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/login could not be started/');
        Opaque::startLogin($this->password);
    }

    public function testAFailedLoginFinishIsAnAuthErrorBecauseItIsTheCredentialCheck(): void
    {
        // Both halves of the mutual authentication live here: the envelope only
        // opens under the right password, and KE2's MAC only verifies if the server
        // actually holds the record. AuthError rather than NetworkError is what
        // keeps a misconfigured KSF from being shown as a wrong password.
        $this->lib->fail('login_finish');
        $exchange = Opaque::startLogin($this->otherPassword);

        try {
            $exchange->finish($this->otherPassword, self::KE2, self::argon2id());
            self::fail('expected an AuthError');
        } catch (AuthError $e) {
            self::assertStringContainsString('invalid credentials', $e->getMessage());
        }

        self::assertSame(0, $this->lib->statesAlive());
        self::assertSame(0, $this->lib->ksfAlive);
    }

    public function testASilentLibraryStillProducesASentence(): void
    {
        $this->lib->fail('login_finish');
        $this->lib->failMessage('login_finish', '');
        $exchange = Opaque::startLogin($this->otherPassword);

        $this->expectException(AuthError::class);
        $this->expectExceptionMessageMatches('/the OPAQUE envelope did not open/');
        $exchange->finish($this->otherPassword, self::KE2, self::argon2id());
    }

    // -----------------------------------------------------------------
    // Lifecycle
    // -----------------------------------------------------------------

    public function testAnExchangeIsSingleUse(): void
    {
        $exchange = Opaque::startLogin($this->password);
        $exchange->finish($this->password, self::KE2, self::argon2id());

        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/already been completed/');
        $exchange->finish($this->password, self::KE2, self::argon2id());
    }

    public function testARefusedKsfLeavesTheExchangeIntact(): void
    {
        // The key-stretching handle is built before the state is spent, so a
        // refusal is not a spent exchange. If the order were the other way round,
        // the state would be out of its slot and unreachable by close() -- a
        // leaked Rust allocation per refused attempt, which is once per login
        // against a misconfigured tenant.
        $exchange = Opaque::startRegistration($this->password);

        try {
            $exchange->finish(
                $this->password,
                self::REGISTRATION_RESPONSE,
                KsfParams::fromWire(['ksf' => 'bcrypt'])
            );
            self::fail('expected a NetworkError');
        } catch (NetworkError) {
            // expected
        }

        self::assertSame(1, $this->lib->statesAlive(), 'the state must still be reachable');
        self::assertSame(0, $this->lib->ksfAlive, 'a refused ksf allocates nothing to leak');

        // And the caller who fixes the parameters can simply carry on.
        $record = $exchange->finish($this->password, self::REGISTRATION_RESPONSE, self::argon2id());
        self::assertStringStartsWith('record:', FakeOpaqueNative::decode($record));
        self::assertSame(0, $this->lib->statesAlive());
    }

    public function testAnOutOfBandCostAlsoLeavesTheExchangeIntact(): void
    {
        $exchange = Opaque::startLogin($this->password);

        try {
            $exchange->finish($this->password, self::KE2, KsfParams::fromWire([
                'ksf' => 'argon2id',
                'memory_kib' => 4096,
                'iterations' => 2,
                'parallelism' => 1,
            ]));
            self::fail('expected a NetworkError');
        } catch (NetworkError) {
            // expected
        }

        self::assertSame(1, $this->lib->statesAlive());
        $exchange->close();
        self::assertSame(0, $this->lib->statesAlive());
    }

    public function testCloseReleasesAnExchangeThatWasNeverFinished(): void
    {
        $exchange = Opaque::startLogin($this->password);
        self::assertSame(1, $this->lib->statesAlive());

        $exchange->close();
        self::assertSame(0, $this->lib->statesAlive());

        $exchange->close();
        self::assertSame(0, $this->lib->statesAlive());
    }

    public function testCloseAfterAFinishIsANoOp(): void
    {
        $exchange = Opaque::startLogin($this->password);
        $exchange->finish($this->password, self::KE2, self::argon2id());
        $exchange->close();

        self::assertSame(0, $this->lib->statesAlive());
    }

    public function testTheDestructorReleasesAnAbandonedExchange(): void
    {
        // PHP's refcounting makes this prompt rather than eventual, which is the
        // one place its object model is kinder here than a tracing GC's.
        (static function (): void {
            $exchange = Opaque::startRegistration('unused');
            self::assertInstanceOf(RegistrationExchange::class, $exchange);
        })();

        self::assertSame(0, $this->lib->statesAlive());
    }

    // -----------------------------------------------------------------
    // Encoding
    // -----------------------------------------------------------------

    public function testANonAsciiPasswordSurvivesTheRoundTrip(): void
    {
        $accented = 'pàsswörd-ünïcøde-🔐';
        $exchange = Opaque::startLogin($accented);

        self::assertInstanceOf(LoginExchange::class, $exchange);
        self::assertSame('ke1:' . $accented, FakeOpaqueNative::decode($exchange->ke1()));
        $exchange->close();
    }
}
