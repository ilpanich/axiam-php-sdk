<?php

declare(strict_types=1);

namespace Axiam\Sdk\Srp;

/**
 * The arbitrary-precision arithmetic SRP needs, behind an interface.
 *
 * PHP is the one language in the AXIAM SDK family with no native bignum, and neither `ext-gmp` nor
 * `ext-bcmath` is guaranteed present (CONTRACT.md §23.8). Everything SRP needs is here, so the rest
 * of `Axiam\Sdk\Srp` is written once against this interface rather than twice against two
 * extensions — and so a test can supply neither backend and prove the refusal path, which is the
 * behaviour §23.8 actually pins for PHP.
 *
 * Every value crossing this boundary is **uppercase-or-lowercase hex without a sign**, not a
 * PHP int: the numbers are 2048 to 4096 bits wide and there is no native type that holds them.
 */
interface BigIntBackend
{
    /** A short name for this backend, e.g. `gmp` — used only in diagnostics. */
    public function name(): string;

    /**
     * `(base ^ exponent) mod modulus`, all hex.
     *
     * This is the whole reason the interface exists: a 4096-bit modular exponentiation is not
     * something to hand-roll in PHP, and it is the operation both extensions provide natively.
     */
    public function modPow(string $baseHex, string $exponentHex, string $modulusHex): string;

    /** `(a * b) mod modulus`, all hex. */
    public function mulMod(string $aHex, string $bHex, string $modulusHex): string;

    /** `(a + b) mod modulus`, all hex. */
    public function addMod(string $aHex, string $bHex, string $modulusHex): string;

    /**
     * `a * b`, hex, with **no** reduction.
     *
     * Every other product in SRP is modular; this one is not. `u * x` feeds the exponent
     * `a + u*x`, and reducing an exponent modulo `N` — rather than modulo the group order —
     * produces a different, wrong `S` that is still perfectly well-formed. Having the
     * unreduced operation on the interface is how that mistake is kept unavailable.
     */
    public function mul(string $aHex, string $bHex): string;

    /** `a + b`, hex, with no reduction — the other half of the exponent `a + u*x`. */
    public function add(string $aHex, string $bHex): string;

    /**
     * `(a - b) mod modulus`, all hex, with a **non-negative** result.
     *
     * The non-negativity is load-bearing: `B - k*g^x` is routinely negative before reduction, and
     * a backend that returned a negative value here would feed a nonsense exponent into
     * {@see self::modPow()} and produce a client that fails roughly half of all logins.
     */
    public function subMod(string $aHex, string $bHex, string $modulusHex): string;

    /** `a mod modulus`, hex, non-negative. */
    public function mod(string $aHex, string $modulusHex): string;

    /** Whether the hex value is zero. */
    public function isZero(string $hex): bool;

    /** The value's width in bits, for the group-constant assertions §23.4 requires. */
    public function bitLength(string $hex): int;

    /**
     * A probabilistic primality test.
     *
     * Only the test suite calls this — §23.4 requires an SDK to assert that its embedded moduli
     * are prime, and ideally safe prime, because a transcription slip there is a silent, total
     * break that no round-trip test can catch.
     */
    public function isProbablePrime(string $hex): bool;

    /** `value >> 1`, hex — used to derive `q = (N-1)/2` for the safe-prime assertion. */
    public function shiftRight1(string $hex): string;
}
