<?php

declare(strict_types=1);

namespace Axiam\Sdk\Srp;

/**
 * {@see BigIntBackend} over `ext-gmp` — the preferred backend.
 *
 * GMP's `gmp_powm` is a native modular exponentiation and is roughly two orders of magnitude
 * faster than the `ext-bcmath` fallback at 4096 bits, which is the difference between an SRP login
 * that costs milliseconds of arithmetic and one that costs seconds.
 */
final class GmpBackend implements BigIntBackend
{
    /** Whether `ext-gmp` is loaded in this runtime. */
    public static function isAvailable(): bool
    {
        return \extension_loaded('gmp');
    }

    /** {@inheritDoc} */
    public function name(): string
    {
        return 'gmp';
    }

    /** {@inheritDoc} */
    public function modPow(string $baseHex, string $exponentHex, string $modulusHex): string
    {
        return $this->toHex(\gmp_powm($this->of($baseHex), $this->of($exponentHex), $this->of($modulusHex)));
    }

    /** {@inheritDoc} */
    public function mulMod(string $aHex, string $bHex, string $modulusHex): string
    {
        return $this->toHex(\gmp_mod(\gmp_mul($this->of($aHex), $this->of($bHex)), $this->of($modulusHex)));
    }

    /** {@inheritDoc} */
    public function addMod(string $aHex, string $bHex, string $modulusHex): string
    {
        return $this->toHex(\gmp_mod(\gmp_add($this->of($aHex), $this->of($bHex)), $this->of($modulusHex)));
    }

    /** {@inheritDoc} */
    public function mul(string $aHex, string $bHex): string
    {
        return $this->toHex(\gmp_mul($this->of($aHex), $this->of($bHex)));
    }

    /** {@inheritDoc} */
    public function add(string $aHex, string $bHex): string
    {
        return $this->toHex(\gmp_add($this->of($aHex), $this->of($bHex)));
    }

    /** {@inheritDoc} */
    public function subMod(string $aHex, string $bHex, string $modulusHex): string
    {
        // gmp_mod always returns a non-negative result for a positive modulus, which is exactly
        // the guarantee BigIntBackend::subMod() states.
        return $this->toHex(\gmp_mod(\gmp_sub($this->of($aHex), $this->of($bHex)), $this->of($modulusHex)));
    }

    /** {@inheritDoc} */
    public function mod(string $aHex, string $modulusHex): string
    {
        return $this->toHex(\gmp_mod($this->of($aHex), $this->of($modulusHex)));
    }

    /** {@inheritDoc} */
    public function isZero(string $hex): bool
    {
        return \gmp_sign($this->of($hex)) === 0;
    }

    /** {@inheritDoc} */
    public function bitLength(string $hex): int
    {
        $value = $this->of($hex);

        return \gmp_sign($value) === 0 ? 0 : \strlen(\gmp_strval($value, 2));
    }

    /** {@inheritDoc} */
    public function isProbablePrime(string $hex): bool
    {
        return \gmp_prob_prime($this->of($hex), 40) !== 0;
    }

    /** {@inheritDoc} */
    public function shiftRight1(string $hex): string
    {
        return $this->toHex(\gmp_div_q($this->of($hex), 2));
    }

    private function of(string $hex): \GMP
    {
        // An empty string is a legitimate encoding of zero on this boundary; gmp_init rejects it.
        return \gmp_init($hex === '' ? '0' : $hex, 16);
    }

    private function toHex(\GMP $value): string
    {
        return \gmp_strval($value, 16);
    }
}
