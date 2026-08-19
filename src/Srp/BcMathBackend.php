<?php

declare(strict_types=1);

namespace Axiam\Sdk\Srp;

/**
 * {@see BigIntBackend} over `ext-bcmath` — the fallback when `ext-gmp` is absent.
 *
 * bcmath works in **decimal strings**, so every value crossing the {@see BigIntBackend} boundary is
 * converted at the edge. That conversion is written out here rather than delegated to
 * `base_convert` or `hexdec`, both of which silently lose precision above 2^53 — a bug that would
 * not show up until a value happened to exceed it, which for a 4096-bit modulus is always.
 *
 * This backend is materially slower than {@see GmpBackend}: `bcpowmod` at 4096 bits is on the
 * order of seconds rather than milliseconds. It exists so that a runtime with only `ext-bcmath`
 * can still perform SRP, not because it is a good place to be.
 */
final class BcMathBackend implements BigIntBackend
{
    /** Whether `ext-bcmath` is loaded in this runtime. */
    public static function isAvailable(): bool
    {
        return \extension_loaded('bcmath');
    }

    /** {@inheritDoc} */
    public function name(): string
    {
        return 'bcmath';
    }

    /** {@inheritDoc} */
    public function modPow(string $baseHex, string $exponentHex, string $modulusHex): string
    {
        return $this->toHex(
            \bcpowmod($this->toDec($baseHex), $this->toDec($exponentHex), $this->toDec($modulusHex))
        );
    }

    /** {@inheritDoc} */
    public function mulMod(string $aHex, string $bHex, string $modulusHex): string
    {
        $modulus = $this->toDec($modulusHex);

        return $this->toHex($this->positiveMod(\bcmul($this->toDec($aHex), $this->toDec($bHex)), $modulus));
    }

    /** {@inheritDoc} */
    public function addMod(string $aHex, string $bHex, string $modulusHex): string
    {
        $modulus = $this->toDec($modulusHex);

        return $this->toHex($this->positiveMod(\bcadd($this->toDec($aHex), $this->toDec($bHex)), $modulus));
    }

    /** {@inheritDoc} */
    public function mul(string $aHex, string $bHex): string
    {
        return $this->toHex(\bcmul($this->toDec($aHex), $this->toDec($bHex)));
    }

    /** {@inheritDoc} */
    public function add(string $aHex, string $bHex): string
    {
        return $this->toHex(\bcadd($this->toDec($aHex), $this->toDec($bHex)));
    }

    /** {@inheritDoc} */
    public function subMod(string $aHex, string $bHex, string $modulusHex): string
    {
        $modulus = $this->toDec($modulusHex);

        return $this->toHex($this->positiveMod(\bcsub($this->toDec($aHex), $this->toDec($bHex)), $modulus));
    }

    /** {@inheritDoc} */
    public function mod(string $aHex, string $modulusHex): string
    {
        return $this->toHex($this->positiveMod($this->toDec($aHex), $this->toDec($modulusHex)));
    }

    /** {@inheritDoc} */
    public function isZero(string $hex): bool
    {
        return \bccomp($this->toDec($hex), '0') === 0;
    }

    /** {@inheritDoc} */
    public function bitLength(string $hex): int
    {
        $trimmed = \ltrim($hex, '0');
        if ($trimmed === '') {
            return 0;
        }
        // Every hex digit after the first contributes exactly 4 bits; the first contributes
        // however many its value needs.
        $leading = (int) \hexdec($trimmed[0]);
        $bitsInLeading = 0;
        while ($leading > 0) {
            ++$bitsInLeading;
            $leading >>= 1;
        }

        return $bitsInLeading + (\strlen($trimmed) - 1) * 4;
    }

    /** {@inheritDoc} */
    public function isProbablePrime(string $hex): bool
    {
        // Miller-Rabin with fixed bases. Deterministic, and at these widths the fixed base set is
        // as strong in practice as a random one — the only caller is the test suite's §23.4
        // group-constant assertion, which needs a definite answer rather than a fast one.
        $n = $this->toDec($hex);
        if (\bccomp($n, '2') < 0) {
            return false;
        }
        $bases = ['2', '3', '5', '7', '11', '13', '17', '19', '23', '29', '31', '37'];
        foreach ($bases as $base) {
            if (\bccomp($n, $base) === 0) {
                return true;
            }
            if (\bccomp(\bcmod($n, $base), '0') === 0) {
                return false;
            }
        }

        $d = \bcsub($n, '1');
        $r = 0;
        while (\bccomp(\bcmod($d, '2'), '0') === 0) {
            $d = \bcdiv($d, '2', 0);
            ++$r;
        }
        $nMinusOne = \bcsub($n, '1');

        foreach ($bases as $base) {
            $x = \bcpowmod($base, $d, $n);
            if (\bccomp($x, '1') === 0 || \bccomp($x, $nMinusOne) === 0) {
                continue;
            }
            $passed = false;
            for ($i = 1; $i < $r; ++$i) {
                $x = \bcpowmod($x, '2', $n);
                if (\bccomp($x, $nMinusOne) === 0) {
                    $passed = true;
                    break;
                }
            }
            if (!$passed) {
                return false;
            }
        }

        return true;
    }

    /** {@inheritDoc} */
    public function shiftRight1(string $hex): string
    {
        return $this->toHex(\bcdiv($this->toDec($hex), '2', 0));
    }

    /** bcmod's sign follows the dividend; every caller here needs the non-negative representative. */
    private function positiveMod(string $value, string $modulus): string
    {
        $result = \bcmod($value, $modulus);

        return \bccomp($result, '0') < 0 ? \bcadd($result, $modulus) : $result;
    }

    /** Hex to a decimal string, digit by digit — never via hexdec, which caps at 2^53. */
    private function toDec(string $hex): string
    {
        $hex = \ltrim($hex, '0');
        if ($hex === '') {
            return '0';
        }
        $result = '0';
        foreach (\str_split(\strtolower($hex)) as $digit) {
            $result = \bcadd(\bcmul($result, '16'), (string) \hexdec($digit));
        }

        return $result;
    }

    /** Decimal string back to lowercase hex, digit by digit — never via dechex. */
    private function toHex(string $dec): string
    {
        if (\bccomp($dec, '0') === 0) {
            return '0';
        }
        $digits = '';
        while (\bccomp($dec, '0') > 0) {
            $digits = \dechex((int) \bcmod($dec, '16')) . $digits;
            $dec = \bcdiv($dec, '16', 0);
        }

        return $digits;
    }
}
