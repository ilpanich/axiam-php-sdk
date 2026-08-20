<?php

declare(strict_types=1);

namespace Axiam\Sdk\Srp;

use Axiam\Sdk\Core\NetworkError;

/**
 * SRP-6a protocol arithmetic (CONTRACT.md §23).
 *
 * Everything here is pure: no I/O, no client state, no network. The two HTTP calls and the policy
 * around them live in {@see \Axiam\Sdk\AxiamClient::loginSrp()}.
 *
 * `H` is **SHA-256** throughout. RFC 5054 specifies SHA-1; AXIAM does not use SHA-1 anywhere and
 * does not start here.
 *
 * The bignum work is delegated to a {@see BigIntBackend} rather than calling `gmp_*` or `bc*`
 * directly: PHP is the one AXIAM SDK language with no native arbitrary-precision integer, and
 * §23.8 makes the whole feature conditional on an extension this class must therefore not assume.
 */
final class Srp
{
    /** The wire name of the memory-hard KDF AXIAM asks for by default. */
    public const KDF_ARGON2ID = 'argon2id';

    /** The wire name of the fallback for runtimes with no vetted Argon2. */
    public const KDF_PBKDF2_SHA256 = 'pbkdf2_sha256';

    private function __construct(private readonly BigIntBackend $backend)
    {
    }

    /**
     * An instance over whichever bignum backend this runtime has, or `null` if it has neither.
     *
     * `null` rather than an exception: {@see \Axiam\Sdk\AxiamClient::srpAvailable()} has to answer
     * a question, and §23.8 requires PHP's probe to report `false` rather than throw at login time.
     */
    public static function detect(): ?self
    {
        if (GmpBackend::isAvailable()) {
            return new self(new GmpBackend());
        }
        if (BcMathBackend::isAvailable()) {
            return new self(new BcMathBackend());
        }

        return null;
    }

    /**
     * An instance over an explicitly supplied backend.
     *
     * For tests, which need to exercise each backend on a runtime that may have both, and to
     * exercise the arithmetic without depending on {@see self::detect()}'s preference order.
     */
    public static function over(BigIntBackend $backend): self
    {
        return new self($backend);
    }

    /** The backend this instance computes with. */
    public function backend(): BigIntBackend
    {
        return $this->backend;
    }

    /**
     * `PAD(v)` — a hex value rendered as exactly `$byteLength` big-endian bytes (§23.3 rule 1).
     *
     * Skipping this is the classic SRP interop bug: two implementations agree until a value happens
     * to have a leading zero byte, and then roughly one login in 256 fails in a way that reads as a
     * flaky network.
     */
    public static function pad(string $hex, int $byteLength): string
    {
        $hex = \ltrim(\strtolower($hex), '0');
        $width = $byteLength * 2;
        if (\strlen($hex) > $width) {
            // A value wider than the modulus is a caller error, not something to truncate: silently
            // dropping high bytes would produce a wrong hash that still looked well-formed.
            throw NetworkError::fromMessage('SRP: a value is wider than the group modulus');
        }

        return \str_pad($hex, $width, '0', \STR_PAD_LEFT);
    }

    /** SHA-256 over the concatenation of the raw-byte arguments, as lowercase hex. */
    public static function hash(string ...$parts): string
    {
        return \hash('sha256', \implode('', $parts));
    }

    /** `k = H(N | PAD(g))` — depends only on the group. */
    public static function multiplier(SrpGroup $group): string
    {
        return self::hash(
            self::hexToBytes(self::pad($group->modulusHex, $group->byteLength)),
            self::hexToBytes(self::pad(\dechex($group->generator), $group->byteLength)),
        );
    }

    /**
     * `x = KDF(identity ":" password, salt)`, as raw bytes (§23.3 rule 3).
     *
     * RFC 5054's bare-hash `x` would make a leaked verifier *cheaper* to attack offline than the
     * Argon2id hashes AXIAM stores today, which would make adopting SRP a net regression at rest —
     * so the KDF is memory-hard, and the server dictates which one per exchange.
     *
     * `$identity` is the one the server named in the challenge, never what the human typed
     * (§23.3 rule 2).
     *
     * @throws NetworkError if `$params->kdf` is not one this SDK implements
     */
    public static function deriveX(string $identity, string $password, string $salt, SrpKdfParams $params): string
    {
        $secret = $identity . ':' . $password;

        return match ($params->kdf) {
            self::KDF_ARGON2ID => self::argon2id(),
            self::KDF_PBKDF2_SHA256 => \hash_pbkdf2('sha256', $secret, $salt, \max(1, $params->iterations), 32, true),
            // Never substitute the other KDF: it derives a different x and surfaces as
            // "invalid password", the single most misleading failure this code could produce.
            default => throw NetworkError::fromMessage(
                "SRP: this SDK does not implement KDF '{$params->kdf}'; " .
                'it implements argon2id and pbkdf2_sha256'
            ),
        };
    }

    /**
     * Argon2id — which no PHP runtime can compute interoperably, and this SDK refuses rather than
     * approximates.
     *
     * The reason is a hard interface mismatch, not a missing library. §23.5's SRP salt is **32
     * bytes**; libsodium's `sodium_crypto_pwhash` — the only Argon2id in PHP that accepts a
     * caller-supplied salt at all — requires exactly `SODIUM_CRYPTO_PWHASH_SALTBYTES`, which is
     * **16**. `password_hash(PASSWORD_ARGON2ID)` is worse: it generates its own salt and never
     * accepts one. Folding 32 bytes into 16 would produce a perfectly well-formed `x` that no
     * other AXIAM SDK and no AXIAM server agrees with, and the user would be told their password
     * is wrong — the single most misleading failure available here, and precisely what §23.3
     * rule 4 forbids when it says an SDK MUST NOT substitute.
     *
     * So this raises {@see NetworkError} naming the KDF, exactly as rule 4 requires of a KDF an
     * SDK cannot perform. A tenant that wants PHP clients on SRP configures `pbkdf2_sha256`; the
     * README says so, and this is the second half of §23.8's "conditional" posture for PHP.
     *
     * @throws NetworkError always
     */
    private static function argon2id(): string
    {
        throw NetworkError::fromMessage(
            "SRP: this SDK does not implement KDF 'argon2id'. No PHP runtime offers Argon2id with " .
            'a caller-supplied 32-byte salt — libsodium requires exactly 16 bytes and ' .
            'password_hash() generates its own — and deriving x from a folded salt would produce a ' .
            'value no AXIAM server agrees with. Configure the tenant for pbkdf2_sha256.'
        );
    }

    /** `v = g^x mod N` — the verifier the server stores instead of a password hash. */
    public function computeVerifier(SrpGroup $group, string $x): string
    {
        $reduced = $this->backend->mod(\bin2hex($x), $group->modulusHex);

        return self::pad(
            $this->backend->modPow(\dechex($group->generator), $reduced, $group->modulusHex),
            $group->byteLength,
        );
    }

    /**
     * 32 fresh bytes from the platform CSPRNG, for an enrolment salt (§23.3 rule 11).
     *
     * A reused salt would make every verifier in a tenant equally attackable with one
     * precomputation.
     */
    public static function generateSalt(): string
    {
        return \random_bytes(32);
    }

    /**
     * Constant-time comparison of the server's `M2` against the expected one (§23.3 rule 6).
     */
    public static function verifyServerProof(string $expected, ?string $actual): bool
    {
        if ($actual === null || \strlen($actual) !== \strlen($expected)) {
            return false;
        }

        return \hash_equals(\strtolower($expected), \strtolower($actual));
    }

    /**
     * Decodes a lowercase-hex wire field to raw bytes.
     *
     * @throws NetworkError if `$hex` is not valid hex
     */
    public static function hexToBytes(string $hex, string $field = 'value'): string
    {
        $bytes = \strlen($hex) % 2 === 0 ? @\hex2bin($hex) : false;
        if ($bytes === false) {
            throw NetworkError::fromMessage("SRP: the server's {$field} is not valid hex");
        }

        return $bytes;
    }
}
