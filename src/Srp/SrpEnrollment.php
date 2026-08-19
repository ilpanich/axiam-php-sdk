<?php

declare(strict_types=1);

namespace Axiam\Sdk\Srp;

/**
 * The `srp` object CONTRACT.md §23.5 defines: a verifier and the parameters it was computed under.
 *
 * The server cannot compute this — it never sees the plaintext — so any request that **sets** a
 * password has to carry it: `POST /api/v1/users`, `/auth/password/change`,
 * `/auth/reset/confirm` and `/admin/bootstrap` (§23.3 rule 11).
 *
 * Neither {@see self::$salt} nor {@see self::$verifier} may be logged (§23.3 rule 12).
 */
final class SrpEnrollment
{
    public function __construct(
        /** The wire group name the verifier lives in. */
        public readonly string $group,
        /** The KDF used to derive `x`. */
        public readonly string $kdf,
        /** Argon2id's memory cost, or `0` for PBKDF2. */
        public readonly int $memoryKib,
        /** The KDF's iteration/time cost. */
        public readonly int $iterations,
        /** Argon2id's lane count, or `0` for PBKDF2. */
        public readonly int $parallelism,
        /** The 32-byte enrolment salt, lowercase hex. */
        public readonly string $salt,
        /** `v = g^x mod N`, lowercase hex. */
        public readonly string $verifier,
    ) {
    }

    /**
     * This enrolment as the JSON-ready array the password-setting endpoints accept.
     *
     * @return array<string,string|int>
     */
    public function toArray(): array
    {
        $out = ['group' => $this->group, 'kdf' => $this->kdf];
        if ($this->memoryKib > 0) {
            $out['memory_kib'] = $this->memoryKib;
        }
        $out['iterations'] = $this->iterations;
        if ($this->parallelism > 0) {
            $out['parallelism'] = $this->parallelism;
        }
        $out['salt'] = $this->salt;
        $out['verifier'] = $this->verifier;

        return $out;
    }
}
