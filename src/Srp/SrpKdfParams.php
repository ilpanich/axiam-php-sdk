<?php

declare(strict_types=1);

namespace Axiam\Sdk\Srp;

/**
 * The KDF and cost the server dictates for one SRP exchange (CONTRACT.md §23.5).
 *
 * §23.3 rule 4: these arrive per exchange and are honoured as given. They are deliberately **not**
 * cached across logins — a verifier enrolled under different costs is still valid and has to keep
 * working.
 */
final class SrpKdfParams
{
    public function __construct(
        /** `argon2id` or `pbkdf2_sha256`. */
        public readonly string $kdf,
        /** Argon2id's time cost, or PBKDF2's iteration count. */
        public readonly int $iterations,
        /** Argon2id's memory cost in KiB; ignored for PBKDF2. */
        public readonly int $memoryKib = 0,
        /** Argon2id's lane count; ignored for PBKDF2. */
        public readonly int $parallelism = 0,
    ) {
    }

    /**
     * Reads the KDF fields of a challenge response.
     *
     * `memory_kib` and `parallelism` are present only for `argon2id`, so their absence is normal
     * rather than an error.
     *
     * @param array<string,mixed> $challenge the decoded challenge response body
     */
    public static function fromChallenge(array $challenge): self
    {
        return new self(
            \is_string($challenge['kdf'] ?? null) ? $challenge['kdf'] : '',
            (int) ($challenge['iterations'] ?? 0),
            (int) ($challenge['memory_kib'] ?? 0),
            (int) ($challenge['parallelism'] ?? 0),
        );
    }

    /**
     * This instance with any zero cost replaced by AXIAM's default for the chosen KDF.
     *
     * Used on the enrolment path, where the caller may know only which KDF the tenant runs. It is
     * never applied to a challenge response: a server that omits a cost it is required to send is a
     * server this SDK should not be guessing on behalf of.
     */
    public function withDefaults(): self
    {
        $kdf = $this->kdf === '' ? Srp::KDF_ARGON2ID : $this->kdf;
        if ($kdf === Srp::KDF_PBKDF2_SHA256) {
            return new self($kdf, $this->iterations > 0 ? $this->iterations : 600000);
        }

        return new self(
            $kdf,
            $this->iterations > 0 ? $this->iterations : 2,
            $this->memoryKib > 0 ? $this->memoryKib : 19456,
            $this->parallelism > 0 ? $this->parallelism : 1,
        );
    }
}
