<?php

declare(strict_types=1);

namespace Axiam\Sdk\Opaque;

use Axiam\Sdk\Core\NetworkError;

/**
 * The key-stretching function and cost a `/start` response names (CONTRACT.md §23.4).
 *
 * The cost properties are nullable on purpose: they arrive flat, and a field that does not apply
 * to the named function is **absent, not zero**. Reading a missing `memoryKib` as `0` would
 * stretch at the wrong cost and fail against a record that is perfectly good (§23.4 rule 5).
 *
 * These are never cached across exchanges and never defaulted locally. A credential enrolled
 * under one cost keeps working after a tenant raises its policy, so a client that guessed would
 * derive a different randomized password and report "invalid password" for one that is entirely
 * correct (§23.4 rule 2).
 *
 * **This is where PHP stopped being doubly conditional.** The SRP client it replaces needed a
 * bignum extension *and* a tenant on `pbkdf2_sha256`, because no PHP runtime offers Argon2id with
 * a caller-supplied salt. The key stretching now happens inside `libaxiam_opaque_ffi`, so an
 * `argon2id` tenant is no longer a PHP-shaped hole.
 */
final class KsfParams
{
    /** The wire name of the memory-hard function AXIAM asks for by default. */
    public const ARGON2ID = 'argon2id';

    /** The wire name of the alternative AXIAM accepts. */
    public const SCRYPT = 'scrypt';

    /**
     * The bands this SDK will act on, per field.
     *
     * A server is trusted to name its own policy, not to name a cost that would wedge every
     * device an account owns. The library range-checks too; doing it here as well means the
     * refusal names the field.
     *
     * @var array<string, array{0: int, 1: int}>
     */
    private const BOUNDS = [
        'memory_kib' => [8192, 1048576],
        'iterations' => [1, 10],
        'parallelism' => [1, 16],
        'log_n' => [14, 20],
        'r' => [1, 16],
        'p' => [1, 16],
    ];

    /**
     * Every field exactly as the server named it — no local defaults, no coercion of an absent
     * cost to zero.
     */
    public function __construct(
        /** The wire name of the function: `argon2id` or `scrypt`. */
        public readonly string $ksf,
        /** Argon2id's memory cost in KiB. */
        public readonly ?int $memoryKib = null,
        /** Argon2id's time cost. */
        public readonly ?int $iterations = null,
        /** Argon2id's lane count. */
        public readonly ?int $parallelism = null,
        /** scrypt's base-2 CPU/memory cost. */
        public readonly ?int $logN = null,
        /** scrypt's block size. */
        public readonly ?int $r = null,
        /** scrypt's parallelisation parameter. */
        public readonly ?int $p = null,
    ) {
    }

    /**
     * Reads the flat key-stretching fields of a `/start` response, preserving absence.
     *
     * @param array<string, mixed> $wire the decoded response body
     */
    public static function fromWire(array $wire): self
    {
        return new self(
            \is_string($wire['ksf'] ?? null) ? $wire['ksf'] : '',
            self::optional($wire, 'memory_kib'),
            self::optional($wire, 'iterations'),
            self::optional($wire, 'parallelism'),
            self::optional($wire, 'log_n'),
            self::optional($wire, 'r'),
            self::optional($wire, 'p'),
        );
    }

    /** @param array<string, mixed> $wire */
    private static function optional(array $wire, string $field): ?int
    {
        $value = $wire[$field] ?? null;
        if ($value === null) {
            return null;
        }

        return \is_numeric($value) ? (int) $value : null;
    }

    /**
     * Builds the library's key-stretching handle from what the *server* named.
     *
     * An unrecognised function is refused, never substituted: substituting produces a well-formed
     * randomized password no AXIAM server agrees with, which surfaces to the user as a wrong
     * password (§23.4 rule 3). The returned handle must be released with `ksfFree`.
     *
     * @throws NetworkError if a cost is missing, out of range, or the function is one this SDK
     *                      cannot ask for
     */
    public function build(OpaqueNativeInterface $lib): mixed
    {
        $handle = match ($this->ksf) {
            self::ARGON2ID => $lib->ksfArgon2id(
                $this->require('memory_kib', $this->memoryKib),
                $this->require('iterations', $this->iterations),
                $this->require('parallelism', $this->parallelism),
            ),
            self::SCRYPT => $lib->ksfScrypt(
                $this->require('log_n', $this->logN),
                $this->require('r', $this->r),
                $this->require('p', $this->p),
            ),
            default => throw NetworkError::fromMessage(
                'OPAQUE: this SDK cannot perform the key-stretching function the server named ' .
                "(`{$this->ksf}`)"
            ),
        };

        if ($handle === null) {
            throw NetworkError::fromMessage(
                'OPAQUE: ' . Opaque::lastError($lib, 'invalid KSF parameters')
            );
        }

        return $handle;
    }

    /** One cost the named function needs: present, and inside the band this SDK will act on. */
    private function require(string $field, ?int $value): int
    {
        if ($value === null) {
            throw NetworkError::fromMessage(
                "OPAQUE: the server named ksf `{$this->ksf}` without `{$field}`"
            );
        }

        [$low, $high] = self::BOUNDS[$field];
        if ($value < $low || $value > $high) {
            throw NetworkError::fromMessage(
                "OPAQUE: the server named {$field}={$value} for `{$this->ksf}`, outside the " .
                "accepted {$low}..{$high}"
            );
        }

        return $value;
    }
}
