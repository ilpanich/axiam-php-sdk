<?php

declare(strict_types=1);

namespace Axiam\Sdk\Opaque;

use FFI;

/**
 * The real FFI binding to `libaxiam_opaque_ffi`.
 *
 * Deliberately the thinnest layer in this package. Everything above it — exchange lifecycle,
 * key-stretching selection, error mapping — lives in classes a test can drive against a fake
 * {@see OpaqueNativeInterface}. What is here needs the actual shared library to exercise, so
 * there is as little of it as the job allows, and the two rules it has to get right are stated
 * where they are implemented:
 *
 *  1. **Every `char *` the library returns is Rust-allocated and must be freed exactly once.**
 *     {@see self::take()} copies it into a PHP string and frees it, on every path including the
 *     failure ones — a binding that freed only on success would leak once per failed login,
 *     which is the login rate an installation under attack sees.
 *  2. **A state handle is consumed by its `finish`, success or failure.** This class does not
 *     free one afterwards; {@see OpaqueExchange} is what guarantees it is never used twice.
 */
final class FfiOpaqueNative implements OpaqueNativeInterface
{
    /**
     * The subset of `include/axiam/opaque.h` this SDK calls.
     *
     * Declared inline rather than read from the header file: FFI's parser accepts a small C
     * subset, and shipping a copy of the real header would invite someone to update one and not
     * the other. The opaque struct types are `void *` here because PHP never dereferences them.
     */
    private const CDEF = <<<'C'
        void axiam_opaque_string_free(char *ptr);
        const char *axiam_opaque_last_error(void);
        int32_t axiam_opaque_available(void);
        void *axiam_opaque_ksf_argon2id(uint32_t memory_kib, uint32_t iterations, uint32_t parallelism);
        void *axiam_opaque_ksf_scrypt(uint8_t log_n, uint32_t r, uint32_t p);
        void axiam_opaque_ksf_free(void *ptr);
        void *axiam_opaque_registration_start(const char *password, char **out_request);
        char *axiam_opaque_registration_finish(void *state, const char *password, const char *registration_response, const void *ksf, char **out_export_key);
        void axiam_opaque_registration_free(void *ptr);
        void *axiam_opaque_login_start(const char *password, char **out_ke1);
        char *axiam_opaque_login_finish(void *state, const char *password, const char *ke2, const void *ksf, char **out_session_key, char **out_export_key);
        void axiam_opaque_login_free(void *ptr);
        C;

    private function __construct(private readonly FFI $ffi)
    {
    }

    /**
     * Binds the library at `$path`, or returns `null` when it cannot be loaded.
     *
     * Reports rather than throwing because absence is normal: `ext-ffi` is optional and the
     * library is a per-platform release asset, not a Composer package.
     */
    public static function open(string $path): ?self
    {
        if (!\extension_loaded('ffi')) {
            return null;
        }

        try {
            /** @var FFI $ffi */
            $ffi = FFI::cdef(self::CDEF, $path);
        } catch (\FFI\Exception|\Throwable) {
            // Not found, wrong architecture, or a different library of the same
            // name missing our symbols. All three are "absent" as far as a
            // caller is concerned, and none is worth retrying.
            return null;
        }

        return new self($ffi);
    }

    public function available(): bool
    {
        try {
            return $this->ffi->axiam_opaque_available() !== 0;
        } catch (\Throwable) {
            // FFI resolves a symbol lazily on first call, so this is where a
            // same-named library missing our exports actually shows up.
            return false;
        }
    }

    public function lastError(): string
    {
        $raw = $this->ffi->axiam_opaque_last_error();
        if ($raw === null) {
            return '';
        }

        // Borrowed, not owned: library-allocated and NOT freed here.
        return FFI::string($raw);
    }

    public function ksfArgon2id(int $memoryKib, int $iterations, int $parallelism): mixed
    {
        return $this->ffi->axiam_opaque_ksf_argon2id($memoryKib, $iterations, $parallelism);
    }

    public function ksfScrypt(int $logN, int $r, int $p): mixed
    {
        return $this->ffi->axiam_opaque_ksf_scrypt($logN, $r, $p);
    }

    public function ksfFree(mixed $ksf): void
    {
        $this->ffi->axiam_opaque_ksf_free($ksf);
    }

    public function registrationStart(string $password): ?array
    {
        $out = $this->ffi->new('char *[1]');
        $state = $this->ffi->axiam_opaque_registration_start($password, $out);
        if ($state === null) {
            return null;
        }

        return [$state, $this->take($out[0])];
    }

    public function registrationFinish(
        mixed $state,
        string $password,
        string $registrationResponse,
        mixed $ksf,
    ): ?string {
        $record = $this->ffi->axiam_opaque_registration_finish(
            $state,
            $password,
            $registrationResponse,
            $ksf,
            null,
        );

        return $record === null ? null : $this->take($record);
    }

    public function registrationFree(mixed $state): void
    {
        $this->ffi->axiam_opaque_registration_free($state);
    }

    public function loginStart(string $password): ?array
    {
        $out = $this->ffi->new('char *[1]');
        $state = $this->ffi->axiam_opaque_login_start($password, $out);
        if ($state === null) {
            return null;
        }

        return [$state, $this->take($out[0])];
    }

    public function loginFinish(mixed $state, string $password, string $ke2, mixed $ksf): ?string
    {
        $ke3 = $this->ffi->axiam_opaque_login_finish($state, $password, $ke2, $ksf, null, null);

        return $ke3 === null ? null : $this->take($ke3);
    }

    public function loginFree(mixed $state): void
    {
        $this->ffi->axiam_opaque_login_free($state);
    }

    /**
     * Copies a returned string into PHP and frees the Rust allocation.
     *
     * `FFI::string()` copies, so the PHP value outlives the free. Doing the free in the same
     * expression that reads the value is what makes "exactly once" true by construction rather
     * than by every caller remembering.
     */
    private function take(mixed $ptr): string
    {
        try {
            return FFI::string($ptr);
        } finally {
            $this->ffi->axiam_opaque_string_free($ptr);
        }
    }
}
