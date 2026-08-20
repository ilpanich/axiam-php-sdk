<?php

declare(strict_types=1);

namespace Axiam\Sdk\Opaque;

/**
 * The `libaxiam_opaque_ffi` C ABI, expressed in PHP terms.
 *
 * An interface rather than the FFI calls themselves, for one reason: it is what a test can
 * implement. CONTRACT.md §23.1 forbids this SDK from implementing OPAQUE, so there is no
 * cryptography here to test — what there is, and what a fake can exercise exhaustively, is the
 * layer above: single-use exchanges, the key-stretching function the *server* named being the one
 * used, and which failure means what.
 *
 * The methods take and return PHP strings rather than pointers. Pointer ownership — who frees a
 * returned `char *`, when a state handle is spent — is real but is entirely
 * {@see FfiOpaqueNative}'s, because it is the only implementation that has pointers at all. That
 * keeps the untestable-without-the-real-library part as small as it can be.
 *
 * A `null` return always means the library refused; {@see self::lastError()} says why.
 */
interface OpaqueNativeInterface
{
    /** Whether this build can perform OPAQUE. */
    public function available(): bool;

    /** The library's description of the last failure, or an empty string. */
    public function lastError(): string;

    /**
     * Builds an Argon2id key-stretching handle.
     *
     * @return object|int|null an opaque handle the caller passes back, or `null` when refused
     */
    public function ksfArgon2id(int $memoryKib, int $iterations, int $parallelism): mixed;

    /**
     * Builds a scrypt key-stretching handle.
     *
     * @return object|int|null an opaque handle the caller passes back, or `null` when refused
     */
    public function ksfScrypt(int $logN, int $r, int $p): mixed;

    /** Releases a key-stretching handle. */
    public function ksfFree(mixed $ksf): void;

    /**
     * Begins an enrolment.
     *
     * @return array{0: mixed, 1: string}|null the state handle and the hex `RegistrationRequest`,
     *                                         or `null` when refused
     */
    public function registrationStart(string $password): ?array;

    /**
     * Completes an enrolment, CONSUMING `$state` whether it succeeds or fails.
     *
     * @return string|null the hex `RegistrationRecord`, or `null` when refused
     */
    public function registrationFinish(
        mixed $state,
        string $password,
        string $registrationResponse,
        mixed $ksf,
    ): ?string;

    /** Releases enrolment state that was never finished. */
    public function registrationFree(mixed $state): void;

    /**
     * Begins a login.
     *
     * @return array{0: mixed, 1: string}|null the state handle and the hex `KE1`, or `null` when
     *                                         refused
     */
    public function loginStart(string $password): ?array;

    /**
     * Completes a login, CONSUMING `$state`.
     *
     * A `null` return is the whole of the client's authentication check, and it covers both halves
     * of the mutual authentication: the envelope only opens under the right password, and `KE2`'s
     * MAC only verifies if the server actually holds the record. Per CONTRACT.md §23.4 rule 7
     * nothing may be sent to `login/finish` after it.
     *
     * @return string|null the hex `KE3`, or `null`
     */
    public function loginFinish(mixed $state, string $password, string $ke2, mixed $ksf): ?string;

    /** Releases login state that was never finished. */
    public function loginFree(mixed $state): void;
}
