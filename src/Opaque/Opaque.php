<?php

declare(strict_types=1);

namespace Axiam\Sdk\Opaque;

use Axiam\Sdk\Core\NetworkError;

/**
 * Entry points into `libaxiam_opaque_ffi` (CONTRACT.md §23).
 *
 * There is no cryptography in this class, or anywhere in this package. That is deliberate and is
 * what §23.1 requires: OPAQUE needs an oblivious PRF, `hash_to_curve`, `expand_message_xmd`, an
 * envelope construction and a three-message AKE, and eleven independent implementations of that
 * is eleven chances to be subtly and silently wrong. The SRP-6a this replaces was arithmetic
 * every language can express — which in PHP meant 800-odd lines across two bignum backends, and
 * a `pbkdf2_sha256`-only limitation on top.
 */
final class Opaque
{
    private function __construct()
    {
    }

    /**
     * Whether this installation can perform OPAQUE (§23.2).
     *
     * Reports rather than throwing. PHP was already the one AXIAM SDK language where the SRP
     * equivalent genuinely answered `false`; it still can, for a different and simpler reason —
     * `ext-ffi` or the shared library is absent, rather than a missing bignum.
     */
    public static function available(): bool
    {
        return OpaqueLibrary::load() !== null;
    }

    /**
     * Blinds `$password` to open an enrolment.
     *
     * @throws NetworkError if the library is unavailable or refuses
     */
    public static function startRegistration(string $password): RegistrationExchange
    {
        $lib = OpaqueLibrary::require();
        $started = $lib->registrationStart($password);
        if ($started === null) {
            throw NetworkError::fromMessage(
                'OPAQUE: ' . self::lastError($lib, 'registration could not be started')
            );
        }

        [$handle, $request] = $started;

        return new RegistrationExchange($lib, $handle, $request);
    }

    /**
     * Blinds `$password` to open a login.
     *
     * @throws NetworkError if the library is unavailable or refuses
     */
    public static function startLogin(string $password): LoginExchange
    {
        $lib = OpaqueLibrary::require();
        $started = $lib->loginStart($password);
        if ($started === null) {
            throw NetworkError::fromMessage(
                'OPAQUE: ' . self::lastError($lib, 'login could not be started')
            );
        }

        [$handle, $ke1] = $started;

        return new LoginExchange($lib, $handle, $ke1);
    }

    /**
     * The library's description of the last failure, or `$fallback`.
     *
     * A failure with nothing behind it is a library bug, but a caller still deserves a sentence
     * rather than an empty one.
     */
    public static function lastError(OpaqueNativeInterface $lib, string $fallback): string
    {
        $message = $lib->lastError();

        return $message === '' ? $fallback : $message;
    }
}
