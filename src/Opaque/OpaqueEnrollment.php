<?php

declare(strict_types=1);

namespace Axiam\Sdk\Opaque;

/**
 * The `opaque` object CONTRACT.md §23 defines: a registration record and the server-issued
 * session handle that identifies the exchange it came from.
 *
 * The server cannot build this — it never sees the plaintext — so any request that **sets** a
 * password has to carry it: `POST /api/v1/users`, `/auth/password/change`,
 * `/auth/reset/confirm` and `/admin/bootstrap`.
 *
 * Note what is *not* here. The SRP enrolment this replaces carried a salt, a group and a full set
 * of KDF costs, and required the account's canonical username — passing an email produced a
 * verifier no login could ever satisfy, and renaming a user invalidated their verifier outright.
 * A record binds to a credential identifier the server chooses, and the key-stretching parameters
 * are the server's, so there is nothing here a caller can get wrong.
 */
final class OpaqueEnrollment
{
    public function __construct(
        /** The handle `register/start` issued. */
        public readonly string $opaqueSession,
        /** The hex `RegistrationRecord`. */
        public readonly string $registrationRecord,
    ) {
    }

    /**
     * This enrolment as the array the password-setting endpoints accept as their `opaque` member.
     *
     * @return array{opaque_session: string, registration_record: string}
     */
    public function toWire(): array
    {
        return [
            'opaque_session' => $this->opaqueSession,
            'registration_record' => $this->registrationRecord,
        ];
    }
}
