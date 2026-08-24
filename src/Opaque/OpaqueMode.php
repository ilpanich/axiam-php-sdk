<?php

declare(strict_types=1);

namespace Axiam\Sdk\Opaque;

/**
 * The tenant's `opaque_mode`, as `login/start` reports it (CONTRACT.md §23.4 rule 7, §23.5).
 *
 * The field is **optional on the wire** and this type is built to tolerate its absence: a server
 * older than contract 1.29 answers without it, and reading that as anything other than "unknown"
 * would change what an SDK does against a server that never said anything.
 *
 * It carries `"optional"` or `"required"` and never `"disabled"` — a disabled tenant answers
 * `404` and never reaches this type at all.
 *
 * **This is not downgrade protection, and must not be described as one.** A hostile endpoint that
 * wanted the plaintext password could simply answer `404`, which sends a caller to `login()`
 * whatever it would have put here. What closes that is the server: `required` refuses
 * `/auth/login` with `403 opaque_required` for every principal in the tenant, before any
 * credential is examined. The field exists for one reason only — to tell a mid-migration tenant
 * (`optional`, where an account with no registration record is the ordinary case) apart from one
 * where a failed exchange is final.
 */
final class OpaqueMode
{
    /** Both login paths work; records accumulate as passwords are set. The migration state. */
    public const OPTIONAL = 'optional';

    /** `/auth/login` answers `403 opaque_required` for every principal in the tenant. */
    public const REQUIRED = 'required';

    /**
     * Holds the value exactly as the server named it, or `null` when the response carried no
     * `mode` at all.
     */
    private function __construct(
        /** The wire value, or `null` for a server older than the field. */
        public readonly ?string $value,
    ) {
    }

    /**
     * Reads the optional `mode` field of a `/start` response, preserving absence.
     *
     * Anything that is not a string — absent, `null`, a number, an object — becomes `null`, which
     * {@see self::allowsPasswordFallback()} treats exactly as `required`.
     *
     * @param array<string, mixed> $wire the decoded response body
     */
    public static function fromWire(array $wire): self
    {
        $value = $wire['mode'] ?? null;

        return new self(\is_string($value) ? $value : null);
    }

    /**
     * Whether a failed `KE2` may be retried over `POST /api/v1/auth/login` (§23.4 rule 7).
     *
     * True for `optional` and **nothing else** — an unrecognised value and an absent field both
     * fail closed. Under `optional` a failed exchange is the ordinary case rather than an error:
     * every account has no registration record the moment an operator enables OPAQUE and acquires
     * one only when its password is next set, so an SDK that treated the failure as final would
     * lock out every user of a tenant mid-migration. Under `required` the retry would be refused
     * anyway, and would have put a plaintext password on the wire for nothing.
     */
    public function allowsPasswordFallback(): bool
    {
        return $this->value === self::OPTIONAL;
    }
}
