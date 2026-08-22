<?php

declare(strict_types=1);

namespace Axiam\Sdk\Webauthn;

/**
 * A credential the user just enrolled — the `201` body of `register/finish`
 * (CONTRACT.md §24.1).
 */
final readonly class WebauthnCredential
{
    /**
     * @param string      $id             This credential's AXIAM id, for a later delete.
     * @param string      $credentialId   The authenticator's own base64url credential id.
     * @param string      $name           The label it was stored under.
     * @param string      $credentialType `passkey` or `security_key`, as the server classified it.
     * @param string      $createdAt      RFC 3339 timestamp.
     * @param string|null $lastUsedAt     RFC 3339 timestamp, or `null` for a credential never used.
     */
    public function __construct(
        public string $id,
        public string $credentialId,
        public string $name,
        public string $credentialType,
        public string $createdAt,
        public ?string $lastUsedAt = null,
    ) {
    }
}
