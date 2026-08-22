<?php

declare(strict_types=1);

namespace Axiam\Sdk\Webauthn;

use Axiam\Sdk\Core\Sensitive;

/**
 * A started ceremony: the server's options plus the token binding a response to them
 * (CONTRACT.md §24.1).
 */
final readonly class WebauthnChallenge
{
    /**
     * @param array<string,mixed> $challenge The server's options, exactly as they arrived — a
     *   `{"publicKey": {…}}` object carrying base64url buffers. Hand it to the authenticator
     *   **unchanged** (§24.0), or call {@see self::requestJson()} for the string a platform API
     *   takes.
     * @param Sensitive $stateToken Binds the authenticator's answer to this challenge. A bearer
     *   credential for the length of the ceremony — one that leaks inside that window is a
     *   ceremony an attacker can try to complete — so it is {@see Sensitive} (§24.5). It is
     *   **opaque**: this SDK never decodes it, and neither should a caller.
     */
    public function __construct(
        public array $challenge,
        public Sensitive $stateToken,
    ) {
    }

    /**
     * The challenge in the JSON form every platform authenticator API takes (§24.6a rule 1).
     *
     * This is the string a browser passes to `PublicKeyCredential.parseCreationOptionsFromJSON()`
     * and an Android app passes to `CreatePublicKeyCredentialRequest`. It is the inner options
     * object: the `publicKey` wrapper belongs to the DOM's `CredentialCreationOptions`, and the
     * platform JSON APIs do not want it.
     *
     * Pure local computation, no I/O. Nothing is defaulted, dropped or reordered on the way
     * through (§24.0).
     */
    public function requestJson(): string
    {
        $options = $this->challenge['publicKey'] ?? $this->challenge;

        return json_encode($options, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}
