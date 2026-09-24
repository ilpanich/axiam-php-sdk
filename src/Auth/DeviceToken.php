<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

use Axiam\Sdk\Core\Sensitive;

/**
 * The result of `AxiamClient::authenticateDevice()` — the mTLS device login
 * (CONTRACT.md §6.1 rules 6-10, contract 1.51).
 *
 * A readonly DTO, mirroring {@see LoginResult}'s and {@see UserInfo}'s own shape (D-09:
 * a typed record, never a raw array/stdClass).
 *
 * **There is no refresh token** (§6.1 rule 6, server decision D-6 of the dogfooding
 * remediation plan). A device re-authenticates by calling `authenticateDevice()` again,
 * which costs one TLS handshake — the SDK's §9 single-flight refresh guard has nothing
 * to spend on this credential, and never tries.
 */
final class DeviceToken
{
    /**
     * @param Sensitive $accessToken The service-account access token this device now
     *                                holds. Certificate-bound when AXIAM itself
     *                                terminated the TLS handshake (§6.1 rule 9) — a
     *                                REST request without the same certificate, or a
     *                                gRPC call on a listener not requesting client
     *                                certificates, is refused.
     * @param string    $tokenType    Always `"Bearer"` (§6.1 rule 6). Does not say
     *                                whether the token is certificate-bound — see
     *                                {@see \Axiam\Sdk\AxiamClient::validateToken()} /
     *                                `introspectToken()` for that.
     * @param int       $expiresIn    The access-token lifetime in seconds (server
     *                                default 900).
     */
    public function __construct(
        public readonly Sensitive $accessToken,
        public readonly string $tokenType,
        public readonly int $expiresIn,
    ) {
    }
}
