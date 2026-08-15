<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

/**
 * What the caller proved about **this** connection and **this** request, for
 * {@see JwksVerifier::verifyTokenBinding()}.
 *
 * A value object rather than two string parameters on purpose: two same-typed
 * nullable thumbprints are exactly the pair a positional call transposes
 * silently, and transposing them would check each proof against the wrong
 * confirmation.
 */
final class PresentedProofs
{
    /**
     * @param string|null $certificateThumbprint The peer certificate's RFC 8705 §3.1
     *   `x5t#S256`, taken from the TLS connection (`$_SERVER['SSL_CLIENT_CERT']`) or
     *   from a *trusted* terminating proxy over a channel your application controls.
     *   **Never** from a caller-settable request header: a forgeable input makes the
     *   whole mechanism decorative.
     * @param string|null $dpopThumbprint The `jkt` of an **already verified** DPoP
     *   proof. Supply it only after checking the proof's signature, `htm`, `htu`,
     *   `iat` and `jti` for this request — {@see DpopVerifier::verifyProof()} does all
     *   ten §21.7.2 checks and returns exactly this value. A thumbprint lifted off an
     *   unverified proof would let a proof captured from any other endpoint authorize
     *   this one.
     */
    public function __construct(
        public readonly ?string $certificateThumbprint = null,
        public readonly ?string $dpopThumbprint = null,
    ) {
    }

    /**
     * Neither proof — the ordinary bearer case.
     *
     * @return self A pair with both thumbprints absent.
     */
    public static function none(): self
    {
        return new self();
    }

    /**
     * Only a client certificate was presented.
     *
     * @param string $thumbprint The peer certificate's `x5t#S256`.
     *
     * @return self A pair carrying only the certificate thumbprint.
     */
    public static function certificate(string $thumbprint): self
    {
        return new self(certificateThumbprint: $thumbprint);
    }

    /**
     * Only a verified DPoP proof was presented.
     *
     * @param string $thumbprint The `jkt` of an already verified proof.
     *
     * @return self A pair carrying only the DPoP thumbprint.
     */
    public static function dpop(string $thumbprint): self
    {
        return new self(dpopThumbprint: $thumbprint);
    }
}
