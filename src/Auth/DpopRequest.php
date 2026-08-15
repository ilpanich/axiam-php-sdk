<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

/**
 * What {@see DpopVerifier::verifyProof()} needs to know about the current request.
 *
 * Every field feeds a §21.7.2 check that cannot be made without it — there is no
 * "just check the signature" mode, because that is exactly the partial
 * verification the contract calls worse than none.
 */
final class DpopRequest
{
    /**
     * @param string      $httpMethod  The request method, e.g. `POST`.
     * @param string      $httpUri     The full request URI. Query and fragment are
     *   stripped during comparison, so passing it with a query string is expected.
     * @param string      $accessToken The token from the `Authorization` header,
     *   exactly as it arrived — this is hashed for the `ath` check.
     * @param string|null $expectedJkt The token's `cnf.jkt`, when the caller has it.
     *   Supplying it performs check 10 inside the call; leaving it null means the
     *   caller must do that comparison itself, which
     *   {@see JwksVerifier::verifyTokenBinding()} does.
     * @param int         $leewaySeconds The `iat` window, applied in both directions.
     * @param int|null    $nowUnix     Override for the current time, for tests.
     */
    public function __construct(
        public readonly string $httpMethod,
        public readonly string $httpUri,
        public readonly string $accessToken,
        public readonly ?string $expectedJkt = null,
        public readonly int $leewaySeconds = DpopVerifier::IAT_LEEWAY_SECONDS,
        public readonly ?int $nowUnix = null,
    ) {
    }

    /**
     * The same request, with the token's `cnf.jkt` so check 10 runs inside the call.
     *
     * @param string $jkt The token's `cnf.jkt`.
     *
     * @return self A copy carrying the expected thumbprint.
     */
    public function withExpectedJkt(string $jkt): self
    {
        return new self(
            $this->httpMethod,
            $this->httpUri,
            $this->accessToken,
            $jkt,
            $this->leewaySeconds,
            $this->nowUnix,
        );
    }
}
