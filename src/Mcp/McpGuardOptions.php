<?php

declare(strict_types=1);

namespace Axiam\Sdk\Mcp;

use Axiam\Sdk\Management\FieldError;
use Axiam\Sdk\Management\ValidationError;
use Axiam\Sdk\Rest\ReasonCode;

/**
 * Validates a §10 guard's CONTRACT.md §28.5 configuration and precomputes the challenge
 * values it will emit, at guard-CONSTRUCTION time so that an invalid one is a startup
 * failure rather than a surprise on the 401 path — the same discipline
 * {@see \Axiam\Sdk\AxiamClient}'s own constructor applies to every other CONDITIONAL
 * option.
 *
 * Built by {@see \Axiam\Sdk\Laravel\AxiamMiddleware} and
 * {@see \Axiam\Sdk\Symfony\AxiamAuthSubscriber} — the two §10 guards — so the §28.5
 * option can never drift between the two framework bridges.
 */
final class McpGuardOptions
{
    /**
     * @param string $resourceMetadataUrl CONTRACT.md §28.5's option, as given —
     *        every challenge this instance builds is built from it.
     * @param string $noCredentialChallenge CONTRACT.md §28.4 vector 1 — the request
     *        carried **no** authentication information, so RFC 6750 §3 says not to name
     *        an error.
     * @param string $invalidTokenChallenge CONTRACT.md §28.4 vector 2 — a credential was
     *        presented and rejected. The only thing a 401 this SDK emits ever says about
     *        why (expired, wrong tenant, wrong audience, bad signature — all of them).
     * @param string $metadataPath The document's path, exempted from authentication by
     *        the guard itself (CONTRACT.md §28.3 rule 2).
     */
    private function __construct(
        public readonly string $resourceMetadataUrl,
        public readonly string $noCredentialChallenge,
        public readonly string $invalidTokenChallenge,
        public readonly string $metadataPath,
    ) {
    }

    /**
     * @param string $operation The guard class's own name, so a refusal says which
     *        guard refused (e.g. `AxiamMiddleware`, `AxiamAuthSubscriber`).
     * @param string $resourceMetadataUrl CONTRACT.md §28.5's option — the document's
     *        URL. Setting it on a guard is what turns §28 on for that guard.
     * @param string|null $expectedAudience The SAME §10.1 row 6 `expectedAudience` the
     *        {@see \Axiam\Sdk\AxiamClient} this guard was built from was constructed
     *        with — read via {@see \Axiam\Sdk\AxiamClient::expectedAudience()}. §28 adds
     *        no second audience option.
     *
     * @throws ValidationError When `$expectedAudience` is `null`/empty (CONTRACT.md
     *         §28.5 rule 2), or `$resourceMetadataUrl` is outside §28.4's syntax for
     *         `resource_metadata`.
     */
    public static function build(string $operation, string $resourceMetadataUrl, ?string $expectedAudience): self
    {
        if ($expectedAudience === null || $expectedAudience === '') {
            throw new ValidationError(
                sprintf(
                    'resourceMetadataUrl: requires expectedAudience to be set on the same AxiamClient '
                    . '(CONTRACT.md §28.5 rule 2) — announcing a resource identifier obliges this server '
                    . 'to check that an inbound token\'s aud is that identifier, and a resource server that '
                    . 'announces itself without checking is opened by a token minted for somebody else '
                    . '[%s]',
                    $operation,
                ),
                [new FieldError('resourceMetadataUrl', 'requires expectedAudience to be set on the same AxiamClient')],
            );
        }

        // Also validates §28.4's `resource_metadata` syntax as a side effect — the same
        // value is what every challenge below carries.
        $noCredential = Mcp::bearerChallenge($resourceMetadataUrl);
        $invalidToken = Mcp::bearerChallenge($resourceMetadataUrl, error: BearerChallengeError::INVALID_TOKEN);

        return new self(
            resourceMetadataUrl: $resourceMetadataUrl,
            noCredentialChallenge: $noCredential,
            invalidTokenChallenge: $invalidToken,
            metadataPath: Mcp::pathOf($resourceMetadataUrl),
        );
    }

    /**
     * CONTRACT.md §28.5 rule 5: the one class of `403` that carries a challenge, and
     * only it. A `no_grant` denial on a route that named a scope means *ask for more*,
     * which is exactly what a challenge invites a client to do; every other reason code
     * — `denied_by_rule`, absent, or unrecognised — leaves the outcome alone
     * (§11.2 rule 9), which is a header-free 403.
     *
     * @param string $scope The scope the route asked for, verbatim (never synthesised,
     *        never derived, never substituted — CONTRACT.md §28.5 rule 6).
     */
    public function insufficientScopeChallenge(string $reasonCode, string $scope): ?string
    {
        if ($reasonCode !== ReasonCode::NO_GRANT) {
            return null;
        }

        return Mcp::bearerChallenge(
            $this->resourceMetadataUrl,
            error: BearerChallengeError::INSUFFICIENT_SCOPE,
            scope: $scope,
        );
    }

    /**
     * Picks between CONTRACT.md §28.4's first two vectors for a `401`: `invalidToken`
     * when the request carried a credential, `noCredential` when it carried none. RFC
     * 6750 §3 says a resource server SHOULD NOT name an error code when the request
     * carried no authentication information at all — no credential is not a bad
     * credential, and a client has to be able to tell the two apart.
     */
    public function challengeFor401(bool $credentialPresented): string
    {
        return $credentialPresented ? $this->invalidTokenChallenge : $this->noCredentialChallenge;
    }

    /**
     * Is this request the unauthenticated `GET`/`HEAD` of the metadata document
     * (CONTRACT.md §28.3 rule 2)? A document that 401s cannot start the handshake it
     * exists to start — the client would be holding a 401 and being told to go read a
     * page that answers 401.
     */
    public function isMetadataDocumentRequest(string $method, string $path): bool
    {
        $verb = strtoupper($method);

        return ($verb === 'GET' || $verb === 'HEAD') && $path === $this->metadataPath;
    }
}
