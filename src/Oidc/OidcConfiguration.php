<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\NetworkError;
use Psr\Http\Message\ResponseInterface;

/**
 * The OIDC Discovery 1.0 metadata document served by
 * `GET /.well-known/openid-configuration` (wire schema `OidcDiscoveryDocument`,
 * CONTRACT.md §12.1). Every field is required by the server's schema.
 *
 * Field names deliberately keep the wire's snake_case spelling rather than PHP's usual
 * camelCase (contract 1.4 port-brief judgment call 3): this type IS a protocol document,
 * and a caller cross-references these names against OIDC Discovery 1.0 / RFC 8414.
 *
 * `issuer` is the **authoritative** issuer for ID-token validation (§12.4 rule 3). It may
 * legitimately differ from the client's base URL when AXIAM runs behind a proxy, so this
 * SDK never rejects a document on an issuer/base-URL mismatch (§12.3 rule 6). Likewise
 * `jwks_uri` is read from here rather than hardcoded.
 */
final class OidcConfiguration
{
    /**
     * @param string $issuer The authorization server's issuer identifier — the value an ID token's `iss` claim must equal exactly.
     * @param string $authorization_endpoint The authorization endpoint `oidcBegin` builds its redirect URL from.
     * @param string $token_endpoint The token endpoint used by `oidcExchange`, `oidcRefresh` and `loginClientCredentials`.
     * @param string $userinfo_endpoint The userinfo endpoint. Advertised by the server but deliberately NOT called by this SDK (§12.3 rule 5).
     * @param string $jwks_uri URI of the JWKS document whose keys verify ID-token signatures (§12.4 rule 2).
     * @param string $revocation_endpoint The RFC 7009 revocation endpoint used by `revoke`.
     * @param string $introspection_endpoint The RFC 7662 introspection endpoint used by `introspect`.
     * @param list<string> $response_types_supported OAuth2 `response_type` values the server supports.
     * @param list<string> $subject_types_supported Subject identifier types the server supports.
     * @param list<string> $id_token_signing_alg_values_supported ID-token signing algorithms the server advertises. Informational only: §12.4 rule 1 pins verification to `EdDSA` regardless of what appears here.
     * @param list<string> $scopes_supported Scopes the server supports.
     * @param list<string> $token_endpoint_auth_methods_supported Client-authentication methods the token endpoint supports (`client_secret_post`, §12.1 note 3).
     * @param list<string> $claims_supported Claims the server may include in an ID token.
     * @param list<string> $grant_types_supported Grant types the token endpoint supports.
     */
    public function __construct(
        public readonly string $issuer,
        public readonly string $authorization_endpoint,
        public readonly string $token_endpoint,
        public readonly string $userinfo_endpoint,
        public readonly string $jwks_uri,
        public readonly string $revocation_endpoint,
        public readonly string $introspection_endpoint,
        public readonly array $response_types_supported,
        public readonly array $subject_types_supported,
        public readonly array $id_token_signing_alg_values_supported,
        public readonly array $scopes_supported,
        public readonly array $token_endpoint_auth_methods_supported,
        public readonly array $claims_supported,
        public readonly array $grant_types_supported,
    ) {
    }

    /**
     * Build a {@see OidcConfiguration} from the decoded `GET
     * /.well-known/openid-configuration` JSON body, raising {@see NetworkError} on a
     * malformed document (missing/mistyped required field) rather than letting a
     * confusing `TypeError` escape from the constructor.
     */
    public static function fromWire(ResponseInterface $response): self
    {
        $wire = json_decode((string) $response->getBody(), true);
        if (!is_array($wire)) {
            throw NetworkError::fromResponse($response, 'oidc discovery: response body is not a JSON object');
        }

        $string = static function (mixed $value, string $field) use ($response): string {
            if (!is_string($value) || $value === '') {
                throw NetworkError::fromResponse($response, sprintf('oidc discovery: missing or invalid "%s"', $field));
            }

            return $value;
        };
        /** @return list<string> */
        $stringList = static function (mixed $value, string $field) use ($response): array {
            if (!is_array($value)) {
                throw NetworkError::fromResponse($response, sprintf('oidc discovery: missing or invalid "%s"', $field));
            }

            return array_values(array_filter($value, 'is_string'));
        };

        return new self(
            issuer: $string($wire['issuer'] ?? null, 'issuer'),
            authorization_endpoint: $string($wire['authorization_endpoint'] ?? null, 'authorization_endpoint'),
            token_endpoint: $string($wire['token_endpoint'] ?? null, 'token_endpoint'),
            userinfo_endpoint: $string($wire['userinfo_endpoint'] ?? null, 'userinfo_endpoint'),
            jwks_uri: $string($wire['jwks_uri'] ?? null, 'jwks_uri'),
            revocation_endpoint: $string($wire['revocation_endpoint'] ?? null, 'revocation_endpoint'),
            introspection_endpoint: $string($wire['introspection_endpoint'] ?? null, 'introspection_endpoint'),
            response_types_supported: $stringList($wire['response_types_supported'] ?? null, 'response_types_supported'),
            subject_types_supported: $stringList($wire['subject_types_supported'] ?? null, 'subject_types_supported'),
            id_token_signing_alg_values_supported: $stringList($wire['id_token_signing_alg_values_supported'] ?? null, 'id_token_signing_alg_values_supported'),
            scopes_supported: $stringList($wire['scopes_supported'] ?? null, 'scopes_supported'),
            token_endpoint_auth_methods_supported: $stringList($wire['token_endpoint_auth_methods_supported'] ?? null, 'token_endpoint_auth_methods_supported'),
            claims_supported: $stringList($wire['claims_supported'] ?? null, 'claims_supported'),
            grant_types_supported: $stringList($wire['grant_types_supported'] ?? null, 'grant_types_supported'),
        );
    }
}
