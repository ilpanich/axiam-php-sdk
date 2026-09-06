<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * RFC 8705 §5 `mtls_endpoint_aliases` — the six endpoints re-based on the host that
 * performs the mutual-TLS handshake (wire schema `MtlsEndpointAliases`, contract 1.40).
 *
 * A TLS listener decides whether to request a client certificate during the handshake,
 * before it has seen any HTTP, so "ask for a certificate on `/oauth2/token` but not on
 * `/oauth2/authorize`" is not something one listener can do. A deployment wanting both
 * runs two, and this object names the second.
 *
 * Only these six are ever aliased. `authorization_endpoint` and `end_session_endpoint` are
 * front-channel and `jwks_uri` is public key material, so CONTRACT.md §21.3 rule 2 forbids
 * synthesising an alias for any of them — sending a browser to an mTLS host raises a native
 * certificate-chooser dialog most users cannot answer. `issuer` is not an endpoint and does
 * not move either: §12.4 rule 3 still compares `iss` against it by exact string.
 *
 * **Every property is nullable**, though the server's schema marks all six required. AXIAM
 * builds them from one path through a shared macro and so always publishes the complete
 * set, but RFC 8705 §5 permits an OP to alias fewer, and the shape of this member must
 * never be why a client stops working — the same principle rule 2 point 1 states for the
 * object as a whole, one level in. A `null` entry falls back to the top-level endpoint of
 * the same name, exactly as an absent object does.
 */
final class MtlsEndpointAliases
{
    /**
     * @param string|null $token_endpoint RFC 8705 §2 client authentication, and §3 the mint of a certificate-bound token.
     * @param string|null $userinfo_endpoint OIDC Core §5.3, reached with an access token that may carry `cnf`.
     * @param string|null $revocation_endpoint RFC 7009 §2.1 — authenticates the client.
     * @param string|null $introspection_endpoint RFC 7662 §2.1 — authenticates the caller.
     * @param string|null $device_authorization_endpoint RFC 8628 §3.1 — authenticates the client.
     * @param string|null $pushed_authorization_request_endpoint RFC 9126 §2 — authenticates the client.
     */
    public function __construct(
        public readonly ?string $token_endpoint = null,
        public readonly ?string $userinfo_endpoint = null,
        public readonly ?string $revocation_endpoint = null,
        public readonly ?string $introspection_endpoint = null,
        public readonly ?string $device_authorization_endpoint = null,
        public readonly ?string $pushed_authorization_request_endpoint = null,
    ) {
    }

    /**
     * Build a {@see MtlsEndpointAliases} from the decoded `mtls_endpoint_aliases` object,
     * or `null` when the document carries none.
     *
     * Absence is never an error: it means "no separate mTLS host", not "mTLS unsupported".
     * Each member is read independently, so a partial object — which RFC 8705 §5 permits —
     * aliases what it names and leaves the rest falling back to the top-level entries,
     * rather than failing the whole document.
     */
    public static function fromWire(mixed $wire): ?self
    {
        if (!is_array($wire)) {
            return null;
        }

        $optionalString = static fn (mixed $value): ?string => is_string($value) && $value !== '' ? $value : null;

        return new self(
            token_endpoint: $optionalString($wire['token_endpoint'] ?? null),
            userinfo_endpoint: $optionalString($wire['userinfo_endpoint'] ?? null),
            revocation_endpoint: $optionalString($wire['revocation_endpoint'] ?? null),
            introspection_endpoint: $optionalString($wire['introspection_endpoint'] ?? null),
            device_authorization_endpoint: $optionalString($wire['device_authorization_endpoint'] ?? null),
            pushed_authorization_request_endpoint: $optionalString($wire['pushed_authorization_request_endpoint'] ?? null),
        );
    }
}
