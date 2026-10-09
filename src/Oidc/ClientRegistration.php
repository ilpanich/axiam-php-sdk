<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\Sensitive;

/**
 * An RFC 7591 §3.2.1 / RFC 7592 §3 client information response — what
 * {@see \Axiam\Sdk\AxiamClient::readClientRegistration()} and
 * {@see \Axiam\Sdk\AxiamClient::updateClientRegistration()} return (CONTRACT.md §28.12.1).
 *
 * `registrationAccessToken` and `clientSecret` are {@see Sensitive} (§28.12.4), so
 * `print_r()`, `var_dump()`, `var_export()`, `json_encode()` and string casts of this object
 * never show either.
 *
 * Every member the server sent that this type does not name is kept, verbatim, in
 * {@see self::$extra}: RFC 7591 §3.2.1 lets a server add members (AXIAM's CIBA `backchannel_*`
 * members are some), and because an update is a **full replacement** a member a read returned
 * and an update left out is a member the server deletes. Passing a read's result straight to
 * `updateClientRegistration()` therefore sends it back intact, `jwks` / `jwks_uri` included.
 *
 * The properties are deliberately **mutable**: the intended update is "read, change a field,
 * update", and that is `$registration->clientName = 'v2';` on the value the read returned.
 */
final class ClientRegistration implements \JsonSerializable
{
    /**
     * The members `updateClientRegistration()` never sends (§28.12.2 rule 4). The first four
     * the server refuses with `400 invalid_request` when present; `client_secret` it never
     * accepts back.
     */
    public const SERVER_STATED_MEMBERS = [
        'registration_access_token',
        'registration_client_uri',
        'client_secret_expires_at',
        'client_id_issued_at',
        'client_secret',
    ];

    /** The members this type models as properties; everything else lands in `$extra`. */
    private const MODELLED = [
        'client_id', 'client_id_issued_at', 'client_name', 'redirect_uris', 'grant_types',
        'response_types', 'token_endpoint_auth_method', 'scope', 'registration_client_uri',
        'client_secret_expires_at', 'jwks', 'jwks_uri', 'client_secret',
        'registration_access_token',
    ];

    /**
     * @param string $clientId The client's `client_id`.
     * @param int|null $clientIdIssuedAt When the id was issued (seconds since the epoch). Never sent on an update.
     * @param string|null $clientName The registered display name.
     * @param list<string>|null $redirectUris The registered redirect URIs; `null` when the response did not carry them.
     * @param list<string>|null $grantTypes The registered grant types; `null` when the response did not carry them.
     * @param list<string>|null $responseTypes The registered response types; `null` when the response did not carry them.
     * @param string|null $tokenEndpointAuthMethod How the client authenticates at the token endpoint. The server refuses an update that changes it.
     * @param string|null $scope The registered scope, space-separated.
     * @param string|null $registrationClientUri Where this registration is read, replaced and deleted. Never sent on an update.
     * @param int|null $clientSecretExpiresAt When the client secret expires (`0` = never). Never sent on an update.
     * @param array<string,mixed>|null $jwks The client's JWK Set, for a `private_key_jwt` client.
     * @param string|null $jwksUri Where the client's JWK Set is published.
     * @param Sensitive|null $clientSecret Present only on the registration response itself; never on a read or an update, and never sent back.
     * @param Sensitive|null $registrationAccessToken Present on the registration response and, **rotated**, on every update response; absent on a read. Never sent in a body.
     * @param array<string,mixed> $extra Every other member of the response, verbatim.
     */
    public function __construct(
        public string $clientId,
        public ?int $clientIdIssuedAt = null,
        public ?string $clientName = null,
        public ?array $redirectUris = null,
        public ?array $grantTypes = null,
        public ?array $responseTypes = null,
        public ?string $tokenEndpointAuthMethod = null,
        public ?string $scope = null,
        public ?string $registrationClientUri = null,
        public ?int $clientSecretExpiresAt = null,
        public ?array $jwks = null,
        public ?string $jwksUri = null,
        public ?Sensitive $clientSecret = null,
        public ?Sensitive $registrationAccessToken = null,
        public array $extra = [],
    ) {
    }

    /**
     * Decode a client information response, tolerating members this type does not name.
     *
     * A modelled member whose value has an unexpected type is kept in `$extra` rather than
     * dropped: a replacement must not lose what the server holds.
     *
     * @param array<mixed> $wire The decoded JSON object.
     * @throws NetworkError when the response is not an object or carries no `client_id`.
     */
    public static function fromArray(array $wire): self
    {
        if ($wire !== [] && array_is_list($wire)) {
            throw NetworkError::fromMessage('client registration response is not a JSON object');
        }
        $clientId = $wire['client_id'] ?? null;
        if (!is_string($clientId) || $clientId === '') {
            throw NetworkError::fromMessage('client registration response carries no client_id');
        }

        $extra = [];
        foreach ($wire as $key => $value) {
            if (!in_array($key, self::MODELLED, true)) {
                $extra[(string) $key] = $value;
            }
        }

        $string = static function (string $key) use ($wire, &$extra): ?string {
            $value = $wire[$key] ?? null;
            if ($value !== null && !is_string($value)) {
                $extra[$key] = $value;

                return null;
            }

            return $value;
        };
        $int = static function (string $key) use ($wire, &$extra): ?int {
            $value = $wire[$key] ?? null;
            if ($value !== null && !is_int($value)) {
                $extra[$key] = $value;

                return null;
            }

            return $value;
        };
        // A list of strings, or `null` when absent. Anything else — a non-list, or a list with a
        // non-string item — is an unexpected shape and is kept as read, in `$extra`, so the
        // replacement sends it back unchanged (§28.12.2 rule 4, §34.2 P12.4).
        /** @return list<string>|null */
        $list = static function (string $key) use ($wire, &$extra): ?array {
            $value = $wire[$key] ?? null;
            if ($value === null) {
                return null;
            }
            if (!is_array($value) || !array_is_list($value) || count(array_filter($value, 'is_string')) !== count($value)) {
                $extra[$key] = $value;

                return null;
            }

            /** @var list<string> $value */
            return $value;
        };

        $jwks = null;
        $rawJwks = $wire['jwks'] ?? null;
        if (is_array($rawJwks)) {
            /** @var array<string,mixed> $jwks */
            $jwks = $rawJwks;
        } elseif ($rawJwks !== null) {
            $extra['jwks'] = $rawJwks;
        }
        $secret = $string('client_secret');
        $token = $string('registration_access_token');

        return new self(
            clientId: $clientId,
            clientIdIssuedAt: $int('client_id_issued_at'),
            clientName: $string('client_name'),
            redirectUris: $list('redirect_uris'),
            grantTypes: $list('grant_types'),
            responseTypes: $list('response_types'),
            tokenEndpointAuthMethod: $string('token_endpoint_auth_method'),
            scope: $string('scope'),
            registrationClientUri: $string('registration_client_uri'),
            clientSecretExpiresAt: $int('client_secret_expires_at'),
            jwks: $jwks,
            jwksUri: $string('jwks_uri'),
            clientSecret: $secret !== null ? new Sensitive($secret) : null,
            registrationAccessToken: $token !== null ? new Sensitive($token) : null,
            extra: $extra,
        );
    }

    /**
     * The RFC 7592 §2.2 replacement body `updateClientRegistration()` sends (§28.12.2
     * rule 4): every member — the unknown ones in `$extra` included — except the five
     * {@see self::SERVER_STATED_MEMBERS}, with `client_id` set to this registration's own.
     *
     * It is built from what the read carried (§34.2 P12.4): a member that is `null` — one the
     * read did not carry — is not sent, so no list becomes `[]` because the read lacked it,
     * and a member of an unexpected shape goes back exactly as read.
     *
     * Holds no secret: the token and the client secret are exactly what it leaves out.
     *
     * @return array<string,mixed>
     */
    public function updateBody(): array
    {
        $body = $this->extra;
        foreach (self::SERVER_STATED_MEMBERS as $member) {
            unset($body[$member]);
        }
        $body['client_id'] = $this->clientId;
        if ($this->clientName !== null) {
            $body['client_name'] = $this->clientName;
        }
        if ($this->redirectUris !== null) {
            $body['redirect_uris'] = array_values($this->redirectUris);
        }
        if ($this->grantTypes !== null) {
            $body['grant_types'] = array_values($this->grantTypes);
        }
        if ($this->responseTypes !== null) {
            $body['response_types'] = array_values($this->responseTypes);
        }
        if ($this->tokenEndpointAuthMethod !== null) {
            $body['token_endpoint_auth_method'] = $this->tokenEndpointAuthMethod;
        }
        if ($this->scope !== null) {
            $body['scope'] = $this->scope;
        }
        if ($this->jwks !== null) {
            $body['jwks'] = $this->jwks;
        }
        if ($this->jwksUri !== null) {
            $body['jwks_uri'] = $this->jwksUri;
        }

        return $body;
    }

    /**
     * Renders this registration for `json_encode()` — a log line, never the wire. The token
     * and the secret stay wrapped and print `[SENSITIVE]`.
     *
     * @return array<string,mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->extra + [
            'client_id' => $this->clientId,
            'client_id_issued_at' => $this->clientIdIssuedAt,
            'client_name' => $this->clientName,
            'redirect_uris' => $this->redirectUris,
            'grant_types' => $this->grantTypes,
            'response_types' => $this->responseTypes,
            'token_endpoint_auth_method' => $this->tokenEndpointAuthMethod,
            'scope' => $this->scope,
            'registration_client_uri' => $this->registrationClientUri,
            'client_secret_expires_at' => $this->clientSecretExpiresAt,
            'jwks' => $this->jwks,
            'jwks_uri' => $this->jwksUri,
            'client_secret' => $this->clientSecret,
            'registration_access_token' => $this->registrationAccessToken,
        ];
    }
}
