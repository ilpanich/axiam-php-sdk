<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\Sensitive;

/**
 * A token set returned by the OAuth2 token endpoint (wire schema `TokenResponse`),
 * returned by `oidcExchange`, `oidcRefresh` and `loginClientCredentials` (CONTRACT.md
 * §12.1).
 *
 * `$accessToken`, `$refreshToken` and `$idToken` are {@see Sensitive} (§12.5):
 * `__toString()`/`var_dump()`/`json_encode()` all redact them to `"[SENSITIVE]"`, and the
 * raw value is reachable only through `->reveal()`.
 *
 * `$idClaims` is present exactly when `$idToken` is, and holds the **already-validated**
 * claim set (§12.4) — validation happens before this object is ever constructed, so an
 * `OidcTokenSet` in your hands is never partially trusted (§12.4 rule 7).
 */
final class OidcTokenSet
{
    /**
     * @param Sensitive             $accessToken  The OAuth2 access token (§12.5 secret).
     * @param string                $tokenType    The token type the server issued (`Bearer`).
     * @param int                   $expiresIn    Access-token lifetime in seconds from the time of the response.
     * @param string|null           $scope        Granted scope, when the server narrowed or echoed it.
     * @param Sensitive|null        $refreshToken The refresh token, when the grant issued one (§12.5 secret).
     * @param Sensitive|null        $idToken      The raw ID token, when the grant issued one (§12.5 secret).
     * @param array<string,mixed>|null $idClaims The validated ID-token claims — present exactly when `$idToken` is (§12.1, §12.4). Keeps the wire's snake_case claim spelling (`iss`, `sub`, `aud`, …) rather than camelCase, since these are protocol identifiers a caller cross-references against OIDC Core.
     */
    public function __construct(
        public readonly Sensitive $accessToken,
        public readonly string $tokenType,
        public readonly int $expiresIn,
        public readonly ?string $scope = null,
        public readonly ?Sensitive $refreshToken = null,
        public readonly ?Sensitive $idToken = null,
        public readonly ?array $idClaims = null,
    ) {
    }
}
