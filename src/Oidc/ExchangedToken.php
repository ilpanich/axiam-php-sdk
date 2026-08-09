<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\Sensitive;

/**
 * The result of an RFC 8693 exchange (wire schema `TokenExchangeResponse`,
 * CONTRACT.md §15.1).
 *
 * **There is no `$refreshToken` property, and that is deliberate** (§15.2 rule 4).
 * RFC 8693 issues none, so this type cannot represent one: an application that wants a
 * fresh exchanged token re-runs the exchange. This result also never enters the §9
 * single-flight refresh guard — there is nothing to refresh.
 */
final class ExchangedToken
{
    /**
     * @param Sensitive $accessToken The issued token (§15.5 secret).
     * @param string $issuedTokenType What the server actually issued. Mandatory in RFC 8693 §2.2.1 and surfaced rather than dropped (§15.2 rule 6), so a client that asked for one type and got another can tell.
     * @param string $tokenType The token type (`Bearer`).
     * @param int $expiresIn Lifetime in seconds — never longer than the subject token's remaining life.
     * @param string|null $scope **The granted scope, which may be narrower than requested** even on success (§15.2 rule 7); read it rather than assuming the request was honoured verbatim.
     */
    public function __construct(
        public readonly Sensitive $accessToken,
        public readonly string $issuedTokenType,
        public readonly string $tokenType,
        public readonly int $expiresIn,
        public readonly ?string $scope,
    ) {
    }
}
