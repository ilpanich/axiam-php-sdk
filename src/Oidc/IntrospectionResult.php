<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * The RFC 7662 introspection result (wire schema `IntrospectionResponse`, CONTRACT.md
 * §12.1). Only `$active` is guaranteed; the server omits the metadata fields for an
 * inactive token.
 */
final class IntrospectionResult
{
    /**
     * @param bool        $active   Whether the token is currently active.
     * @param string|null $sub      Subject the token was issued to.
     * @param string|null $clientId Client the token was issued to.
     * @param string|null $scope    Scope granted to the token.
     * @param string|null $tokenType Token type (`Bearer`).
     * @param int|null    $exp      Expiry time, epoch seconds.
     * @param int|null    $iat      Issued-at time, epoch seconds.
     */
    public function __construct(
        public readonly bool $active,
        public readonly ?string $sub = null,
        public readonly ?string $clientId = null,
        public readonly ?string $scope = null,
        public readonly ?string $tokenType = null,
        public readonly ?int $exp = null,
        public readonly ?int $iat = null,
    ) {
    }
}
