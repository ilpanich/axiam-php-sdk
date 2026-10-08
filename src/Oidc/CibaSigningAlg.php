<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * The algorithms a signed CIBA authentication request may use (CONTRACT.md §33.2) — the
 * client's registered `backchannel_authentication_request_signing_alg`.
 *
 * This SDK signs `ES256` and `EdDSA`. `PS256` is part of the contract's set but is **not
 * supported here**: `firebase/php-jwt`, this SDK's JOSE library, signs PS256 only through
 * phpseclib 3, which this SDK does not depend on. {@see CibaRequestSigner::fromPem()} refuses
 * it locally rather than fail at the first request.
 */
enum CibaSigningAlg: string
{
    /** RSASSA-PSS with SHA-256 — refused by this SDK (see the type's summary). */
    case PS256 = 'PS256';

    /** ECDSA on P-256 with SHA-256. */
    case ES256 = 'ES256';

    /** Ed25519. */
    case EdDSA = 'EdDSA';
}
