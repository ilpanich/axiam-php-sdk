<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * The result of `ssoProviders` (wire schema `PublicFederationProvidersResponse`,
 * CONTRACT.md §12.1).
 *
 * An **empty** `$providers` is a normal success, never an error (§12.1 note 9).
 * An unknown organization, a known one with nothing configured, and a request
 * naming no workspace at all all answer `200` this way, precisely so the endpoint
 * cannot be used to enumerate organization or tenant slugs.
 */
final class FederationProviderList
{
    /**
     * The query parameter the server delivers a handoff code in, on the SPA's own
     * callback URL (§12.1 note 12).
     */
    public const HANDOFF_QUERY_PARAM = 'axiam_handoff';

    /**
     * How long a handoff code is valid, in seconds (§12.1 note 12). It exists to
     * survive one redirect. Redeem it immediately, once.
     */
    public const HANDOFF_CODE_TTL_SECONDS = 60;

    /**
     * @param list<FederationProvider> $providers The providers to offer, in a stable
     *                                            server-defined order.
     */
    public function __construct(
        public readonly array $providers,
    ) {
    }
}
