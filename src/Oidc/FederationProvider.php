<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * One sign-in button (wire schema `PublicFederationProvider`, CONTRACT.md §12.1,
 * contract 1.38).
 *
 * This is an **unauthenticated** response and carries only what a button needs.
 * There is no `client_id`, no `metadata_url`, no endpoint URL and no secret —
 * absent by construction rather than filtered out — and §12.1 note 9 forbids an
 * SDK from expecting one.
 */
final class FederationProvider
{
    /** `protocol` value selecting `ssoStart` (§12.1 note 10). */
    public const PROTOCOL_OIDC_CONNECT = 'OidcConnect';

    /** `protocol` value selecting `ssoStartOauth2` (§12.1 note 10). */
    public const PROTOCOL_OAUTH2 = 'OAuth2';

    /**
     * `protocol` value selecting the SAML login endpoint, which is **not** a §12
     * vocabulary operation (§12.1 note 10).
     */
    public const PROTOCOL_SAML = 'Saml';

    /**
     * @param string      $id             Config id, echoed back to the matching start
     *                                    operation. Pass it through unmodified:
     *                                    inheritance is resolved server-side (§12.1
     *                                    note 13) and this id is how the server is told
     *                                    what resolution produced.
     * @param string      $providerKind   Which provider this is, for the button's
     *                                    branding — `google`, `github`, `generic_oidc`,
     *                                    … **Not** what selects the start operation;
     *                                    see `$protocol`.
     * @param string      $displayName    The operator's display name for the provider.
     * @param string      $protocol       `OidcConnect`, `Saml` or `OAuth2` — the value
     *                                    that selects which start operation to call
     *                                    (§12.1 note 10). Kept as the wire string
     *                                    rather than narrowed to an enum: the server
     *                                    owns this vocabulary, and a value added
     *                                    server-side must not become a parse failure
     *                                    for the whole list. An `OAuth2` provider
     *                                    issues **no** ID token (§12.1 note 11), a
     *                                    distinction a surface rendering these buttons
     *                                    SHOULD make visible.
     * @param bool        $hasBundledMark Whether AXIAM ships this provider's own
     *                                    sign-in mark, which its button must then use.
     *                                    `false` for the generic kinds, whose buttons
     *                                    read "Sign in with $displayName" and use
     *                                    `$buttonIcon` where one was uploaded.
     * @param bool        $inherited      `true` when the provider is inherited from the
     *                                    organization rather than configured on this
     *                                    tenant (§12.1 note 13). Informational — it is
     *                                    not needed to sign in, and nothing in this SDK
     *                                    computes it.
     * @param string|null $buttonIcon     The operator's uploaded button icon as a
     *                                    bounded raster `data:` URL, or `null` — which
     *                                    is the case for most providers.
     */
    public function __construct(
        public readonly string $id,
        public readonly string $providerKind,
        public readonly string $displayName,
        public readonly string $protocol,
        public readonly bool $hasBundledMark,
        public readonly bool $inherited,
        public readonly ?string $buttonIcon = null,
    ) {
    }
}
