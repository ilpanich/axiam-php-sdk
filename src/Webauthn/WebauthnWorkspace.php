<?php

declare(strict_types=1);

namespace Axiam\Sdk\Webauthn;

/**
 * The workspace a usernameless ceremony runs in (CONTRACT.md §24.1).
 *
 * `discoverable/start` is the one WebAuthn endpoint that carries the workspace explicitly,
 * because a usernameless ceremony has no prior step to have minted a token that names it.
 * Unlike the five `/oauth2` operations of §12.1 rule 2 it **accepts slugs**, so a slug-only
 * client can run it.
 *
 * Pass `null` to `webauthnDiscoverableStart()` to have it filled from the client's own
 * configured identity, which is what almost every caller wants.
 */
final readonly class WebauthnWorkspace
{
    public function __construct(
        public ?string $orgId = null,
        public ?string $orgSlug = null,
        public ?string $tenantId = null,
        public ?string $tenantSlug = null,
    ) {
    }
}
