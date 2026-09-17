<?php

declare(strict_types=1);

namespace Axiam\Sdk\Symfony;

use Axiam\Sdk\Mcp\Mcp;
use Axiam\Sdk\Mcp\ProtectedResourceMetadata;

// D-01: guarded and optional exactly like OidcCallbackController's own header comment —
// this file never fatals if `symfony/http-kernel`/`symfony/http-foundation` happen to be
// absent.
if (class_exists(\Symfony\Component\HttpFoundation\Request::class)) {
    /**
     * Symfony's realization of CONTRACT.md §28.3's `serve_protected_resource_metadata`:
     * an invokable controller that serves the RFC 9728 protected-resource metadata
     * document, `200 application/json`, at the path {@see ProtectedResourceMetadata}
     * derived from the `resource` it was built from.
     *
     * Named `…Controller` rather than `serveProtectedResourceMetadata` — the canonical
     * name §28.7's naming map pins for PHP — because Symfony's routing table is
     * declarative configuration (`routes.yaml`/attributes) rather than a runtime call
     * this SDK can hook, unlike Laravel's `Route::serveProtectedResourceMetadata()`
     * macro. The integrator wires this controller into their own routing configuration
     * at `$metadata->metadataPath` (see this repository's README for a worked example);
     * this class supplies everything CONTRACT.md §28.3's response rules require once
     * that route is hit, so nothing about the response itself is left to the
     * integrator to get right.
     *
     * The response is `200`, `Content-Type: application/json`, the document body
     * exactly, `Cache-Control: public, max-age=3600` and
     * `Access-Control-Allow-Origin: *` — identical for every caller, no
     * `Access-Control-Allow-Credentials`, and reachable with **no** credential of any
     * kind (§28.3 rules 1–6). {@see AxiamAuthSubscriber} listens on every request and
     * must itself exempt this exact path from authentication (see its own docblock);
     * this controller carries no auth logic of its own to duplicate that with.
     */
    final class ProtectedResourceMetadataController
    {
        /**
         * @param ProtectedResourceMetadata $metadata The value a prior
         *        `Mcp::protectedResourceMetadata(...)` call returned. Immutable, so the
         *        SAME response is served on every request (§28.3 rule 4).
         * @param AxiamAuthSubscriber|null $guard Optionally, the subscriber this
         *        document's guard is configured from — passing it lets this controller
         *        apply CONTRACT.md §28.5 rule 3's cross-check (refuse at construction
         *        when the subscriber's `resourceMetadataUrl`/`expectedAudience`
         *        disagree with `$metadata`) instead of silently publishing a document
         *        the guard does not agree with. Omit it when the guard runs in a
         *        separate process, where nothing can be cross-checked.
         */
        public function __construct(
            private readonly ProtectedResourceMetadata $metadata,
            ?AxiamAuthSubscriber $guard = null,
        ) {
            if ($guard !== null) {
                $guardOptions = $guard->mcpGuardOptions();
                if ($guardOptions !== null) {
                    Mcp::checkGuardAgreement($this->metadata, $guardOptions, $guard->client()->expectedAudience());
                }
            }
        }

        /** Serves the document (CONTRACT.md §28.3). */
        public function __invoke(): \Symfony\Component\HttpFoundation\JsonResponse
        {
            return Mcp::toJsonResponse($this->metadata);
        }
    }
}
