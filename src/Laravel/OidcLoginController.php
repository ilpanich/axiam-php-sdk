<?php

declare(strict_types=1);

namespace Axiam\Sdk\Laravel;

use Axiam\Sdk\Oidc\OidcLoginFlow;
use Axiam\Sdk\Oidc\OidcLoginOutcome;

// D-01: guarded exactly like every other Laravel bridge class in this SDK (defense in
// depth — PSR-4 autoloading is already lazy, so this file is only ever `require`d when
// an application actually references this class by name, e.g. in its own
// `routes/web.php`). CONTRACT.md §12 / plan T8 item 2: this controller — and the OIDC
// "Login with AXIAM" flow it fronts — is OPTIONAL and OFF BY DEFAULT.
// `AxiamServiceProvider` registers no route for it automatically; an application must
// explicitly add a route pointing at this controller (see
// `examples/laravel_app/oidc_routes.php`).
if (class_exists(\Symfony\Component\HttpFoundation\Request::class)) {
    /**
     * Step 1 of "Login with AXIAM" (CONTRACT.md §12.1 `oidc_begin`): an invokable
     * controller that builds the authorization request, parks its
     * `state`/`nonce`/`code_verifier` in the configured
     * {@see \Axiam\Sdk\Oidc\OidcStateStoreInterface}, and redirects the browser to the
     * IdP. All security-critical logic lives in {@see OidcLoginFlow} — this class only
     * translates its {@see OidcLoginOutcome} into an HTTP response, exactly as
     * {@see AxiamMiddleware} never duplicates {@see \Axiam\Sdk\AxiamClient}'s own
     * verification logic.
     *
     * Type-hinted against `Symfony\Component\HttpFoundation\Request`/`Response`
     * (already the pattern {@see AxiamMiddleware} uses) rather than
     * `Illuminate\Http\*`, so this class needs no new runtime dependency beyond what a
     * Laravel application already ships transitively (D-01).
     */
    final class OidcLoginController
    {
        public function __construct(private readonly OidcLoginFlow $flow)
        {
        }

        /** Handles the login GET request and returns the mapped HTTP response (a redirect to the IdP, or a 503 error body). */
        public function __invoke(\Symfony\Component\HttpFoundation\Request $request): \Symfony\Component\HttpFoundation\Response
        {
            $returnTo = $request->query->get('return_to');

            return self::toResponse($this->flow->begin(is_string($returnTo) ? $returnTo : null));
        }

        /**
         * Shared outcome → HTTP-response translation, reused by
         * {@see OidcCallbackController} (both add nothing of their own beyond this
         * translation, mirroring how {@see AxiamMiddleware}/{@see AxiamAuthSubscriber}
         * independently — but identically — build their own 401/403 bodies).
         */
        public static function toResponse(OidcLoginOutcome $outcome): \Symfony\Component\HttpFoundation\Response
        {
            return match ($outcome->kind) {
                OidcLoginOutcome::KIND_REDIRECT => new \Symfony\Component\HttpFoundation\RedirectResponse((string) $outcome->redirectUrl),
                OidcLoginOutcome::KIND_JSON => new \Symfony\Component\HttpFoundation\JsonResponse($outcome->jsonBody()),
                default => new \Symfony\Component\HttpFoundation\JsonResponse($outcome->errorBody(), (int) $outcome->status),
            };
        }
    }
}
