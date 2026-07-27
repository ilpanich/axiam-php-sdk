<?php

declare(strict_types=1);

namespace Axiam\Sdk\Symfony;

use Axiam\Sdk\Oidc\OidcLoginFlow;
use Axiam\Sdk\Oidc\OidcLoginOutcome;

// D-01: guarded exactly like every other Symfony bridge class in this SDK (defense in
// depth — see {@see AxiamAuthSubscriber}'s own header comment). CONTRACT.md §12 /
// plan T8 item 2: this controller pair is OPTIONAL and OFF BY DEFAULT — `AxiamBundle`
// registers no route for it automatically. A consuming application must manually add a
// route pointing at this controller in its own `config/routes.yaml` (see
// `examples/symfony_app/oidc_routes.yaml`), exactly as it must manually tag
// `AxiamAuthSubscriber`/`AxiamVoter` today.
if (interface_exists(\Symfony\Component\EventDispatcher\EventSubscriberInterface::class)) {
    /**
     * Step 1 of "Login with AXIAM" (CONTRACT.md §12.1 `oidc_begin`): builds the
     * authorization request, parks its `state`/`nonce`/`code_verifier` in the
     * configured {@see \Axiam\Sdk\Oidc\OidcStateStoreInterface}, and redirects the
     * browser to the IdP. All security-critical logic lives in {@see OidcLoginFlow} —
     * this class only translates its {@see OidcLoginOutcome} into an HTTP response.
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

        /** Shared outcome → HTTP-response translation, reused by {@see OidcCallbackController}. */
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
