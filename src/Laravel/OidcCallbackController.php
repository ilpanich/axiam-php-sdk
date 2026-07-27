<?php

declare(strict_types=1);

namespace Axiam\Sdk\Laravel;

use Axiam\Sdk\Oidc\OidcLoginFlow;

// D-01 / CONTRACT.md §12 (plan T8 item 2): guarded and optional exactly like
// {@see OidcLoginController} — see that class's own header comment.
if (class_exists(\Symfony\Component\HttpFoundation\Request::class)) {
    /**
     * Step 2 of "Login with AXIAM" (CONTRACT.md §12.1 `oidc_exchange`): an invokable
     * controller that validates the IdP callback, consumes the single-use stored
     * state, exchanges the authorization code, and redirects (or replies `200 JSON`)
     * on success. All security-critical logic lives in {@see OidcLoginFlow} — see
     * {@see OidcLoginFlow::complete()} for the full 400/401/503 failure mapping.
     */
    final class OidcCallbackController
    {
        public function __construct(private readonly OidcLoginFlow $flow)
        {
        }

        /** Handles the IdP callback GET request and returns the mapped HTTP response. */
        public function __invoke(\Symfony\Component\HttpFoundation\Request $request): \Symfony\Component\HttpFoundation\Response
        {
            $state = $request->query->get('state');
            $code = $request->query->get('code');
            $error = $request->query->get('error');
            $errorDescription = $request->query->get('error_description');

            $outcome = $this->flow->complete(
                state: is_string($state) ? $state : null,
                code: is_string($code) ? $code : null,
                error: is_string($error) ? $error : null,
                errorDescription: is_string($errorDescription) ? $errorDescription : null,
            );

            return OidcLoginController::toResponse($outcome);
        }
    }
}
