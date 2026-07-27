<?php

declare(strict_types=1);

/**
 * examples/laravel_app/oidc_routes.php — CONTRACT.md §12 "Login with AXIAM" (plan T8
 * item 2). OPTIONAL and OFF BY DEFAULT: unlike `axiam.auth`/`axiam.access`,
 * `AxiamServiceProvider` registers NO route for this on its own — an application opts
 * in explicitly, either of these two ways:
 *
 *   1. The route macro `AxiamServiceProvider::boot()` registers (this file's style):
 *      `Route::axiamOidcLogin('/auth/axiam/login', '/auth/axiam/callback')` wires BOTH
 *      routes to the pre-bound `Axiam\Sdk\Laravel\OidcLoginController`/
 *      `OidcCallbackController` singletons in one call.
 *   2. Wiring the same two controllers onto routes of your own choosing directly (see
 *      the commented-out alternative below) — useful if you want different paths or
 *      additional middleware on just one of the two.
 *
 * Required config/env (mirrors examples/laravel_app/README.md's table, plus the new
 * §12 keys — all resolved by `AxiamServiceProvider::register()`'s `OidcLoginFlow`
 * binding, config('axiam.oidc.*') falling back to AXIAM_OIDC_* env vars):
 *
 *   AXIAM_OIDC_CLIENT_ID       - the relying party's OAuth2 client_id (required)
 *   AXIAM_OIDC_CLIENT_SECRET   - confidential-client secret (optional — public client
 *                                without it can still complete this login flow;
 *                                introspect()/revoke()/loginClientCredentials() need it)
 *   AXIAM_OIDC_TENANT_ID       - tenant UUID for the /oauth2/* query parameter (§12.3
 *                                rule 4) — distinct from AXIAM_TENANT (the slug)
 *   AXIAM_OIDC_REDIRECT_URI    - MUST be this app's own public callback URL
 *   AXIAM_OIDC_SCOPE           - optional, defaults to "openid"
 *
 * The default `Axiam\Sdk\Oidc\OidcStateStoreInterface` binding is
 * `Axiam\Sdk\Oidc\MemoryOidcStateStore` (single-process only) — override that binding
 * in your own `AppServiceProvider` with a Redis/database-backed implementation for a
 * multi-instance deployment.
 */

use Illuminate\Support\Facades\Route;

// --- Option A: the route macro (registers BOTH routes in one call) -----------------
Route::axiamOidcLogin('/auth/axiam/login', '/auth/axiam/callback');

// --- Option B (commented out): wire the same controllers manually, e.g. to add your
// own middleware or a different path shape -------------------------------------------
// use Axiam\Sdk\Laravel\OidcCallbackController;
// use Axiam\Sdk\Laravel\OidcLoginController;
//
// Route::get('/login/axiam', OidcLoginController::class);
// Route::get('/login/axiam/callback', OidcCallbackController::class)->middleware('throttle:10,1');
