<?php

declare(strict_types=1);

namespace Axiam\Sdk\Laravel;

use Axiam\Sdk\AccessEnforcer;
use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Oidc\MemoryOidcStateStore;
use Axiam\Sdk\Oidc\OidcLoginFlow;
use Axiam\Sdk\Oidc\OidcStateStoreInterface;

// D-01: the entire class definition is wrapped in a `class_exists` guard so that
// autoloading this file (which only ever happens because a real Laravel application
// listed it under `extra.laravel.providers` and Laravel's own package-discovery
// mechanism referenced it by name) never fatals if `illuminate/support` happens to be
// absent for any reason — a non-Laravel consumer of `axiam/axiam-sdk` never triggers
// Laravel's discovery mechanism at all, so this file is never even `require`d in that
// case (PSR-4 autoloading is lazy), but the guard is added as defense-in-depth per this
// plan's own `must_haves` (never assume the class is unreachable by name alone).
if (class_exists(\Illuminate\Support\ServiceProvider::class)) {
    /**
     * Auto-discovered Laravel bridge entry point (D-01): listed under `composer.json`
     * `extra.laravel.providers`, so a Laravel consumer gets this provider registered
     * with ZERO manual wiring beyond `composer require axiam/axiam-sdk` (true
     * zero-config auto-discovery, unlike the Symfony bridge which has no equivalent
     * mechanism without a published Flex recipe).
     *
     * `register()` binds a singleton {@see AxiamClient} configured from
     * `config('axiam.*')` (falling back to `AXIAM_*` environment variables so a
     * consumer never needs to publish a config file to get started). `boot()`
     * registers the `axiam.auth` middleware alias ({@see AxiamMiddleware}) and the
     * `axiam` Gate ability ({@see AxiamGate}, D-02) — `can:axiam,<resource>,<action>`
     * route middleware then works out of the box — plus the `axiam.access` middleware
     * alias ({@see AxiamAccessMiddleware}, backed by {@see AccessEnforcer}, CONTRACT.md
     * §11) for the declarative `#[RequireAuth]`/`#[RequireAccess]`/`#[RequireRole]`
     * helpers.
     */
    final class AxiamServiceProvider extends \Illuminate\Support\ServiceProvider
    {
        public function register(): void
        {
            $this->app->singleton(AxiamClient::class, static function ($app): AxiamClient {
                $config = $app->bound('config') ? $app->make('config') : null;

                $baseUrl = $config !== null
                    ? (string) $config->get('axiam.base_url', getenv('AXIAM_BASE_URL') ?: '')
                    : (string) (getenv('AXIAM_BASE_URL') ?: '');
                $tenant = $config !== null
                    ? (string) $config->get('axiam.tenant', getenv('AXIAM_TENANT') ?: '')
                    : (string) (getenv('AXIAM_TENANT') ?: '');
                $customCa = $config !== null
                    ? $config->get('axiam.custom_ca', getenv('AXIAM_CUSTOM_CA') ?: null)
                    : (getenv('AXIAM_CUSTOM_CA') ?: null);

                // CONTRACT.md §12 (optional, off by default — a §1–§11-only consumer
                // never sets these env vars/config keys and every §12 call is simply
                // unreachable from routes it never registers).
                $oidcClientId = $config !== null
                    ? $config->get('axiam.oidc.client_id', getenv('AXIAM_OIDC_CLIENT_ID') ?: null)
                    : (getenv('AXIAM_OIDC_CLIENT_ID') ?: null);
                $oidcClientSecret = $config !== null
                    ? $config->get('axiam.oidc.client_secret', getenv('AXIAM_OIDC_CLIENT_SECRET') ?: null)
                    : (getenv('AXIAM_OIDC_CLIENT_SECRET') ?: null);
                $oidcTenantId = $config !== null
                    ? $config->get('axiam.oidc.tenant_id', getenv('AXIAM_OIDC_TENANT_ID') ?: null)
                    : (getenv('AXIAM_OIDC_TENANT_ID') ?: null);

                return new AxiamClient(
                    baseUrl: $baseUrl,
                    tenant: $tenant,
                    customCa: is_string($customCa) && $customCa !== '' ? $customCa : null,
                    oidcClientId: is_string($oidcClientId) && $oidcClientId !== '' ? $oidcClientId : null,
                    oidcClientSecret: is_string($oidcClientSecret) && $oidcClientSecret !== '' ? $oidcClientSecret : null,
                    oidcTenantId: is_string($oidcTenantId) && $oidcTenantId !== '' ? $oidcTenantId : null,
                );
            });

            $this->app->singleton(AxiamMiddleware::class, function ($app): AxiamMiddleware {
                $config = $app->bound('config') ? $app->make('config') : null;
                $tenant = $config !== null
                    ? (string) $config->get('axiam.tenant', getenv('AXIAM_TENANT') ?: '')
                    : (string) (getenv('AXIAM_TENANT') ?: '');

                return new AxiamMiddleware($app->make(AxiamClient::class), $tenant);
            });

            $this->app->singleton(AxiamGate::class, static fn ($app): AxiamGate => new AxiamGate(
                $app->make(AxiamClient::class),
            ));

            // CONTRACT.md §11: one shared AccessEnforcer, reused by both the
            // axiam.access middleware here and (independently) the Symfony bridge.
            $this->app->singleton(AccessEnforcer::class, static fn ($app): AccessEnforcer => new AccessEnforcer(
                $app->make(AxiamClient::class),
            ));

            $this->app->singleton(AxiamAccessMiddleware::class, static fn ($app): AxiamAccessMiddleware => new AxiamAccessMiddleware(
                $app->make(AccessEnforcer::class),
            ));

            // CONTRACT.md §12 (plan T8 item 2, optional/off-by-default): a default
            // in-memory state store — an application that needs a shared (multi-instance)
            // store overrides this binding with its own OidcStateStoreInterface
            // implementation, exactly like any other Laravel container binding.
            $this->app->singleton(OidcStateStoreInterface::class, static fn (): MemoryOidcStateStore => new MemoryOidcStateStore());

            $this->app->singleton(OidcLoginFlow::class, static function ($app): OidcLoginFlow {
                $config = $app->bound('config') ? $app->make('config') : null;
                $redirectUri = $config !== null
                    ? (string) $config->get('axiam.oidc.redirect_uri', getenv('AXIAM_OIDC_REDIRECT_URI') ?: '')
                    : (string) (getenv('AXIAM_OIDC_REDIRECT_URI') ?: '');
                $scope = $config !== null
                    ? $config->get('axiam.oidc.scope', getenv('AXIAM_OIDC_SCOPE') ?: null)
                    : (getenv('AXIAM_OIDC_SCOPE') ?: null);

                return new OidcLoginFlow(
                    client: $app->make(AxiamClient::class),
                    store: $app->make(OidcStateStoreInterface::class),
                    redirectUri: $redirectUri,
                    scope: is_string($scope) && $scope !== '' ? $scope : null,
                );
            });

            $this->app->singleton(OidcLoginController::class, static fn ($app): OidcLoginController => new OidcLoginController(
                $app->make(OidcLoginFlow::class),
            ));
            $this->app->singleton(OidcCallbackController::class, static fn ($app): OidcCallbackController => new OidcCallbackController(
                $app->make(OidcLoginFlow::class),
            ));
        }

        /**
         * Registers the `axiam.auth` route-middleware alias so applications can guard routes with
         * `->middleware('axiam.auth')` (D-02, §10) instead of referencing the middleware class.
         */
        public function boot(): void
        {
            // Route middleware alias — `->middleware('axiam.auth')` (D-02, §10).
            if ($this->app->bound('router')) {
                $this->app->make('router')->aliasMiddleware('axiam.auth', AxiamMiddleware::class);

                // CONTRACT.md §11: ->middleware('axiam.access:ACTION,SCOPE,RESOURCE_PARAM')
                // (SCOPE and RESOURCE_PARAM optional) or, with no params,
                // attribute-reflection off the resolved controller (see
                // AxiamAccessMiddleware's own docblock for both styles).
                $this->app->make('router')->aliasMiddleware('axiam.access', AxiamAccessMiddleware::class);
            }

            // CONTRACT.md §12 (plan T8 item 2): a route MACRO, not an auto-registered
            // route — calling Route::axiamOidcLogin() is what an application does to
            // opt IN to the "Login with AXIAM" flow; nothing here registers a route on
            // its own, so a §1–§11-only consumer is completely unaffected.
            if (class_exists(\Illuminate\Support\Facades\Route::class)) {
                // Deliberately calls the Route FACADE (not `$this->get(...)`) so this
                // closure needs no `illuminate/routing`-typed `$this` binding — this
                // package declares no runtime dependency on `illuminate/routing` at all
                // (D-01), only on `illuminate/support`/`illuminate/contracts`.
                \Illuminate\Support\Facades\Route::macro(
                    'axiamOidcLogin',
                    function (string $loginPath = '/auth/axiam/login', string $callbackPath = '/auth/axiam/callback'): void {
                        \Illuminate\Support\Facades\Route::get($loginPath, OidcLoginController::class);
                        \Illuminate\Support\Facades\Route::get($callbackPath, OidcCallbackController::class);
                    },
                );
            }

            // The `axiam` Gate ability — `can:axiam,<resource>,<action>` route
            // middleware (D-02). The server's additive-only RBAC is authoritative: this
            // callback never caches or overrides the decision, it is a one-line
            // delegation via {@see AxiamGate::allows()} -> {@see AxiamClient::can()}.
            if (class_exists(\Illuminate\Support\Facades\Gate::class)) {
                \Illuminate\Support\Facades\Gate::define(
                    'axiam',
                    fn ($user, string $resource, string $action): bool => $this->app
                        ->make(AxiamGate::class)
                        ->allows($resource, $action),
                );
            }
        }
    }
}
