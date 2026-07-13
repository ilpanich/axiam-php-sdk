<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Laravel\AxiamGate;
use Axiam\Sdk\Laravel\AxiamMiddleware;
use Axiam\Sdk\Laravel\AxiamServiceProvider;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Gate;
use PHPUnit\Framework\TestCase;

/**
 * SC#4-Laravel / D-01/D-02 proof for the auto-discovered {@see AxiamServiceProvider}:
 * drives its `register()` (singleton bindings for {@see AxiamClient}/{@see AxiamMiddleware}/
 * {@see AxiamGate}, configured from `config('axiam.*')` with `AXIAM_*` env fallback) and
 * `boot()` (the `axiam.auth` route-middleware alias and the `axiam` Gate ability) through a
 * lightweight container double — the provider's `$app` is untyped, so a minimal
 * `bound()/make()/singleton()` fake plus the Facade wiring is enough to exercise every
 * binding closure without pulling in `illuminate/container`/`illuminate/foundation`.
 *
 * Skipped automatically when `illuminate/support` is absent (the same reason the other
 * Laravel bridge tests live in the `integration` testsuite): a REST-only consumer never
 * installs it, and the provider class only exists behind a `class_exists` guard (D-01).
 */
final class LaravelServiceProviderTest extends TestCase
{
    /** @var array<string, string> env vars this test set and must restore */
    private array $envBackup = [];

    protected function setUp(): void
    {
        if (!class_exists(\Illuminate\Support\ServiceProvider::class)) {
            self::markTestSkipped('illuminate/support not installed (REST-only consumer)');
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->envBackup as $name => $_) {
            putenv($name);
        }
        $this->envBackup = [];
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);
    }

    private function setEnv(string $name, string $value): void
    {
        $this->envBackup[$name] = $name;
        putenv("{$name}={$value}");
    }

    /**
     * Builds a minimal container double sufficient for the provider. `$config` maps
     * dotted config keys to values (config is considered "bound" only when non-null).
     *
     * @param array<string, mixed>|null $config
     */
    private function makeApp(?array $config, object $router, object $gate): object
    {
        return new class($config, $router, $gate) implements \ArrayAccess {
            /** @var array<string, \Closure> */
            private array $singletons = [];

            /** @var array<string, object> */
            private array $resolved = [];

            /**
             * @param array<string, mixed>|null $config
             */
            public function __construct(
                private readonly ?array $config,
                private readonly object $router,
                private readonly object $gate,
            ) {
            }

            public function singleton(string $abstract, \Closure $concrete): void
            {
                $this->singletons[$abstract] = $concrete;
            }

            public function bound(string $name): bool
            {
                if ($name === 'config') {
                    return $this->config !== null;
                }
                if ($name === 'router') {
                    return true;
                }

                return isset($this->singletons[$name]) || isset($this->resolved[$name]);
            }

            public function make(string $name): mixed
            {
                if ($name === 'config') {
                    $config = $this->config ?? [];

                    return new class($config) {
                        /** @param array<string, mixed> $values */
                        public function __construct(private readonly array $values)
                        {
                        }

                        public function get(string $key, mixed $default = null): mixed
                        {
                            return $this->values[$key] ?? $default;
                        }
                    };
                }
                if ($name === 'router') {
                    return $this->router;
                }
                if (isset($this->resolved[$name])) {
                    return $this->resolved[$name];
                }
                if (isset($this->singletons[$name])) {
                    return $this->resolved[$name] = ($this->singletons[$name])($this);
                }

                throw new \RuntimeException("unbound: {$name}");
            }

            public function offsetExists(mixed $offset): bool
            {
                return true;
            }

            public function offsetGet(mixed $offset): mixed
            {
                // The Gate facade resolves its accessor (the Gate contract) through here.
                return $this->gate;
            }

            public function offsetSet(mixed $offset, mixed $value): void
            {
            }

            public function offsetUnset(mixed $offset): void
            {
            }
        };
    }

    private function makeRouter(): object
    {
        return new class {
            /** @var array<string, string> */
            public array $aliases = [];

            public function aliasMiddleware(string $alias, string $class): void
            {
                $this->aliases[$alias] = $class;
            }
        };
    }

    private function makeGate(): object
    {
        return new class {
            /** @var array<string, callable> */
            public array $abilities = [];

            public function define(string $ability, callable $callback): void
            {
                $this->abilities[$ability] = $callback;
            }
        };
    }

    public function testRegisterBindsClientFromConfigValues(): void
    {
        $router = $this->makeRouter();
        $gate = $this->makeGate();
        $app = $this->makeApp([
            'axiam.base_url' => 'https://api.test',
            'axiam.tenant' => 'acme-tenant',
            'axiam.custom_ca' => '/etc/ssl/custom-ca.pem',
        ], $router, $gate);

        $provider = new AxiamServiceProvider($app);
        $provider->register();

        $client = $app->make(AxiamClient::class);
        self::assertInstanceOf(AxiamClient::class, $client);
        // customCa is threaded through as the Guzzle `verify` CA path (§6/D-12).
        self::assertSame('/etc/ssl/custom-ca.pem', $client->debugVerifyOption());

        self::assertInstanceOf(AxiamMiddleware::class, $app->make(AxiamMiddleware::class));
        self::assertInstanceOf(AxiamGate::class, $app->make(AxiamGate::class));
    }

    public function testRegisterFallsBackToEnvWhenNoConfigBound(): void
    {
        $this->setEnv('AXIAM_BASE_URL', 'https://env.test');
        $this->setEnv('AXIAM_TENANT', 'env-tenant');
        // AXIAM_CUSTOM_CA left unset -> customCa resolves to null -> verify === true.

        $router = $this->makeRouter();
        $gate = $this->makeGate();
        $app = $this->makeApp(null, $router, $gate);

        $provider = new AxiamServiceProvider($app);
        $provider->register();

        $client = $app->make(AxiamClient::class);
        self::assertInstanceOf(AxiamClient::class, $client);
        self::assertTrue($client->debugVerifyOption());

        // The middleware singleton also resolves its tenant from the env fallback.
        self::assertInstanceOf(AxiamMiddleware::class, $app->make(AxiamMiddleware::class));
    }

    public function testBootRegistersMiddlewareAliasAndGateAbility(): void
    {
        $router = $this->makeRouter();
        $gate = $this->makeGate();
        $app = $this->makeApp([
            'axiam.base_url' => 'https://api.test',
            'axiam.tenant' => 'acme-tenant',
        ], $router, $gate);

        // The `axiam` Gate ability is defined via the Gate facade -> resolve our double.
        Facade::setFacadeApplication($app);
        Facade::clearResolvedInstances();

        $provider = new AxiamServiceProvider($app);
        $provider->register();
        $provider->boot();

        self::assertSame(AxiamMiddleware::class, $router->aliases['axiam.auth'] ?? null);
        self::assertArrayHasKey('axiam', $gate->abilities);
        self::assertIsCallable($gate->abilities['axiam']);
        // Sanity: the facade root really was our double.
        self::assertSame($gate, Gate::getFacadeRoot());
    }
}
