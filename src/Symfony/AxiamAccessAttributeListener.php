<?php

declare(strict_types=1);

namespace Axiam\Sdk\Symfony;

use Axiam\Sdk\AccessEnforcer;
use Axiam\Sdk\Attributes\RequireAccess;
use Axiam\Sdk\Attributes\RequireAuth;
use Axiam\Sdk\Attributes\RequireRole;

// D-01: the entire class definition is wrapped in an `interface_exists` guard, exactly
// like {@see AxiamAuthSubscriber} — this file never fatals if `symfony/event-dispatcher`/
// `symfony/http-kernel` happen to be absent, and PSR-4's lazy autoloading never even
// `require`s this file for a non-Symfony consumer.
if (interface_exists(\Symfony\Component\EventDispatcher\EventSubscriberInterface::class)) {
    /**
     * Symfony CONTRACT.md §11 declarative-authorization enforcement listener: an
     * `EventSubscriberInterface` on `KernelEvents::CONTROLLER` — the SAME extension
     * point Symfony's own `#[IsGranted]` attribute is enforced from
     * (`Symfony\Component\Security\Http\EventListener\IsGrantedAttributeListener`).
     * Once the framework has resolved the controller callable for the matched route,
     * this listener reflects that callable for `#[RequireAuth]`/`#[RequireAccess]`/
     * `#[RequireRole]` (method-level attributes take precedence over class-level ones,
     * mirroring the same override rule as annotation-based enforcement in every other
     * AXIAM SDK that ships this feature) and, when any are present, delegates the
     * actual decision to {@see AccessEnforcer} — this class contains NO authorization
     * logic of its own, only reflection + wiring.
     *
     * Identity comes from the `axiam_user` request attribute — the same one
     * {@see AxiamAuthSubscriber} populates on `kernel.request` (which runs strictly
     * BEFORE `kernel.controller`, so the identity is always already resolved by the
     * time this listener runs). A missing attribute (guard not installed, or the
     * request never authenticated) is treated as "no identity", which
     * {@see AccessEnforcer} maps to 401 — this listener never attempts its own token
     * extraction or verification (CONTRACT.md §11.2.1).
     *
     * Short-circuiting on `kernel.controller`: `ControllerEvent` (unlike
     * `RequestEvent`) has no `setResponse()` — the idiomatic way to abort at this stage
     * (the same technique Symfony's own `IsGrantedAttributeListener` effectively
     * achieves via the exception listener) is to REPLACE the resolved controller with
     * a zero-argument closure that simply returns the precomputed error response;
     * `kernel.view`/the HTTP kernel then invokes that closure instead of the original
     * controller, and its return value becomes the final response unchanged.
     *
     * MUST be manually registered (Pitfall 5, same as {@see AxiamAuthSubscriber} and
     * {@see AxiamVoter}): tag this class `kernel.event_subscriber` in the consuming
     * app's own `config/services.yaml` — see `examples/symfony_app/services.yaml`.
     */
    final class AxiamAccessAttributeListener implements \Symfony\Component\EventDispatcher\EventSubscriberInterface
    {
        public function __construct(private readonly AccessEnforcer $enforcer)
        {
        }

        /** @return array<string,string> */
        public static function getSubscribedEvents(): array
        {
            return [\Symfony\Component\HttpKernel\KernelEvents::CONTROLLER => 'onKernelController'];
        }

        /**
         * Reflects the resolved controller for `#[RequireAuth]`/`#[RequireRole]`/
         * `#[RequireAccess]` and, when any are present, enforces them via
         * {@see AccessEnforcer} — replacing the controller with a closure returning the
         * error response on the first failing check. Checks are evaluated in the order
         * auth -> role -> access (each of {@see AccessEnforcer}'s own methods re-checks
         * authentication internally too, so this ordering only affects which message a
         * caller sees first, never the correctness of the final decision).
         *
         * @param \Symfony\Component\HttpKernel\Event\ControllerEvent $event The
         *        kernel's controller-resolution event; its controller is replaced with
         *        an error-returning closure on a failing check.
         */
        public function onKernelController(\Symfony\Component\HttpKernel\Event\ControllerEvent $event): void
        {
            $reflected = $this->reflectController($event->getController());
            if ($reflected === null) {
                return;
            }
            [$method, $class] = $reflected;

            $requireAuth = $this->findAttribute($method, $class, RequireAuth::class);
            $requireRole = $this->findAttribute($method, $class, RequireRole::class);
            $requireAccess = $this->findAttribute($method, $class, RequireAccess::class);

            if ($requireAuth === null && $requireRole === null && $requireAccess === null) {
                return;
            }

            $request = $event->getRequest();
            $rawIdentity = $request->attributes->get('axiam_user');
            /** @var array{user_id: string, tenant_id: string, roles: list<string>}|null $identity */
            $identity = is_array($rawIdentity) ? $rawIdentity : null;

            $response = null;
            if ($requireAuth !== null) {
                $response = $this->enforcer->enforceAuth($identity);
            }
            if ($response === null && $requireRole !== null) {
                $response = $this->enforcer->enforceRole($identity, $requireRole);
            }
            if ($response === null && $requireAccess !== null) {
                $response = $this->enforcer->enforceAccess($identity, $requireAccess, $request->attributes->all());
            }

            if ($response !== null) {
                $event->setController(static fn (): \Symfony\Component\HttpFoundation\JsonResponse => $response);
            }
        }

        /**
         * Resolves the reflection pair `[ReflectionMethod, ReflectionClass]` for a
         * Symfony controller callable, or `null` when the callable has no attribute-bearing
         * class method to reflect (e.g. a plain `Closure`, which PHP forbids
         * `Attribute::TARGET_METHOD`/`TARGET_CLASS` attributes on entirely).
         *
         * Supports every controller shape Symfony itself resolves: `[$controllerInstance,
         * 'methodName']`, the string form `'App\Controller\Foo::bar'`, and an invokable
         * controller service/object (`__invoke`).
         *
         * @return array{0: \ReflectionMethod, 1: \ReflectionClass<object>}|null
         */
        private function reflectController(mixed $controller): ?array
        {
            if (is_array($controller) && count($controller) === 2) {
                [$objectOrClass, $methodName] = $controller;
                $className = is_object($objectOrClass) ? $objectOrClass::class : (string) $objectOrClass;
            } elseif (is_string($controller) && str_contains($controller, '::')) {
                [$className, $methodName] = explode('::', $controller, 2);
            } elseif (is_object($controller) && method_exists($controller, '__invoke')) {
                $className = $controller::class;
                $methodName = '__invoke';
            } else {
                return null;
            }

            if (!class_exists($className) || !method_exists($className, $methodName)) {
                return null;
            }

            try {
                return [new \ReflectionMethod($className, $methodName), new \ReflectionClass($className)];
            } catch (\ReflectionException) {
                return null;
            }
        }

        /**
         * Reads a single instance of `$attributeClass` off `$method`, falling back to
         * `$class` when the method carries none — method-level attributes take
         * precedence over class-level ones.
         *
         * @template T of object
         * @param class-string<T> $attributeClass
         * @param \ReflectionClass<object> $class
         *
         * @return T|null
         */
        private function findAttribute(\ReflectionMethod $method, \ReflectionClass $class, string $attributeClass): ?object
        {
            $methodAttributes = $method->getAttributes($attributeClass);
            if ($methodAttributes !== []) {
                /** @var T */
                return $methodAttributes[0]->newInstance();
            }

            $classAttributes = $class->getAttributes($attributeClass);
            if ($classAttributes !== []) {
                /** @var T */
                return $classAttributes[0]->newInstance();
            }

            return null;
        }
    }
}
