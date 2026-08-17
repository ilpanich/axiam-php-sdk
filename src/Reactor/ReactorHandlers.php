<?php

declare(strict_types=1);

namespace Axiam\Sdk\Reactor;

use Axiam\Sdk\Attributes\OnReactorEvent;
use InvalidArgumentException;
use ReflectionClass;
use ReflectionMethod;

/**
 * Declarative reactor handler binding — CONTRACT.md §22.14.
 *
 * {@see ReactorServer} takes **one** callable from an event to one answer, which
 * is the right shape for the wire and the wrong shape for the code. A reactor
 * registered for three events opens with a `match ($event->event)`, and that
 * `match` carries two defects.
 *
 * The first is cheap: a misspelled event name is a valid string, matches no arm,
 * and is discovered as an event that never fires. The second is not. It is the
 * `default` arm, which is almost always written `ReactorAnswer::allow()`. That
 * answers on behalf of code that never ran — the defect §22.10 rule 2 forbids
 * the *runtime* from committing, relocated into user code where the rule does
 * not reach it. An operator who set `fail_closed` on a registration has it
 * defeated by a `default` arm in a file they never read.
 *
 * This class is the declarative form, in the spirit of §11's
 * {@see \Axiam\Sdk\Attributes\RequireAccess}: mark the methods, collect them,
 * hand the result to {@see ReactorServer}.
 *
 * ```php
 * final class ClaimsReactor
 * {
 *     #[OnReactorEvent(ReactorEvents::TOKEN_PRE_ISSUE)]
 *     public function enrich(ReactorEvent $event): ReactorAnswer { ... }
 *
 *     #[OnReactorEvent(ReactorEvents::LOGIN_POST_AUTH)]
 *     public function screen(ReactorEvent $event): ReactorAnswer { ... }
 * }
 *
 * $handlers = ReactorHandlers::of(new ClaimsReactor());
 * $server   = new ReactorServer($config, $transport, $handlers->handler());
 * ```
 *
 * It is **pure sugar** (§22.14 rule 1): what {@see self::handler()} returns is
 * exactly the callable {@see ReactorServer} already accepts. It opens nothing,
 * verifies nothing, signs nothing, and does not filter a patch (§22.10 rule 3).
 */
final class ReactorHandlers
{
    /** @var array<string, callable(ReactorEvent): ReactorAnswer> */
    private array $handlers = [];

    /**
     * Collect every `#[OnReactorEvent]`-marked public method on $sources.
     *
     * Methods are bound to their instance, so a class-based reactor keeps its
     * state and its constructor-injected collaborators.
     *
     * @param object ...$sources Objects whose public methods carry the attribute.
     *
     * @throws InvalidArgumentException on an unregistered event name (which is
     *                                  also how §22.7's hot-path operations are
     *                                  refused) or a second binding for an
     *                                  already-bound event.
     */
    public static function of(object ...$sources): self
    {
        $collected = new self();

        foreach ($sources as $source) {
            $reflection = new ReflectionClass($source);
            foreach ($reflection->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
                foreach ($method->getAttributes(OnReactorEvent::class) as $attribute) {
                    // newInstance() runs OnReactorEvent's constructor, which is
                    // where an unregistered name is refused (§22.14 rule 2).
                    $binding = $attribute->newInstance();
                    /** @var callable(ReactorEvent): ReactorAnswer $bound */
                    $bound = $method->getClosure($source);
                    $collected->bind($binding->event, $bound);
                }
            }
        }

        return $collected;
    }

    /**
     * Bind $handler to $event without an attribute.
     *
     * The imperative half of the same thing, for handlers that are closures
     * rather than methods. Governed by every §22.14 rule identically.
     *
     * @param callable(ReactorEvent): ReactorAnswer $handler
     *
     * @throws InvalidArgumentException when $event is outside the §22.5 registry
     *                                  — which is how §22.7's hot-path
     *                                  operations are refused, since they are in
     *                                  no registry row — or is already bound. A
     *                                  second binding is a mistake, never a
     *                                  silent overwrite: which of the two runs is
     *                                  not visible from either one.
     */
    public function bind(string $event, callable $handler): self
    {
        // One definition of "hookable", shared with #[OnReactorEvent], so the
        // two spellings of §22.14's binding cannot drift apart.
        ReactorEvents::assertHookable($event);

        if (isset($this->handlers[$event])) {
            throw new InvalidArgumentException(
                sprintf('reactor event %s is already bound', $event),
            );
        }

        $this->handlers[$event] = $handler;

        return $this;
    }

    /**
     * The bound event names, in binding order.
     *
     * Pass them to {@see ReactorEvents::defaultFailurePolicy()} to see what an
     * unreachable reactor costs — the strictest default among them (§22.8) —
     * derived from the code that handles the events rather than from a
     * restatement of the registration.
     *
     * @return list<string>
     */
    public function events(): array
    {
        return array_keys($this->handlers);
    }

    /**
     * Compose the bindings into the callable {@see ReactorServer} accepts.
     *
     * @return callable(ReactorEvent): ReactorAnswer
     *
     * @throws InvalidArgumentException when nothing is bound. A reactor that
     *                                  handles nothing would consume its queue
     *                                  and abstain from every event, which looks
     *                                  exactly like an outage.
     */
    public function handler(): callable
    {
        if ($this->handlers === []) {
            throw new InvalidArgumentException(
                'ReactorHandlers has no bindings; bind at least one event',
            );
        }

        $bound = $this->handlers;

        return static function (ReactorEvent $event) use ($bound): ReactorAnswer {
            $handler = $bound[$event->event] ?? null;
            if ($handler === null) {
                // §22.14 rule 4. NOT allow(): throwing publishes NO REPLY, so
                // the registration's failure_policy resolves this exactly as it
                // resolves a timeout (§22.8). This binder does not know what the
                // registration was for; the operator's policy does.
                throw new ReactorRejection(
                    ReactorRejection::UNKNOWN_EVENT,
                    sprintf('no reactor handler bound for %s', $event->event),
                );
            }

            // Called without a try/catch on purpose (§22.14 rule 5): a handler's
            // own throwable must reach ReactorServer unchanged so it publishes
            // nothing. Catching it here would satisfy the letter of §22.10
            // rule 2 while defeating it.
            return $handler($event);
        };
    }
}
