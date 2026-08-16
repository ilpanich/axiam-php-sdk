<?php

declare(strict_types=1);

namespace Axiam\Sdk\Attributes;

use Attribute;
use Axiam\Sdk\Reactor\ReactorEvents;
use InvalidArgumentException;

/**
 * Declares that a method handles one reactor hook event (CONTRACT.md §22.14,
 * canonical `reactor_handlers`).
 *
 * Placing this attribute on a method does not itself dispatch anything — it is
 * metadata read by {@see \Axiam\Sdk\Reactor\ReactorHandlers::of()}, which builds
 * the single `callable(ReactorEvent): ReactorAnswer` that
 * {@see \Axiam\Sdk\Reactor\ReactorServer} already takes. This mirrors how
 * {@see RequireAccess} carries §11 metadata for a framework listener to enforce.
 *
 * ```php
 * final class ClaimsReactor
 * {
 *     #[OnReactorEvent(ReactorEvents::TOKEN_PRE_ISSUE)]
 *     public function enrich(ReactorEvent $event): ReactorAnswer
 *     {
 *         return ReactorAnswer::mutate(['ext.department' => 'engineering']);
 *     }
 * }
 *
 * $handler = ReactorHandlers::of(new ClaimsReactor());
 * ```
 *
 * The event name is validated **in the constructor**, when the attribute is
 * instantiated by `ReactorHandlers::of()`, so a typo fails at wiring time rather
 * than becoming an event that silently never fires (§22.14 rule 2). A name
 * outside the §22.5 registry is refused — which is also how §22.7's hot-path
 * operations are refused, since they are in no registry row.
 */
#[Attribute(Attribute::TARGET_METHOD)]
final class OnReactorEvent
{
    /**
     * @param string $event A §22.5 registry event name, e.g.
     *                      {@see ReactorEvents::TOKEN_PRE_ISSUE}.
     *
     * @throws InvalidArgumentException when $event is outside the registry.
     */
    public function __construct(public readonly string $event)
    {
        // Delegated so the attribute and ReactorHandlers::bind() cannot drift:
        // there is one definition of "hookable", and it lives on the registry.
        ReactorEvents::assertHookable($event);
    }
}
