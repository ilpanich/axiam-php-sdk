<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

/**
 * Internal §19 dispatcher. A null hook is the overwhelmingly common case and
 * costs one null check per request.
 */
final class TelemetryDispatcher
{
    /**
     * @param (callable(TelemetryEvent): void)|null $hook The caller's sink, or null.
     */
    public function __construct(private readonly mixed $hook = null)
    {
    }

    /**
     * Whether a hook is installed.
     */
    public function installed(): bool
    {
        return $this->hook !== null;
    }

    /**
     * Delivers `$event`, swallowing anything the caller's hook throws.
     *
     * §19.2 rule 2: telemetry is not permitted to fail an authorization check. A
     * hook that throws is the caller's bug, and letting it propagate here would
     * turn a metrics problem into an authorization failure.
     *
     * `\Error` is caught alongside `\Throwable`'s exception branch deliberately: a
     * sink with a type error is still the sink's bug, and an authorization check
     * should not die of it.
     */
    public function emit(TelemetryEvent $event): void
    {
        if ($this->hook === null) {
            return;
        }

        try {
            ($this->hook)($event);
        } catch (\Throwable) {
            // Deliberately swallowed; see above.
        }
    }

    /**
     * Opens a §19 request pair around one **attempt**.
     *
     * Per attempt, not per logical call: §19.2 rule 5 requires a caller to be able
     * to count real wire calls from the events, which one pair per operation would
     * hide — a retried call would look like a single slow one.
     *
     * @param string $operation    Canonical operation name.
     * @param string $method       HTTP method.
     * @param string $pathTemplate The route constant, never a substituted URL.
     * @param int    $attempt      The 1-based attempt number.
     * @return callable(int|null, string): void The closer for this pair.
     */
    public function startRequest(
        string $operation,
        string $method,
        string $pathTemplate,
        int $attempt,
    ): callable {
        if (!$this->installed()) {
            return static function (?int $status, string $outcome): void {
                // No hook: nothing to emit, and no clock read either.
            };
        }

        $this->emit(new RequestStartEvent($operation, $method, $pathTemplate, $attempt));
        $started = hrtime(true);

        return function (?int $status, string $outcome) use (
            $operation,
            $method,
            $pathTemplate,
            $attempt,
            $started,
        ): void {
            $this->emit(new RequestEndEvent(
                $operation,
                $method,
                $pathTemplate,
                $attempt,
                $status,
                (hrtime(true) - $started) / 1_000_000.0,
                $outcome,
            ));
        };
    }
}
