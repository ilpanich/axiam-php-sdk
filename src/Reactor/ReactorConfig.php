<?php

declare(strict_types=1);

namespace Axiam\Sdk\Reactor;

use Axiam\Sdk\Core\Sensitive;

/**
 * Identifies one reactor to {@see ReactorServer} (CONTRACT.md §22.1, §22.10,
 * §22.12).
 */
final class ReactorConfig
{
    /** @var non-empty-string */
    private readonly string $queue;

    /**
     * @param string       $tenantId   The tenant whose events this reactor serves. An event
     *                                 naming any other tenant is refused before the handler
     *                                 sees it.
     * @param Sensitive    $signingKey The tenant's HKDF-derived AMQP subkey (§8.1) — the same
     *                                 key that verifies the event and signs the reply, because
     *                                 §22.2's signing is symmetric in direction.
     *
     *                                 It MUST be fetched from the AXIAM management API;
     *                                 hardcoding one is prohibited. §22.12 requires the wrapper:
     *                                 it is a credential, it is never logged at any level, and
     *                                 it never appears in a reconnect diagnostic — which is why
     *                                 the type here is {@see Sensitive} rather than `string`.
     * @param string|null  $reactorId  This reactor's registration id. The queue name is derived
     *                                 from it when `$queue` is null.
     * @param string|null  $queue      Overrides the derived queue name. It is only ever the
     *                                 queue the SERVER declared for THIS reactor (§22.1) — a
     *                                 reactor never consumes, and never derives a name for,
     *                                 another reactor's queue.
     * @param string       $mode       {@see ReactorEvents::MODE_INTERCEPT} (the default) or
     *                                 {@see ReactorEvents::MODE_LISTEN}.
     * @param int          $skewSeconds The ±freshness window applied to an event's `issued_at`,
     *                                  which also sets the nonce seen-set TTL (2×skew).
     *
     * @throws \InvalidArgumentException when the configuration cannot identify a queue, names an
     *                                   unknown mode, or carries an empty signing key.
     */
    public function __construct(
        public readonly string $tenantId,
        public readonly Sensitive $signingKey,
        public readonly ?string $reactorId = null,
        ?string $queue = null,
        public readonly string $mode = ReactorEvents::MODE_INTERCEPT,
        public readonly int $skewSeconds = ReactorProtocol::FRESHNESS_SKEW_SECONDS,
    ) {
        if ($this->tenantId === '') {
            throw new \InvalidArgumentException('axiam: ReactorConfig requires a tenantId');
        }
        if ($this->signingKey->reveal() === '') {
            throw new \InvalidArgumentException(
                'axiam: ReactorConfig requires a signingKey — fetch the tenant AMQP subkey from the management API (§8.1)',
            );
        }
        if ($queue === null || $queue === '') {
            if ($reactorId === null || $reactorId === '') {
                throw new \InvalidArgumentException(
                    'axiam: ReactorConfig needs either a reactorId (to derive the server-declared queue) or an explicit queue',
                );
            }
            $queue = ReactorEvents::queueName($this->tenantId, $reactorId);
        }
        if (!in_array($this->mode, [ReactorEvents::MODE_INTERCEPT, ReactorEvents::MODE_LISTEN], true)) {
            throw new \InvalidArgumentException(
                'axiam: ReactorConfig mode must be "' . ReactorEvents::MODE_INTERCEPT
                . '" or "' . ReactorEvents::MODE_LISTEN . '"',
            );
        }
        if ($this->skewSeconds <= 0) {
            throw new \InvalidArgumentException('axiam: ReactorConfig skewSeconds must be > 0');
        }

        $this->queue = $queue;
    }

    /**
     * The queue this reactor consumes — the one the SERVER declared for it
     * (§22.1). Deriving the name is not the same as declaring it: nothing in this
     * SDK can declare or bind a queue.
     *
     * @return non-empty-string
     */
    public function queue(): string
    {
        return $this->queue;
    }

    /** Whether this registration is fire-and-forget observation (§22.5). */
    public function isListener(): bool
    {
        return $this->mode === ReactorEvents::MODE_LISTEN;
    }
}
