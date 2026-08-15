<?php

declare(strict_types=1);

namespace Axiam\Sdk\Reactor;

/**
 * One hook firing, delivered to a reactor and **already verified**
 * (CONTRACT.md §22.3).
 *
 * By the time a handler sees one of these, its `key_version`, MAC, freshness and
 * nonce have all been checked, in that order. A runtime that hands an unverified
 * payload to user code has already lost — the handler will act on it, and "we
 * checked afterwards" is not a check.
 *
 * §22.12: the `payload`, the `patch`, the `reason` and the `decision` are **not**
 * sensitive in the §7 sense and remain readable, because a handler that cannot
 * inspect the event cannot decide anything. They are, however, tenant business
 * data — do not log the payload at info level. The `nonce`, `correlationId` and
 * the signature are not secrets and may be logged for correlation.
 */
final class ReactorEvent
{
    /**
     * @param string               $tenantId      The tenant this event belongs to.
     * @param string               $event         The §22.5 registry name, e.g.
     *                                            {@see ReactorEvents::TOKEN_PRE_ISSUE}.
     * @param string               $correlationId The single-use handle for this dispatch. The
     *                                            runtime copies it from the EVENT BODY into the
     *                                            REPLY BODY; copying it only into the AMQP property
     *                                            produces a reply the server discards (§22.1).
     * @param array<string, mixed> $payload       The event-specific body. It never carries a
     *                                            credential, a token or a signing key — a reactor is
     *                                            told what is being decided, not handed the means to
     *                                            act on it elsewhere.
     * @param int                  $timeoutMs     How long the server will wait for THIS dispatch. It
     *                                            is inside the signed body, so it cannot be widened
     *                                            in transit.
     * @param string               $nonce         The §8 v2 replay nonce. Not a secret.
     * @param int                  $issuedAt      The signed `issued_at`, as a Unix timestamp.
     * @param float                $deadline      When the runtime stops waiting on the handler: the
     *                                            moment this delivery was RECEIVED plus `timeoutMs`,
     *                                            as a Unix timestamp with fractional seconds.
     *
     *                                            Measured from receipt rather than from `issuedAt`
     *                                            on purpose: the freshness window is ±300 s while a
     *                                            timeout is typically 500 ms, so a clock a couple of
     *                                            seconds behind the server would compute a window
     *                                            that has already closed for every event and answer
     *                                            nothing at all.
     */
    public function __construct(
        public readonly string $tenantId,
        public readonly string $event,
        public readonly string $correlationId,
        public readonly array $payload,
        public readonly int $timeoutMs,
        public readonly string $nonce,
        public readonly int $issuedAt,
        public readonly float $deadline,
    ) {
    }

    /**
     * This event's §22.5 registry entry.
     *
     * Never null in practice: the runtime refuses a name outside the registry
     * before a handler is ever called.
     */
    public function spec(): ?ReactorEventSpec
    {
        return ReactorEvents::specFor($this->event);
    }

    /**
     * The patch accumulated by earlier reactors in the chain (§22.3's
     * `_reactor_patch`), or null when this is the first reactor consulted.
     *
     * It is READ-ONLY context, provided so a later reactor decides against the
     * state that will actually be committed. Echoing it back inside this reactor's
     * own patch is **not** how a field is preserved: the server merges the chain
     * itself, as a union with last-write-wins per key (§22.6).
     *
     * @return array<string, string>|null
     */
    public function chainPatch(): ?array
    {
        $prior = $this->payload[ReactorProtocol::CHAIN_PATCH_KEY] ?? null;
        if (!is_array($prior)) {
            return null;
        }

        $patch = [];
        foreach ($prior as $key => $value) {
            if (is_string($value)) {
                $patch[(string) $key] = $value;
            }
        }

        return $patch;
    }
}
