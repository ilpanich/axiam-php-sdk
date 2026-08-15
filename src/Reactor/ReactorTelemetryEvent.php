<?php

declare(strict_types=1);

namespace Axiam\Sdk\Reactor;

use Axiam\Sdk\Core\TelemetryEvent;

/**
 * One reactor-runtime telemetry event (CONTRACT.md §19, §22.8).
 *
 * PHP has no `sealed` keyword, so §19.2 rule 3's "no secrets, ever" is carried
 * structurally, the same way the rest of this SDK's §19 surface carries it: the
 * class is `final`, every property is a promoted `readonly` scalar drawn from a
 * fixed vocabulary, and there is no free-form array. There is nowhere to put the
 * signing key, the event payload or the patch.
 *
 * Wiring a hook is worth doing rather than optional. §22.8's last paragraph is why:
 * a `fail_open` timeout produces `allow` **and** an audit record, and that pair is
 * the whole difference between "no reactor was configured" and "the reactor never
 * answered". An SDK surfacing reactor health MUST NOT infer health from the
 * outcome alone — {@see self::PHASE_NO_REPLY} is how this runtime reports the
 * cases the outcome hides.
 */
final class ReactorTelemetryEvent extends TelemetryEvent
{
    /** The §19 operation name every reactor telemetry event carries. */
    public const OPERATION = 'reactorServe';

    /** A delivery passed every §22.3 check and is about to reach the handler. */
    public const PHASE_RECEIVED = 'received';

    /**
     * A delivery was refused BEFORE the handler ran. `$reason` is one of
     * {@see ReactorRejection}'s categories — never the received or expected MAC.
     */
    public const PHASE_REJECTED = 'rejected';

    /** A signed reply was published. `$decision` is the wire value. */
    public const PHASE_REPLIED = 'replied';

    /**
     * The delivery reached the handler but no reply was published, so the
     * registration's `failure_policy` decides (§22.8).
     */
    public const PHASE_NO_REPLY = 'no_reply';

    /**
     * @param string      $phase         One of the `PHASE_*` constants.
     * @param string      $event         The §22.5 event name, or `""` when the delivery was
     *                                   refused before its name could be trusted.
     * @param string      $correlationId The dispatch handle. Not a secret (§22.12), and the field
     *                                   that lets a reactor's own logs be joined to the server's
     *                                   audit records.
     * @param string|null $reason        A fixed-vocabulary rejection or no-reply category.
     * @param string|null $decision      The wire decision on {@see self::PHASE_REPLIED}.
     * @param float|null  $durationMs    Wall-clock time from receipt to publication.
     */
    public function __construct(
        public readonly string $phase,
        public readonly string $event,
        public readonly string $correlationId,
        public readonly ?string $reason = null,
        public readonly ?string $decision = null,
        public readonly ?float $durationMs = null,
    ) {
    }
}
