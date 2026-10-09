<?php

declare(strict_types=1);

namespace Axiam\Sdk\Ssf;

/**
 * A verified Security Event Token — {@see SsfReceiver::verifySet()}'s result (CONTRACT.md
 * §32.7).
 */
final class SecurityEvent
{
    /**
     * @param string               $jti       The SET's unique id.
     * @param int|float            $iat       When it was issued, seconds since the epoch.
     * @param string               $iss       The issuer, equal to the configured one.
     * @param string|list<mixed>   $aud       The audience as sent: one string, or an array containing yours.
     * @param string|null          $txn       The transaction id shared by every SET one operation produced.
     * @param string               $eventType The single `events` key — an event-type URI, see {@see SsfEventTypes}.
     * @param array<string,mixed>  $event     That event's object, opaque to the helper.
     * @param array<string,mixed>  $subId     The RFC 9493 subject identifier, opaque to the helper.
     */
    public function __construct(
        public readonly string $jti,
        public readonly int|float $iat,
        public readonly string $iss,
        public readonly string|array $aud,
        public readonly ?string $txn,
        public readonly string $eventType,
        public readonly array $event,
        public readonly array $subId,
    ) {
    }
}
