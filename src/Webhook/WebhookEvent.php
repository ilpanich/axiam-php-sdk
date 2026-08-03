<?php

declare(strict_types=1);

namespace Axiam\Sdk\Webhook;

/**
 * A webhook delivery whose `X-Axiam-Signature` has already been verified by
 * {@see AxiamWebhooks::verify()} (CONTRACT.md §13). {@see self::$eventType} and
 * {@see self::$deliveryId} are a best-effort parse of the verified body's `event`/`id`
 * JSON fields — a non-JSON or differently-shaped body still verifies successfully (the
 * MAC only covers the raw bytes, not their JSON shape), it simply leaves those two
 * properties `null`. Callers that need the delivery id for at-least-once dedup (§13.3
 * rule 7) should prefer the `X-Axiam-Delivery` header over relying solely on this parse.
 */
final class WebhookEvent
{
    /**
     * @param int         $timestamp The unix-seconds timestamp from the signature header's `t=` field (already checked against the freshness tolerance).
     * @param string      $body      The exact raw body bytes that were verified.
     * @param string|null $eventType The verified body's `"event"` field, or `null` if absent/not a string.
     * @param string|null $deliveryId The verified body's `"id"` field, or `null` if absent/not a string.
     */
    public function __construct(
        public readonly int $timestamp,
        public readonly string $body,
        public readonly ?string $eventType,
        public readonly ?string $deliveryId,
    ) {
    }
}
