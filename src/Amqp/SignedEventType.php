<?php

declare(strict_types=1);

namespace Axiam\Sdk\Amqp;

/**
 * The one signed AMQP event type a {@see Consumer} is configured for (CONTRACT.md §8 step 2c,
 * contract 1.69 "Typed: one configured type"). A consumer checks the canonical bytes against this
 * type's layout only; an application that consumes both types runs two consumers.
 */
enum SignedEventType: string
{
    case AuthzRequest = 'AuthzRequest';
    case AuditEventMessage = 'AuditEventMessage';
}
