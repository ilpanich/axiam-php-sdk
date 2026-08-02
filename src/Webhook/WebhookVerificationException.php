<?php

declare(strict_types=1);

namespace Axiam\Sdk\Webhook;

/**
 * Thrown by {@see AxiamWebhooks::verify()} when a webhook delivery fails signature
 * verification (CONTRACT.md §13.3 rule 6: "fail closed and quiet").
 *
 * `getMessage()` is always a fixed, generic, reason-category string (e.g. "malformed
 * header", "signature mismatch", "timestamp outside tolerance") — it NEVER includes the
 * expected/computed signature, the raw secret, or any other value that could help an
 * attacker forge a signature or leak the secret into a log sink further up the call
 * stack. No structured reason code is exposed beyond the message category; callers that
 * need to distinguish failure reasons programmatically should not parse the message.
 */
final class WebhookVerificationException extends \RuntimeException
{
}
