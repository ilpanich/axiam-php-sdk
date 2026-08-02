<?php

declare(strict_types=1);

namespace Axiam\Sdk\Webhook;

use Axiam\Sdk\Core\Sensitive;

/**
 * Verifies the `X-Axiam-Signature` HMAC-SHA256 header AXIAM attaches to every webhook
 * delivery (CONTRACT.md §13, T-145). Mirrors the server's signer
 * (`crates/axiam-api-rest/src/webhook.rs`'s `compute_signature_v2`): the MAC covers the
 * ASCII string `<t>.<raw_body>`, keyed with the webhook secret's raw UTF-8 bytes.
 */
final class AxiamWebhooks
{
    /**
     * The default freshness window (CONTRACT.md §13.2): a signature whose `t=` is more
     * than this far in the past OR the future (relative to the `$now` clock — see
     * {@see self::verify()}) is rejected.
     */
    public const DEFAULT_TOLERANCE_SECONDS = 300;

    /**
     * Verifies a webhook delivery's `X-Axiam-Signature` header against `$body` and
     * returns the parsed {@see WebhookEvent} on success.
     *
     * @param Sensitive    $secret          The webhook's plaintext signing secret (CONTRACT.md §7). Its raw
     *                                      UTF-8 bytes are the HMAC key.
     * @param string       $signatureHeader The raw, unparsed `X-Axiam-Signature` header value —
     *                                      `t=<unix_seconds>,v1=<hex>`, optionally with multiple `v1` entries
     *                                      during secret rotation.
     * @param string       $body            The **exact raw bytes** received off the wire, before any JSON
     *                                      decoding. Re-serializing a parsed body (different key order/whitespace)
     *                                      changes these bytes and breaks the MAC — callers MUST pass the
     *                                      untouched request body, e.g. `file_get_contents('php://input')` read
     *                                      BEFORE any framework has parsed it as JSON.
     * @param int          $toleranceSeconds The freshness window in seconds; a non-positive value falls back to
     *                                      {@see self::DEFAULT_TOLERANCE_SECONDS} (300). Rejects a `t=` more
     *                                      than this far in the past OR the future — a two-sided check, so a
     *                                      future-dated timestamp is rejected just like a stale one (clock-skew
     *                                      abuse).
     * @param (callable(): int)|null $now   Test/injection seam for "now" (unix seconds); defaults to `time()`.
     *                                      Pass a fake clock to deterministically exercise the freshness check.
     *
     * @throws WebhookVerificationException The header is malformed (no `v1`, more than one `t`, non-numeric
     *                                      `t`, or empty), no supplied `v1` matches the recomputed MAC, or `t`
     *                                      falls outside the freshness tolerance. The exception message is
     *                                      always a fixed, generic reason string — never the expected signature
     *                                      or the secret (CONTRACT.md §13.3 rule 6).
     */
    public static function verify(
        Sensitive $secret,
        string $signatureHeader,
        string $body,
        int $toleranceSeconds = self::DEFAULT_TOLERANCE_SECONDS,
        ?callable $now = null,
    ): WebhookEvent {
        $tolerance = $toleranceSeconds > 0 ? $toleranceSeconds : self::DEFAULT_TOLERANCE_SECONDS;
        $clock = $now ?? static fn (): int => time();

        // 1-2. Parse the header: exactly one `t`, at least one `v1` (a header with no
        // `v1` is always a failure — never treated as "nothing to check"), `t` must be
        // numeric.
        $parsed = self::parseHeader($signatureHeader);
        if ($parsed === null) {
            throw new WebhookVerificationException('Malformed X-Axiam-Signature header.');
        }
        [$timestampRaw, $v1Values] = $parsed;

        if (preg_match('/^-?\d+$/', $timestampRaw) !== 1) {
            throw new WebhookVerificationException('Malformed X-Axiam-Signature header: non-numeric timestamp.');
        }
        $timestamp = (int) $timestampRaw;

        // 3. Recompute HMAC-SHA256(secret, "<t>.<body>") — `<t>` is the EXACT raw text
        // that appeared in the `t=` field (not a reformatted/reparsed integer), matching
        // the bytes the server actually signed.
        $computed = hash_hmac('sha256', $timestampRaw . '.' . $body, $secret->reveal(), true);

        // 4. Constant-time compare against each supplied `v1`, on the DECODED bytes. A
        // failed hex decode fails closed for that candidate. Never `==` on hex strings.
        $matched = false;
        foreach ($v1Values as $v1) {
            $expected = @hex2bin($v1);
            if ($expected === false) {
                continue; // not valid hex -> this candidate can never match; fail closed for it
            }

            if (hash_equals($expected, $computed)) {
                $matched = true;
                break;
            }
        }

        if (!$matched) {
            throw new WebhookVerificationException('Webhook signature verification failed.');
        }

        // 5. Freshness — two-sided: reject stale AND future-dated timestamps.
        $nowTs = $clock();
        if (abs($nowTs - $timestamp) > $tolerance) {
            throw new WebhookVerificationException('Webhook timestamp outside the freshness tolerance window.');
        }

        // 6. Success — return the parsed event.
        [$eventType, $deliveryId] = self::parseEnvelope($body);

        return new WebhookEvent($timestamp, $body, $eventType, $deliveryId);
    }

    /**
     * Parses the comma-separated `key=value` pairs of an `X-Axiam-Signature` header.
     * Returns `null` (caller must reject) unless exactly one `t` and at least one
     * non-empty `v1` were found. Unknown keys are ignored for forward compatibility.
     *
     * @return array{0: string, 1: list<string>}|null [$timestampRaw, $v1Values], or null on any malformed shape.
     */
    private static function parseHeader(string $header): ?array
    {
        $timestampRaw = null;
        $v1Values = [];

        foreach (explode(',', $header) as $rawPart) {
            $part = trim($rawPart);
            if ($part === '') {
                continue;
            }

            $eq = strpos($part, '=');
            if ($eq === false || $eq === 0 || $eq === strlen($part) - 1) {
                continue; // not a well-formed key=value pair -> ignore (forward-compat)
            }

            $key = trim(substr($part, 0, $eq));
            $value = trim(substr($part, $eq + 1));

            if ($key === 't') {
                if ($timestampRaw !== null || $value === '') {
                    return null; // exactly one non-empty `t` is required
                }
                $timestampRaw = $value;
            } elseif ($key === 'v1') {
                if ($value !== '') {
                    $v1Values[] = $value;
                }
            }
            // else: unknown/future scheme key -> ignored, forward compat.
        }

        // A header with no `v1` is ALWAYS a failure — never "nothing to check" == success.
        if ($timestampRaw === null || $v1Values === []) {
            return null;
        }

        return [$timestampRaw, $v1Values];
    }

    /**
     * Best-effort parse of the verified body's `"event"`/`"id"` JSON fields. Never
     * throws and never affects the verification result — a non-JSON or
     * differently-shaped body still verifies successfully (only the raw bytes are
     * covered by the MAC), it simply yields `[null, null]` here.
     *
     * @return array{0: string|null, 1: string|null} [$eventType, $deliveryId]
     */
    private static function parseEnvelope(string $body): array
    {
        $decoded = json_decode($body, true);
        if (!is_array($decoded)) {
            return [null, null];
        }

        $eventType = isset($decoded['event']) && is_string($decoded['event']) ? $decoded['event'] : null;
        $deliveryId = isset($decoded['id']) && is_string($decoded['id']) ? $decoded['id'] : null;

        return [$eventType, $deliveryId];
    }
}
