<?php

declare(strict_types=1);

namespace Axiam\Sdk\Reactor;

use Axiam\Sdk\Amqp\ReplayGuard;

/**
 * The reactor wire protocol — CONTRACT.md §22.2, §22.3, §22.4.
 *
 * Both directions are signed with the same §8 v2 primitives and the same tenant
 * subkey: the server signs the event, the reactor signs the reply. A reply is an
 * instruction to change a token or refuse a login, so an unsigned reply is not a
 * weak reply — it is not a reply at all, and the server discards it as though the
 * reactor had never answered.
 *
 * THE ONE CANONICALIZATION DIFFERENCE FROM §8. On a reactor event and a reactor
 * reply, `hmac_signature` is serialized as JSON **null** inside the signed bytes.
 * It is NOT omitted, which is what §8's own two message types (`AuthzRequest`,
 * `AuditEventMessage` — see {@see \Axiam\Sdk\Amqp\Hmac}) do. Getting this wrong
 * produces a MAC that never verifies in either direction, so the §22.13 vectors
 * carry `canonical_signed_json` for every message and
 * `tests/ReactorVectorsTest.php` asserts against them byte-for-byte rather than
 * against anyone's memory of this paragraph.
 *
 * THE PHP-SPECIFIC TRAPS, all of which this class encodes once:
 *
 *  - `json_encode()` escapes forward slashes and non-ASCII by default and
 *    `serde_json` escapes neither, so every call here passes
 *    `JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE` (the same Pitfall 1 the §8
 *    `Hmac` class documents).
 *  - Bodies are decoded to `stdClass`, **not** to associative arrays. An empty
 *    JSON object decoded into an array re-encodes as `[]` rather than `{}`, which
 *    silently changes the canonical bytes of any event whose `payload` is empty.
 *  - A reply's `patch` is written through a `stdClass` and key-sorted with
 *    `SORT_STRING`, because the server's `BTreeMap<String, String>` emits its keys
 *    in byte order while a PHP array emits them in insertion order.
 */
final class ReactorProtocol
{
    /**
     * The §8 v2 key version both directions carry. A body carrying less than this
     * is refused **before anything else about it is considered** — including its
     * signature (§22.2, §22.4 row 4).
     */
    public const KEY_VERSION = 2;

    /**
     * The ±freshness window, in seconds, applied to `issued_at` in **both**
     * directions. A future timestamp is not "extra fresh", it is the shape of a
     * captured message held for later.
     */
    public const FRESHNESS_SKEW_SECONDS = ReplayGuard::DEFAULT_SKEW_SECONDS;

    /**
     * The payload key under which the server inserts the patch accumulated by
     * earlier reactors in the chain (§22.3), so a later reactor decides against
     * the state that will actually be committed.
     */
    public const CHAIN_PATCH_KEY = '_reactor_patch';

    /** The JSON flags that make PHP's encoder agree with `serde_json`. */
    private const JSON_FLAGS = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;

    /**
     * Serializes `$message` to the exact bytes HMAC runs over.
     *
     * The caller is responsible for property order — PHP preserves the order
     * properties were assigned in, which is how the server's serde
     * field-declaration order is reproduced without a sorting helper.
     */
    public static function canonicalize(\stdClass $message): string
    {
        $json = json_encode($message, self::JSON_FLAGS);
        if ($json === false) {
            throw new ReactorRejection(
                ReactorRejection::MALFORMED,
                'axiam: a reactor message could not be canonicalized to JSON',
            );
        }

        return $json;
    }

    /**
     * HMAC-SHA256 of `$canonical` under the tenant's HKDF-derived AMQP subkey
     * (§8.1, §22.2), hex-encoded. There is no second key and no asymmetric variant
     * in v1.
     */
    public static function sign(string $signingKey, string $canonical): string
    {
        return hash_hmac('sha256', $canonical, $signingKey);
    }

    /**
     * Constant-time verification of a hex-encoded MAC. Never throws: a non-hex or
     * wrong-length signature verifies as false.
     */
    public static function verify(string $signingKey, string $canonical, string $signatureHex): bool
    {
        $expected = @hex2bin($signatureHex);
        if ($expected === false) {
            return false;
        }

        return hash_equals($expected, hash_hmac('sha256', $canonical, $signingKey, true));
    }

    /**
     * Parses and fully verifies one delivery body, in the order §22.3 fixes:
     * reject `key_version < 2`, verify the MAC, check freshness, check the nonce.
     * Only then is the payload decoded and handed on.
     *
     * Identity and registry membership are checked **after** the MAC: neither is
     * cryptography, and spending them on unauthenticated bytes would tell an
     * unauthenticated party what this reactor accepts.
     *
     * @param string      $signingKey       The tenant's HKDF-derived AMQP subkey.
     * @param string      $body             The raw delivery bytes, exactly as received.
     * @param string      $expectedTenantId This reactor's configured tenant. An event naming
     *                                      another one is refused outright.
     * @param ReplayGuard $guard            The shared §8 v2 freshness + nonce gate. ONE instance
     *                                      must serve every delivery — a fresh guard per message
     *                                      would defeat replay dedup entirely.
     * @param int         $now              The instant to measure freshness and the dispatch
     *                                      deadline against; must be the same clock `$guard` reads.
     *
     * @throws ReactorRejection on any refusal, carrying a fixed-vocabulary reason.
     */
    public static function decodeEvent(
        string $signingKey,
        string $body,
        string $expectedTenantId,
        ReplayGuard $guard,
        int $now,
    ): ReactorEvent {
        // stdClass, not an associative array: an empty `payload` object must
        // survive the round trip as `{}` rather than becoming `[]`.
        $raw = json_decode($body);
        if (!$raw instanceof \stdClass) {
            throw new ReactorRejection(ReactorRejection::MALFORMED, 'axiam: reactor event body is not a JSON object');
        }

        // 1. key_version, before anything else about the body is considered —
        //    including the signature (§22.2). The §22.13 `key_version_too_old`
        //    vector was downgraded AFTER signing precisely so an implementation
        //    that checks the MAC first fails this test.
        $keyVersion = $raw->key_version ?? null;
        if (!is_int($keyVersion) || $keyVersion < self::KEY_VERSION) {
            throw new ReactorRejection(
                ReactorRejection::KEY_VERSION_TOO_OLD,
                'axiam: reactor event key_version is below the accepted floor',
            );
        }

        // 2. The MAC, over the body with hmac_signature set to null (NOT omitted).
        $signature = $raw->hmac_signature ?? null;
        if (!is_string($signature)) {
            throw new ReactorRejection(
                ReactorRejection::BAD_SIGNATURE,
                'axiam: reactor event carries no hmac_signature',
            );
        }
        $unsigned = clone $raw;
        $unsigned->hmac_signature = null;
        if (!self::verify($signingKey, self::canonicalize($unsigned), $signature)) {
            throw new ReactorRejection(
                ReactorRejection::BAD_SIGNATURE,
                'axiam: reactor event signature is missing or invalid',
            );
        }

        // Shape checks that the §8 gate below cannot express. A missing or
        // non-string nonce is malformed rather than a replay, so the gate's own
        // `nonce` verdict can only ever mean "already seen".
        $nonce = $raw->nonce ?? null;
        $issuedAtRaw = $raw->issued_at ?? null;
        if (!is_string($nonce) || $nonce === '' || !is_string($issuedAtRaw)) {
            throw new ReactorRejection(
                ReactorRejection::MALFORMED,
                'axiam: reactor event is missing its nonce or issued_at',
            );
        }
        $issuedAtTs = strtotime($issuedAtRaw);
        if ($issuedAtTs === false) {
            // A timestamp that cannot be parsed is malformed, not stale: only one
            // of those two says anything about an attacker's clock.
            throw new ReactorRejection(
                ReactorRejection::MALFORMED,
                'axiam: reactor event issued_at is not a timestamp',
            );
        }

        // 3 and 4. Freshness (±300 s, both directions) and the nonce seen-set,
        //          through the SAME §8 v2 gate the audit/authz consumer uses —
        //          one gate, one policy, no second implementation to drift.
        $verdict = $guard->check([
            'key_version' => $keyVersion,
            'issued_at' => $issuedAtRaw,
            'nonce' => $nonce,
        ]);
        if ($verdict === 'issued_at') {
            throw new ReactorRejection(
                ReactorRejection::STALE,
                'axiam: reactor event issued_at is outside the freshness window',
            );
        }
        if ($verdict !== null) {
            throw new ReactorRejection(
                ReactorRejection::REPLAY,
                'axiam: reactor event nonce has already been seen',
            );
        }

        $tenantId = $raw->tenant_id ?? null;
        $eventName = $raw->event ?? null;
        $correlationId = $raw->correlation_id ?? null;
        $timeoutMs = $raw->timeout_ms ?? null;
        $payload = $raw->payload ?? null;
        if (
            !is_string($tenantId) || !is_string($eventName) || !is_string($correlationId)
            || !is_int($timeoutMs) || !$payload instanceof \stdClass
        ) {
            throw new ReactorRejection(
                ReactorRejection::MALFORMED,
                'axiam: reactor event is missing a required field or carries the wrong type',
            );
        }

        if ($tenantId !== $expectedTenantId) {
            throw new ReactorRejection(
                ReactorRejection::TENANT_MISMATCH,
                'axiam: reactor event names a different tenant',
            );
        }
        if (ReactorEvents::specFor($eventName) === null) {
            // Also how §22.7's hot-path exclusion refuses: those operations are in
            // no registry, so a delivery naming one lands here rather than in a
            // handler.
            throw new ReactorRejection(
                ReactorRejection::UNKNOWN_EVENT,
                'axiam: reactor event name is not in the §22.5 registry',
            );
        }

        /** @var array<string, mixed> $payloadArray */
        $payloadArray = json_decode(self::canonicalize($payload), true) ?? [];

        return new ReactorEvent(
            tenantId: $tenantId,
            event: $eventName,
            correlationId: $correlationId,
            payload: $payloadArray,
            timeoutMs: $timeoutMs,
            nonce: $nonce,
            issuedAt: $issuedAtTs,
            deadline: $now + ($timeoutMs / 1000.0),
        );
    }

    /**
     * Renders and signs the reply for one handler answer (§22.2, §22.4).
     *
     * Field order is the server's struct declaration order:
     * `correlation_id`, `tenant_id`, `event`, `decision`, `reason` (omitted when
     * absent), `patch` (omitted when absent), `require_mfa` (**omitted when
     * false**), `key_version`, `nonce`, `issued_at`, `hmac_signature` (**`null`
     * while signing**).
     *
     * The three conditional omissions are load-bearing: a reply that serializes
     * `"require_mfa": false` rather than omitting it produces different canonical
     * bytes and therefore a different MAC. An SDK must reproduce the omission
     * rule, not merely the values.
     *
     * Two answers are refused here rather than put on the wire, and each raises
     * {@see ReactorRejection} so the caller publishes nothing and the
     * registration's `failure_policy` decides:
     *
     *  - `require_mfa` on any event other than `login.post_auth`. §22.13 permits
     *    rejecting this client-side or sending it and surfacing the server's
     *    rejection; rejecting names the author's mistake at the place it was made.
     *  - a `mutate` answer with an empty patch, which the server rejects as
     *    `malformed_mutation`.
     *
     * It does **NOT** refuse a patch key outside the event's allow-list. That is
     * the one case where sending the wrong thing is required: the server names the
     * offending key in its audit record, and filtering it out here would hide the
     * mistake from everyone (§22.4 rule 1).
     *
     * @param string $nonce A FRESH UUIDv4 per reply. The server keeps no durable
     *                      nonce-dedup store for replies — its protection is the
     *                      freshness window plus the `correlation_id` binding — but the
     *                      nonce is inside the signed bytes, and a unique one is the only
     *                      thing that keeps two replies from being byte-identical.
     * @param int    $now   The instant to stamp `issued_at` with.
     *
     * @throws ReactorRejection when the answer is one this SDK refuses to send.
     */
    public static function buildReply(
        string $signingKey,
        ReactorEvent $event,
        ReactorAnswer $answer,
        string $nonce,
        int $now,
    ): string {
        if ($answer->requireMfa() && $event->event !== ReactorEvents::LOGIN_POST_AUTH) {
            throw new ReactorRejection(
                ReactorRejection::REQUIRE_MFA_NOT_SUPPORTED,
                'axiam: require_mfa is only valid on login.post_auth',
            );
        }

        $patch = $answer->patch();
        if ($answer->decision() === ReactorAnswer::MUTATE && ($patch === null || $patch === [])) {
            throw new ReactorRejection(
                ReactorRejection::MALFORMED_MUTATION,
                'axiam: a mutate answer requires a non-empty patch',
            );
        }

        $reply = new \stdClass();
        $reply->correlation_id = $event->correlationId;
        $reply->tenant_id = $event->tenantId;
        $reply->event = $event->event;
        $reply->decision = $answer->decision();
        if ($answer->reason() !== null) {
            $reply->reason = $answer->reason();
        }
        if ($patch !== null && $patch !== []) {
            // Byte-order key sort: the server's BTreeMap emits sorted keys while a
            // PHP array emits insertion order. The cast to an object also keeps a
            // patch whose keys look numeric from serializing as a JSON array.
            ksort($patch, SORT_STRING);
            $reply->patch = (object) $patch;
        }
        if ($answer->requireMfa()) {
            $reply->require_mfa = true;
        }
        $reply->key_version = self::KEY_VERSION;
        $reply->nonce = $nonce;
        $reply->issued_at = gmdate('Y-m-d\TH:i:s\Z', $now);
        $reply->hmac_signature = null;

        $reply->hmac_signature = self::sign($signingKey, self::canonicalize($reply));

        return self::canonicalize($reply);
    }
}
