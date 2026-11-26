<?php

declare(strict_types=1);

namespace Axiam\Sdk\Amqp;

/**
 * HMAC-SHA256 verify-before-handler primitive for inbound AMQP messages
 * (CONTRACT.md §8).
 *
 * **Verify the received bytes, and hand the handler the same bytes (axiam#882, C2).** The server
 * writes a signed message as a compact JSON object whose LAST member is
 * `"hmac_signature":"<hex>"`, signed over the bytes before it (the object closed with `}`). This
 * class cuts that trailing member out of the body exactly as it was delivered and computes the
 * HMAC over what is left. It never rebuilds the signed bytes by decoding and re-encoding the
 * body: encoders disagree on string escaping (PHP's `json_encode` writes `é` for `é` unless
 * told otherwise and `\/` for `/`; Go's escapes `<`, `>` and `&`; serde_json writes all of them
 * raw), so a re-serialization fails to verify a genuine message whenever a field contains a
 * character the two encoders spell differently, and — worse — a body can verify as one thing
 * while a reader of the original bytes sees another.
 *
 * What is refused, all as `false` / `null`, never an exception (§8.3 strict mode):
 *
 *  - a body that is not a JSON object, or that repeats a key at any depth (a duplicate is read
 *    one way by `json_decode`, which keeps the last, and another way by a parser that keeps the
 *    first), or that has any content after the closing brace;
 *  - a body that does not END in exactly `,"hmac_signature":"` + 64 hex digits + `"}` (a message
 *    the server did not write, or one re-encoded on the way, or one with whitespace added), or
 *    whose top-level `hmac_signature` is not that trailing member;
 *  - a signature that does not match, compared in constant time.
 *
 * {@see self::verifiedCanonical()} returns the bytes the HMAC covered; the caller builds its view
 * of the message from THOSE bytes (`json_decode()` of them), which is what
 * {@see Consumer::verifyAndDispatch()} does.
 */
final class Hmac
{
    /** The member every signed message the server writes ends with, up to the first hex digit. */
    private const SIGNATURE_MEMBER = ',"hmac_signature":"';

    private const SIGNATURE_HEX_LENGTH = 64;

    /**
     * The signed event shapes an SDK consumer accepts (CONTRACT §8 "Exact signed field order"):
     * member name => whether it is optional (omitted, never `null`), in declaration order.
     *
     * @var array<string, array<string, bool>>
     */
    private const LAYOUTS = [
        'AuthzRequest' => [
            'correlation_id' => false, 'tenant_id' => false, 'subject_id' => false, 'action' => false,
            'resource_id' => false, 'scope' => true, 'key_version' => false, 'nonce' => false, 'issued_at' => false,
        ],
        'AuditEventMessage' => [
            'tenant_id' => false, 'actor_id' => false, 'actor_type' => false, 'action' => false,
            'resource_id' => true, 'outcome' => false, 'ip_address' => true, 'metadata' => true,
            'key_version' => false, 'nonce' => false, 'issued_at' => false,
        ],
    ];

    /**
     * Returns true iff `$body` carries a trailing `hmac_signature` member that matches
     * HMAC-SHA256(`$signingKey`, the received bytes with that member cut out), compared in constant
     * time.
     *
     * Never throws: malformed JSON, a non-object body, a duplicate key, trailing content, a
     * missing/non-string/non-hex/wrong-length signature, or a signature that is not the trailing
     * member all verify as false.
     */
    public static function verify(string $signingKey, string $body): bool
    {
        return self::verifiedCanonical($signingKey, $body) !== null;
    }

    /**
     * Verifies `$body` and returns the canonical bytes the HMAC covered — the received bytes with
     * the trailing signature member removed — or `null` when it does not verify. The one byte
     * sequence a caller may build its view of the message from: what is delivered is what was
     * signed (C2).
     */
    public static function verifiedCanonical(string $signingKey, string $body): ?string
    {
        // Refuses non-objects, malformed JSON, trailing content and a key repeated at any depth.
        if (StrictJson::isAmbiguousObject($body)) {
            return null;
        }

        $cut = self::cutTrailingSignature($body);
        if ($cut === null) {
            return null;
        }
        [$canonical, $sigHex] = $cut;

        // The signature the body CLAIMS (its top-level member) must be the one that was cut out:
        // a nested or decoy `hmac_signature` earlier in the body must not stand in for it.
        $members = json_decode($body, true);
        if (!is_array($members) || ($members['hmac_signature'] ?? null) !== $sigHex) {
            return null;
        }

        $expected = hex2bin($sigHex);
        if ($expected === false) {
            return null;
        }

        return hash_equals($expected, hash_hmac('sha256', $canonical, $signingKey, true)) ? $canonical : null;
    }

    /**
     * True when `$canonical` (the verified bytes {@see self::verifiedCanonical()} returned) has
     * the top-level members of a signed event type, in that type's declaration order, each
     * optional member present in its place or absent, and no other member (contract 1.69, §8
     * step 2c). Every tenant-subkey-signed shape shares the key — `AuthzResponse`, the reactor
     * messages, the cache-invalidation broadcast — so a validly signed message of ANOTHER shape
     * must not be accepted as an `AuthzRequest` or an `AuditEventMessage`.
     */
    public static function hasSignedLayout(string $canonical): bool
    {
        $members = json_decode($canonical, true);
        if (!is_array($members)) {
            return false;
        }
        $names = array_map('strval', array_keys($members));

        foreach (self::LAYOUTS as $layout) {
            $position = 0;
            $matches = true;
            foreach ($names as $name) {
                // Advance through the layout to this member; skipped members must be optional.
                $found = false;
                $keys = array_keys($layout);
                for (; $position < count($keys); $position++) {
                    if ($keys[$position] === $name) {
                        $found = true;
                        $position++;
                        break;
                    }
                    if (!$layout[$keys[$position]]) {
                        break;
                    }
                }
                if (!$found) {
                    $matches = false;
                    break;
                }
            }
            if ($matches) {
                // Every required member after the last matched one must be absent from the layout's tail.
                $keys = array_keys($layout);
                for (; $position < count($keys); $position++) {
                    if (!$layout[$keys[$position]]) {
                        $matches = false;
                        break;
                    }
                }
            }
            if ($matches) {
                return true;
            }
        }

        return false;
    }

    /**
     * Removes the final `,"hmac_signature":"<64 hex>"` member from `$body`, returning the bytes
     * before it closed with `}` and the signature hex, or `null` when `$body` does not end in
     * exactly that member.
     *
     * @return array{0: string, 1: string}|null
     */
    private static function cutTrailingSignature(string $body): ?array
    {
        $tail = '"}';
        $suffixLength = strlen(self::SIGNATURE_MEMBER) + self::SIGNATURE_HEX_LENGTH + strlen($tail);
        if (strlen($body) <= $suffixLength || !str_ends_with($body, $tail)) {
            return null;
        }
        $start = strlen($body) - $suffixLength;
        if (substr($body, $start, strlen(self::SIGNATURE_MEMBER)) !== self::SIGNATURE_MEMBER) {
            return null;
        }
        $sigHex = substr($body, $start + strlen(self::SIGNATURE_MEMBER), self::SIGNATURE_HEX_LENGTH);
        if (!ctype_xdigit($sigHex)) {
            return null;
        }

        return [substr($body, 0, $start) . '}', $sigHex];
    }
}
