<?php

declare(strict_types=1);

namespace Axiam\Sdk\Ssf;

/**
 * Why {@see SsfReceiver::verifySet()} refused a Security Event Token — the bracketed reason
 * codes of CONTRACT.md §32.7, one per verification step that can fail.
 */
enum SetFailureReason: string
{
    /** Step 1: not three base64url parts, or a header / payload that is not a JSON object. */
    case Malformed = 'malformed';

    /** Step 2: `typ` is neither `secevent+jwt` nor `application/secevent+jwt`. */
    case InvalidType = 'invalid_type';

    /** Steps 3–5: `alg` is not `EdDSA`, the `kid` is not in the JWKS, or the signature fails. */
    case InvalidKey = 'invalid_key';

    /** Step 6: `iss` is not the configured issuer. */
    case InvalidIssuer = 'invalid_issuer';

    /** Step 7: `aud` does not name this receiver. */
    case InvalidAudience = 'invalid_audience';

    /** Step 8: `exp` or `sub` present; `jti`, `iat` or `sub_id` missing; not exactly one event. */
    case InvalidRequest = 'invalid_request';

    /**
     * Step 9: the `jti` was already accepted within the replay window. Returned by `poll()`, it
     * is **acknowledged** in the next call's `ack`, never reported in `setErrs`
     * (CONTRACT.md §34.2 P2).
     */
    case Replayed = 'replayed';

    /**
     * The RFC 8935 §2.4 `err` to answer a push with (`400 {"err": …}`), and to pass in a
     * poll's `setErrs`.
     *
     * The reason itself for `invalid_key`, `invalid_issuer`, `invalid_audience` and
     * `invalid_request`. `malformed`, `invalid_type` and `replayed` are not RFC 8935 codes,
     * so they are answered as `invalid_request`: only codes the RFC defines go on the wire.
     */
    public function pushErrorCode(): string
    {
        return match ($this) {
            self::InvalidKey, self::InvalidIssuer, self::InvalidAudience, self::InvalidRequest => $this->value,
            self::Malformed, self::InvalidType, self::Replayed => 'invalid_request',
        };
    }
}
