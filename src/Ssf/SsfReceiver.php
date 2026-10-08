<?php

declare(strict_types=1);

namespace Axiam\Sdk\Ssf;

use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\ErrorMapper;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\RetryPolicy;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Core\TelemetryDispatcher;
use Axiam\Sdk\Management\FieldError;
use Axiam\Sdk\Management\ManagementErrorMapper;
use Axiam\Sdk\Management\ValidationError;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Http\Message\ResponseInterface;

/**
 * The SSF receiver helper — CONTRACT.md §32.7 (contract 1.56).
 *
 * AXIAM is a Shared Signals Framework transmitter: it sends CAEP and RISC security events as
 * Security Event Tokens (RFC 8417) to the relying parties a tenant administrator registered
 * (the §27 `ssf` namespace). This class is for the **relying party** that receives them, a
 * different audience from that namespace:
 *
 * - {@see self::verifySet()} verifies one compact SET — pushed to your endpoint (RFC 8935) or
 *   returned by a poll — in the contract's fixed order, and refuses at the first failure with
 *   a {@see SetVerificationError} naming the step.
 * - {@see self::poll()} calls the stream's poll endpoint (RFC 8936), verifies every returned
 *   SET and hands back the verified and the refused apart.
 *
 * Neither transmits, signs or registers anything, and neither trusts a key it did not fetch
 * from the configured JWKS: a `jwk` or `x5c` header member is never honoured (§32.9).
 *
 * Build one with {@see \Axiam\Sdk\AxiamClient::ssfReceiver()}, which supplies the client's
 * session-free transport (its §6 TLS policy, no cookies, no session token, no redirects) and
 * base URL.
 *
 * A push endpoint answers a refusal with `400` and {@see SetFailureReason::pushErrorCode()}:
 *
 * ```php
 * try {
 *     $event = $receiver->verifySet($requestBody);
 *     // ... act on $event, then answer 202
 * } catch (SetVerificationError $e) {
 *     // answer 400 {"err": $e->failureReason->pushErrorCode()}
 * }
 * ```
 */
final class SsfReceiver
{
    /**
     * The replay window's floor and default: seven days, the transmitter's buffer retention
     * (§32.6). A shorter window would forget a `jti` the transmitter can still re-send.
     */
    public const MIN_REPLAY_WINDOW_SECONDS = 7 * 24 * 60 * 60;

    /** A forced JWKS refetch (an unknown `kid`) happens at most once per this many seconds. */
    public const FORCED_REFETCH_INTERVAL_SECONDS = 60;

    /** An un-forced refetch happens once the cached JWKS is this old. */
    public const JWKS_TTL_SECONDS = 300;

    /** The two `typ` spellings §32.7 step 2 accepts, compared case-insensitively. */
    private const SET_TYPES = ['secevent+jwt', 'application/secevent+jwt'];

    /** @var array<string,string>|null kid => raw 32-byte Ed25519 public key */
    private ?array $keys = null;

    private int $fetchedAt = 0;

    private ?int $lastForcedRefetch = null;

    private ?string $resolvedJwksUri = null;

    /** @var (callable(): (Sensitive|string))|null */
    private $accessTokenProvider;

    /** @var callable(): int */
    private $clock;

    private readonly ReplayStore $replayStore;

    /**
     * @param ClientInterface $http The transport: a session-free client with the SDK's TLS
     *        policy — {@see \Axiam\Sdk\AxiamClient::ssfReceiver()} passes its own.
     * @param string $baseUrl The transmitter root `poll()` calls (`{root}/ssf/v1/poll/{id}`).
     * @param string $issuer The transmitter's issuer, compared with `iss` exactly.
     * @param string $audience This receiver's audience — the stream's `audience`.
     * @param string|null $jwksUri Where the signing keys are (AXIAM: `{issuer}/oauth2/jwks`).
     *        Exactly one of this and `$discoveryUrl`.
     * @param string|null $discoveryUrl The transmitter's SSF configuration document
     *        (`/.well-known/ssf-configuration…`); its `jwks_uri` is used, and its `issuer`
     *        must equal `$issuer`.
     * @param (callable(): (Sensitive|string))|null $accessTokenProvider The bearer `poll()`
     *        presents: a client-credentials access token carrying `ssf.manage` (for example
     *        `$client->loginClientCredentials('ssf.manage')->accessToken`). Called once per
     *        poll; `null` for a push-only receiver.
     * @param int $replayWindowSeconds How long a `jti` is remembered — at least, and by
     *        default, {@see self::MIN_REPLAY_WINDOW_SECONDS}.
     * @param ReplayStore|null $replayStore Where accepted `jti`s are kept; an
     *        {@see InMemoryReplayStore} when omitted.
     * @param bool $retryEnabled §16.1's switch, for `poll()`.
     * @param TelemetryDispatcher|null $telemetry §19, notified before a retry wait.
     * @param (callable(): int)|null $clock The current time in seconds (for the refetch limit);
     *        `time()` when omitted.
     *
     * @throws ValidationError locally, when the replay window is below seven days, the issuer
     *         or audience is empty, or not exactly one key source is given.
     */
    public function __construct(
        private readonly ClientInterface $http,
        private readonly string $baseUrl,
        private readonly string $issuer,
        private readonly string $audience,
        private readonly ?string $jwksUri = null,
        private readonly ?string $discoveryUrl = null,
        ?callable $accessTokenProvider = null,
        private readonly int $replayWindowSeconds = self::MIN_REPLAY_WINDOW_SECONDS,
        ?ReplayStore $replayStore = null,
        private readonly bool $retryEnabled = true,
        private readonly ?TelemetryDispatcher $telemetry = null,
        ?callable $clock = null,
    ) {
        if ($replayWindowSeconds < self::MIN_REPLAY_WINDOW_SECONDS) {
            throw self::refuseConfig(
                'replay_window',
                'must be at least seven days, the transmitter\'s buffer retention',
            );
        }
        if ($issuer === '' || $audience === '') {
            throw self::refuseConfig($issuer === '' ? 'issuer' : 'audience', 'issuer and audience are required');
        }
        if (($jwksUri === null) === ($discoveryUrl === null)) {
            throw self::refuseConfig('jwks_uri', 'give exactly one of jwks_uri and discovery_url');
        }
        $this->accessTokenProvider = $accessTokenProvider;
        $this->replayStore = $replayStore ?? new InMemoryReplayStore($clock);
        $this->clock = $clock ?? static fn (): int => time();
    }

    /**
     * What `print_r()` / `var_dump()` show: the configuration, never the access-token
     * provider (a closure that typically captures a bearer) nor the replay store.
     *
     * @return array<string,mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'issuer' => $this->issuer,
            'audience' => $this->audience,
            'jwksUri' => $this->jwksUri,
            'discoveryUrl' => $this->discoveryUrl,
            'replayWindowSeconds' => $this->replayWindowSeconds,
            'accessTokenProvider' => $this->accessTokenProvider === null ? null : '[provider]',
        ];
    }

    /**
     * Verify one compact SET (CONTRACT.md §32.7), in this order, refusing at the first failure
     * with a {@see SetVerificationError} whose {@see SetFailureReason} is in brackets:
     *
     * 1. three base64url parts, a JSON-object header and payload [`malformed`];
     * 2. `typ` `secevent+jwt` or `application/secevent+jwt`, any case [`invalid_type`];
     * 3. `alg` exactly `EdDSA` — `none`, `HS*` and every other value refused [`invalid_key`];
     * 4. the `kid` in the configured JWKS — on a miss, ONE refetch, no more often than once a
     *    minute [`invalid_key`];
     * 5. the Ed25519 signature [`invalid_key`];
     * 6. `iss` equal to the configured issuer [`invalid_issuer`];
     * 7. `aud` equal to, or an array containing, the audience [`invalid_audience`];
     * 8. no `exp`, no `sub`; a non-empty string `jti`, a numeric `iat`, an object `sub_id`;
     *    `events` an object with exactly one member [`invalid_request`];
     * 9. a `jti` not seen within the replay window [`replayed`] — recorded only once 1–8 passed.
     *
     * **A SET that verifies has been recorded**: verifying it again is `replayed`. Acknowledge
     * a polled SET once you have processed it, or a re-offer reads as a replay.
     *
     * @throws SetVerificationError the SET is refused.
     * @throws NetworkError the JWKS (or the configuration document) could not be fetched —
     *         which is not a verdict on the SET.
     */
    public function verifySet(string $set): SecurityEvent
    {
        return $this->verify($set, null);
    }

    /**
     * Poll the stream's RFC 8936 endpoint, `{root}/ssf/v1/poll/{stream_id}`, with a bearer from
     * the configured access-token provider, and verify every SET it returns.
     *
     * The body carries exactly the options set — `{}` when none is — so `ack` and `setErrs` go
     * out exactly as given. **Nothing is acknowledged on your behalf**: on the next call,
     * acknowledge the `jti`s you processed and pass each refused one in `setErrs`
     * ({@see SetErr::fromReason()}). A SET you neither acknowledge nor refuse is re-offered,
     * and — having been recorded when it verified — then reads as `replayed`.
     *
     * The request carries nothing of the SDK's session and follows no redirect. Retried per §16
     * on a transport failure, a `5xx`, `408` or `429` — never on another `4xx`, which maps like
     * a management answer (`400` {@see ValidationError}, `404` NotFoundError, `401` AuthError).
     * A SET that is not a string is refused `malformed`, one whose verified `jti` differs from
     * its map key `invalid_request`; a JWKS fetch failure aborts the poll with that error rather
     * than refusing SETs it could not judge.
     *
     * @throws AuthError locally, when no access-token provider was configured.
     */
    public function poll(string $streamId, ?SsfPollOptions $options = null): SsfPollResult
    {
        if ($this->accessTokenProvider === null) {
            throw new AuthError(
                'ssf.poll needs an accessTokenProvider (a client-credentials token with ssf.manage) '
                . '(CONTRACT.md §32.7)',
            );
        }
        $provided = ($this->accessTokenProvider)();
        $token = $provided instanceof Sensitive ? $provided->reveal() : $provided;
        $url = rtrim($this->baseUrl, '/') . '/ssf/v1/poll/' . rawurlencode($streamId);
        $body = (string) json_encode((object) ($options ?? new SsfPollOptions())->toArray(), JSON_UNESCAPED_SLASHES);

        $lastStatus = null;
        $retryable = static function () use (&$lastStatus): bool {
            return $lastStatus === null || $lastStatus >= 500 || $lastStatus === 408 || $lastStatus === 429;
        };
        $response = RetryPolicy::execute(
            'ssf.poll',
            $this->retryEnabled,
            $this->telemetry ?? new TelemetryDispatcher(null),
            function () use ($url, $token, $body, &$lastStatus): ResponseInterface {
                $lastStatus = null;
                try {
                    $response = $this->http->request('POST', $url, [
                        'http_errors' => false,
                        'allow_redirects' => false,
                        'headers' => [
                            'Authorization' => 'Bearer ' . $token,
                            'Content-Type' => 'application/json',
                            'Accept' => 'application/json',
                        ],
                        'body' => $body,
                    ]);
                } catch (GuzzleException $e) {
                    throw NetworkError::fromException($e, 'ssf.poll request failed');
                }
                $lastStatus = $response->getStatusCode();
                if ($lastStatus < 200 || $lastStatus >= 300) {
                    throw ManagementErrorMapper::fromResponse($response, 'ssf.poll');
                }

                return $response;
            },
            null,
            null,
            $retryable,
        );

        $reply = json_decode((string) $response->getBody());
        if (!$reply instanceof \stdClass) {
            throw NetworkError::fromMessage('ssf.poll: the response is not a JSON object');
        }
        $events = [];
        $refused = [];
        $sets = $reply->sets ?? null;
        if ($sets instanceof \stdClass) {
            foreach (get_object_vars($sets) as $jti => $candidate) {
                $jti = (string) $jti;
                if (!is_string($candidate)) {
                    $refused[] = new RefusedSet($jti, SetFailureReason::Malformed);
                    continue;
                }
                try {
                    $events[] = $this->verify($candidate, $jti);
                } catch (SetVerificationError $e) {
                    $refused[] = new RefusedSet($jti, $e->failureReason);
                }
            }
        }

        return new SsfPollResult($events, ($reply->moreAvailable ?? false) === true, $refused);
    }

    /** The §32.7 order; `$expectedJti` is the poll map key the SET was returned under. */
    private function verify(string $set, ?string $expectedJti): SecurityEvent
    {
        // 1.
        $parts = explode('.', $set);
        if (count($parts) !== 3) {
            throw new SetVerificationError(SetFailureReason::Malformed, 'not three base64url parts');
        }
        $signature = self::base64UrlDecode($parts[2]);
        $headerJson = self::base64UrlDecode($parts[0]);
        $payloadJson = self::base64UrlDecode($parts[1]);
        if ($signature === null || $headerJson === null || $payloadJson === null) {
            throw new SetVerificationError(SetFailureReason::Malformed, 'not three base64url parts');
        }
        $header = json_decode($headerJson);
        $claims = json_decode($payloadJson);
        if (!$header instanceof \stdClass || !$claims instanceof \stdClass) {
            throw new SetVerificationError(SetFailureReason::Malformed, 'the header or payload is not a JSON object');
        }

        // 2.
        $typ = $header->typ ?? null;
        if (!is_string($typ) || !in_array(strtolower($typ), self::SET_TYPES, true)) {
            throw new SetVerificationError(SetFailureReason::InvalidType, 'typ is not secevent+jwt');
        }

        // 3. Pinned before any key is looked up: the token never chooses its algorithm.
        if (($header->alg ?? null) !== 'EdDSA') {
            throw new SetVerificationError(SetFailureReason::InvalidKey, 'alg is not EdDSA');
        }

        // 4. Only the configured JWKS — never a `jwk` or `x5c` header member.
        $kid = $header->kid ?? null;
        if (!is_string($kid) || $kid === '') {
            throw new SetVerificationError(SetFailureReason::InvalidKey, 'no kid');
        }
        $key = $this->keyFor($kid);
        if ($key === null) {
            throw new SetVerificationError(SetFailureReason::InvalidKey, 'no key for the kid in the JWKS');
        }

        // 5.
        if (strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES
            || !sodium_crypto_sign_verify_detached($signature, $parts[0] . '.' . $parts[1], $key)) {
            throw new SetVerificationError(SetFailureReason::InvalidKey, 'the signature does not verify');
        }

        // 6.
        $iss = $claims->iss ?? null;
        if ($iss !== $this->issuer) {
            throw new SetVerificationError(SetFailureReason::InvalidIssuer, 'iss is not the configured issuer');
        }

        // 7.
        $aud = $claims->aud ?? null;
        $audOk = is_string($aud)
            ? $aud === $this->audience
            : is_array($aud) && in_array($this->audience, $aud, true);
        if (!$audOk) {
            throw new SetVerificationError(SetFailureReason::InvalidAudience, 'aud does not name this receiver');
        }

        // 8.
        if (property_exists($claims, 'exp') || property_exists($claims, 'sub')) {
            throw new SetVerificationError(SetFailureReason::InvalidRequest, 'a SET carries no exp and no sub');
        }
        $jti = $claims->jti ?? null;
        if (!is_string($jti) || $jti === '') {
            throw new SetVerificationError(SetFailureReason::InvalidRequest, 'no jti');
        }
        $iat = $claims->iat ?? null;
        if (!is_int($iat) && !is_float($iat)) {
            throw new SetVerificationError(SetFailureReason::InvalidRequest, 'no numeric iat');
        }
        $subId = $claims->sub_id ?? null;
        if (!$subId instanceof \stdClass) {
            throw new SetVerificationError(SetFailureReason::InvalidRequest, 'no sub_id object');
        }
        $events = $claims->events ?? null;
        $members = $events instanceof \stdClass ? get_object_vars($events) : [];
        if (count($members) !== 1) {
            throw new SetVerificationError(SetFailureReason::InvalidRequest, 'events must have exactly one member');
        }
        if ($expectedJti !== null && $expectedJti !== $jti) {
            throw new SetVerificationError(SetFailureReason::InvalidRequest, 'the poll key is not the SET\'s jti');
        }
        $eventType = (string) array_key_first($members);
        $event = $members[$eventType];

        // 9. Only now, once 1–8 passed.
        if (!$this->replayStore->checkAndRecord($jti, $this->replayWindowSeconds)) {
            throw new SetVerificationError(SetFailureReason::Replayed, 'the jti was already accepted');
        }

        $txn = $claims->txn ?? null;

        return new SecurityEvent(
            jti: $jti,
            iat: $iat,
            iss: $iss,
            aud: is_string($aud) ? $aud : array_values(self::toArray($aud)),
            txn: is_string($txn) ? $txn : null,
            eventType: $eventType,
            event: self::toObjectArray($event),
            subId: self::toObjectArray($subId),
        );
    }

    /**
     * The key named `$kid`: from the cache; on a miss, from ONE refetch — but a forced refetch
     * happens at most once per {@see self::FORCED_REFETCH_INTERVAL_SECONDS}, so a stream of
     * SETs with made-up `kid`s cannot turn this receiver into a JWKS load generator (§32.7
     * step 4).
     */
    private function keyFor(string $kid): ?string
    {
        $now = ($this->clock)();
        if ($this->keys === null || $now - $this->fetchedAt >= self::JWKS_TTL_SECONDS) {
            $this->fetchKeys($now);
        }
        if (!isset($this->keys[$kid])
            && ($this->lastForcedRefetch === null || $now - $this->lastForcedRefetch >= self::FORCED_REFETCH_INTERVAL_SECONDS)) {
            $this->lastForcedRefetch = $now;
            $this->fetchKeys($now);
        }

        return $this->keys[$kid] ?? null;
    }

    /** Fetch the JWKS; a failure is a {@see NetworkError}, never a SET refusal. */
    private function fetchKeys(int $now): void
    {
        $response = $this->get($this->jwksUri(), 'SSF JWKS fetch');
        $document = json_decode((string) $response->getBody(), true);
        $entries = is_array($document) ? ($document['keys'] ?? null) : null;
        if (!is_array($entries)) {
            throw NetworkError::fromMessage('SSF JWKS fetch: the document carries no keys array');
        }
        $keys = [];
        foreach ($entries as $jwk) {
            if (!is_array($jwk) || ($jwk['kty'] ?? null) !== 'OKP' || ($jwk['crv'] ?? null) !== 'Ed25519'
                || !is_string($jwk['kid'] ?? null) || !is_string($jwk['x'] ?? null)) {
                continue;
            }
            $x = self::base64UrlDecode($jwk['x']);
            if ($x !== null && strlen($x) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                $keys[$jwk['kid']] = $x;
            }
        }
        $this->keys = $keys;
        $this->fetchedAt = $now;
    }

    /** The JWKS location: configured, or read once from the SSF configuration document. */
    private function jwksUri(): string
    {
        if ($this->jwksUri !== null) {
            return self::secureUrl($this->jwksUri, 'jwks_uri');
        }
        if ($this->resolvedJwksUri === null) {
            $response = $this->get(self::secureUrl((string) $this->discoveryUrl, 'discovery_url'), 'SSF configuration fetch');
            $document = json_decode((string) $response->getBody(), true);
            if (!is_array($document) || ($document['issuer'] ?? null) !== $this->issuer) {
                throw NetworkError::fromMessage('the SSF configuration\'s issuer is not the configured issuer');
            }
            $jwksUri = $document['jwks_uri'] ?? null;
            if (!is_string($jwksUri) || $jwksUri === '') {
                throw NetworkError::fromMessage('the SSF configuration carries no jwks_uri');
            }
            $this->resolvedJwksUri = self::secureUrl($jwksUri, 'jwks_uri');
        }

        return $this->resolvedJwksUri;
    }

    /** One session-free, redirect-free GET; a non-2xx is §2's mapping. */
    private function get(string $url, string $context): ResponseInterface
    {
        try {
            $response = $this->http->request('GET', $url, [
                'http_errors' => false,
                'allow_redirects' => false,
                'headers' => ['Accept' => 'application/json'],
            ]);
        } catch (GuzzleException $e) {
            throw NetworkError::fromException($e, $context . ' failed');
        }
        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw ErrorMapper::fromResponse($response, $context . ' failed');
        }

        return $response;
    }

    /**
     * Keys are fetched over `https` only — `http` solely for a loopback host, a local test
     * transmitter — and never from a relative URL.
     */
    private static function secureUrl(string $url, string $label): string
    {
        $parts = parse_url($url);
        $scheme = is_array($parts) ? strtolower($parts['scheme'] ?? '') : '';
        $host = is_array($parts) ? strtolower(trim($parts['host'] ?? '', '[]')) : '';
        $loopback = in_array($host, ['localhost', '127.0.0.1', '::1'], true);
        if ($host === '' || !($scheme === 'https' || ($scheme === 'http' && $loopback))) {
            throw NetworkError::fromMessage(sprintf('%s must be an absolute https URL (CONTRACT.md §32.7, §6)', $label));
        }

        return $url;
    }

    /** Strict unpadded base64url, or `null` for anything else. */
    private static function base64UrlDecode(string $segment): ?string
    {
        if (preg_match('/^[A-Za-z0-9_-]*$/', $segment) !== 1) {
            return null;
        }
        $decoded = base64_decode(strtr($segment, '-_', '+/'), true);

        return $decoded === false ? null : $decoded;
    }

    /**
     * A decoded JSON value as nested PHP arrays.
     *
     * @return array<mixed>
     */
    private static function toArray(mixed $value): array
    {
        $array = json_decode((string) json_encode($value), true);

        return is_array($array) ? $array : [];
    }

    /**
     * A decoded JSON object as an associative array (an empty object becomes `[]`).
     *
     * @return array<string,mixed>
     */
    private static function toObjectArray(mixed $value): array
    {
        /** @var array<string,mixed> $array */
        $array = self::toArray($value);

        return $array;
    }

    private static function refuseConfig(string $field, string $why): ValidationError
    {
        return new ValidationError(
            sprintf('ssf.receiver: %s %s (CONTRACT.md §32.7)', $field, $why),
            [new FieldError($field, $why)],
        );
    }
}
