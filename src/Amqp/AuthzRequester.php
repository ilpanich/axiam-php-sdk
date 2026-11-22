<?php

declare(strict_types=1);

namespace Axiam\Sdk\Amqp;

use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Core\NetworkError;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * The AMQP authorization requester (CONTRACT.md §8 "Signed authorization responses",
 * contract 1.68; N2, D-9). It publishes a signed `AuthzRequest` on `axiam.authz.request` with a
 * private, exclusive, broker-named `reply_to` queue, and accepts an answer only when it
 * verifies as the server's signed response to THAT request.
 *
 * **The one rule that decides the design: verify the received bytes and deliver the same
 * bytes (C2).** The signature is checked over the delivery body with its trailing
 * `hmac_signature` member cut out — never over a re-serialization — and the decision handed to
 * the caller is decoded from those very canonical bytes. A body that re-serializes to
 * something else than it arrived as would otherwise verify one thing and deliver another.
 *
 * A response is accepted only when ALL of these hold (§8 consumer obligations 1–3):
 *
 *  1. it parses strictly: a JSON object with no duplicate or case-variant keys, `allowed` a
 *     JSON boolean, `tenant_id`, `nonce` and `hmac_signature` present, the signature the
 *     TRAILING member;
 *  2. `HMAC-SHA256(subkey, canonical)` equals the signature, compared in constant time, under
 *     the subkey of THIS requester's own tenant for the `key_version` it sent — the response
 *     carries no `key_version` and nothing in it selects a key;
 *  3. `tenant_id` equals this requester's tenant, and `correlation_id` and `nonce` both match
 *     one request still outstanding, which is then retired.
 *
 * Anything else is nacked without requeue, logged as a security event (never a signature
 * value), is never an allow, and does NOT complete the request: {@see self::check()} keeps
 * waiting for the genuine answer until it times out.
 *
 * A response with no `hmac_signature` at all (a server older than 1.68) is refused unless
 * `allowUnsignedResponses` is set — the explicit, named, off-by-default opt-out for one rolling
 * upgrade. It admits only a response that carries NO signature member; one that carries a
 * signature is verified in full whatever the opt-out says, and the opt-out never admits one
 * that fails.
 *
 * PHP is single-threaded, so {@see self::check()} blocks while it pumps the transport; several
 * requests can still be outstanding (the pending map is keyed by `correlation_id`) when a
 * long-running runtime drives it from more than one fiber.
 */
final class AuthzRequester
{
    /** The queue the server consumes `AuthzRequest` from. */
    public const REQUEST_QUEUE = 'axiam.authz.request';

    /**
     * The signing-key version this requester sends. The caller supplies the tenant subkey for
     * it (§8.1); the response carries no `key_version`, so the requester uses the one it sent.
     */
    public const KEY_VERSION = 2;

    /** Bounds one {@see self::check()} when the caller does not pass a timeout. */
    public const DEFAULT_TIMEOUT_SECONDS = 10.0;

    /** The prefix of the server's own queues; it does not honour a `reply_to` that starts with it (§8 rule 5). */
    private const SERVER_QUEUE_PREFIX = 'axiam.';

    private const SIGNATURE_MEMBER = ',"hmac_signature":"';

    private const SIGNATURE_HEX_LENGTH = 64;

    private const UUID_PATTERN = '/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/';

    /**
     * Outstanding requests, keyed by `correlation_id`: the `nonce` that was sent and, once a
     * response has been accepted, the decision (the entry is removed when `check()` collects it).
     *
     * @var array<string, array{nonce: string, decision: AuthzDecision|null}>
     */
    private array $pending = [];

    private readonly string $tenantId;

    private readonly string $replyTo;

    private bool $closed = false;

    /** @var \Closure(): string */
    private readonly \Closure $newId;

    /** @var \Closure(): int */
    private readonly \Closure $clock;

    /**
     * Opens the private reply queue on `$transport` and returns a requester for `$tenantId`.
     *
     * @param AuthzTransport  $transport  The broker session ({@see AmqpLibAuthzTransport} for
     *        `php-amqplib`).
     * @param string          $tenantId   The requester's OWN tenant — the only tenant a response
     *        is accepted for. A UUID.
     * @param string          $signingKey The tenant's AMQP SUBKEY for key_version 2 (§8.1), as raw
     *        bytes, obtained from the AXIAM management API — never the master key.
     * @param bool            $allowUnsignedResponses The explicit, integrator-set opt-out for
     *        ONE rolling upgrade against a server older than contract 1.68, whose responses are
     *        unsigned. Off by default. See the class docblock.
     * @param LoggerInterface $logger     Receives security events (a discarded response, an
     *        admitted unsigned one). Never a signature value, never a key.
     * @param float           $timeoutSeconds Bounds each {@see self::check()}.
     * @param (\Closure(): string)|null $idGenerator Returns a fresh UUID; `null` draws a random
     *        (v4) one. Used for BOTH the correlation_id and the nonce, which must be
     *        unpredictable.
     * @param (\Closure(): int)|null $clock Seconds since the epoch for `issued_at`; `null` is `time()`.
     *
     * @throws \InvalidArgumentException when the tenant is not a UUID, the key is empty or the
     *         timeout is not positive.
     * @throws AxiamException when the broker's reply queue is not a private one: empty, or named
     *         `axiam.…`, which the server would answer on the shared `axiam.authz.response`
     *         queue instead — putting this requester back on the shared queue the contract forbids.
     *
     * @internal `$idGenerator` and `$clock` exist for tests.
     */
    public function __construct(
        private readonly AuthzTransport $transport,
        string $tenantId,
        private readonly string $signingKey,
        private readonly bool $allowUnsignedResponses = false,
        private readonly LoggerInterface $logger = new NullLogger(),
        private readonly float $timeoutSeconds = self::DEFAULT_TIMEOUT_SECONDS,
        ?\Closure $idGenerator = null,
        ?\Closure $clock = null,
    ) {
        if (preg_match(self::UUID_PATTERN, $tenantId) !== 1) {
            throw new \InvalidArgumentException('axiam: authz requester tenant_id is not a UUID');
        }
        if ($signingKey === '') {
            throw new \InvalidArgumentException('axiam: authz requester needs the tenant signing key');
        }
        if ($timeoutSeconds <= 0.0) {
            throw new \InvalidArgumentException('axiam: authz requester timeout must be positive');
        }
        $this->tenantId = strtolower($tenantId);
        $this->newId = $idGenerator ?? static fn (): string => self::randomUuid();
        $this->clock = $clock ?? static fn (): int => time();

        $queue = $transport->declareReplyQueue($this->handleDelivery(...));
        if ($queue === '' || str_starts_with($queue, self::SERVER_QUEUE_PREFIX)) {
            $transport->close();

            throw new AxiamException(sprintf('axiam: authz reply queue "%s" is not a private queue', $queue));
        }
        $this->replyTo = $queue;
    }

    /** The private reply queue requests name in their `reply_to`. */
    public function replyTo(): string
    {
        return $this->replyTo;
    }

    /** Stops accepting answers and releases the transport. Idempotent; the exclusive auto-delete queue goes with it. */
    public function close(): void
    {
        if ($this->closed) {
            return;
        }
        $this->closed = true;
        $this->pending = [];
        $this->transport->close();
    }

    /**
     * Asks the server whether `$subjectId` may perform `$action` on `$resourceId` (optionally
     * narrowed by `$scope`) and waits for the VERIFIED answer.
     *
     * A response that fails verification or binding is discarded and this keeps waiting for the
     * genuine one until the timeout: a failed verification is never an allow and never
     * completes the request.
     *
     * @param string      $subjectId  UUID of the subject.
     * @param string      $action     The action, e.g. `documents:read`. Valid UTF-8 without U+2028/U+2029.
     * @param string      $resourceId UUID of the resource.
     * @param string|null $scope      Optional single scope narrowing the check.
     * @param float|null  $timeoutSeconds Overrides the constructor's timeout for this call.
     *
     * @throws \InvalidArgumentException when an id is not a UUID or the action/scope cannot be signed byte-exactly.
     * @throws NetworkError when the requester is closed, the broker session is lost or no genuine answer arrives in time.
     */
    public function check(
        string $subjectId,
        string $action,
        string $resourceId,
        ?string $scope = null,
        ?float $timeoutSeconds = null,
    ): AuthzDecision {
        if ($this->closed) {
            throw NetworkError::fromMessage('axiam: authz requester is closed');
        }

        $correlationId = ($this->newId)();
        $nonce = ($this->newId)();
        $body = $this->buildRequest($correlationId, $subjectId, $action, $resourceId, $scope, $nonce);

        $this->pending[$correlationId] = ['nonce' => $nonce, 'decision' => null];

        try {
            try {
                $this->transport->publishRequest(self::REQUEST_QUEUE, $this->replyTo, $correlationId, $body);
            } catch (\Throwable $e) {
                throw NetworkError::fromException($e, 'axiam: failed to publish authz request');
            }

            $timeout = $timeoutSeconds !== null && $timeoutSeconds > 0.0 ? $timeoutSeconds : $this->timeoutSeconds;
            $deadline = microtime(true) + $timeout;
            while (true) {
                $decision = $this->decisionFor($correlationId);
                if ($decision !== null) {
                    return $decision;
                }
                if ($this->closed) {
                    throw NetworkError::fromMessage('axiam: authz requester is closed');
                }
                $remaining = $deadline - microtime(true);
                if ($remaining <= 0.0) {
                    throw NetworkError::fromMessage('axiam: timed out waiting for a verified authz response');
                }
                if (!$this->transport->wait($remaining)) {
                    throw NetworkError::fromMessage('axiam: the authz reply queue went away');
                }
            }
        } finally {
            unset($this->pending[$correlationId]);
        }
    }

    /** The accepted decision for `$correlationId`, once a delivery handler has recorded one. */
    private function decisionFor(string $correlationId): ?AuthzDecision
    {
        return $this->pending[$correlationId]['decision'] ?? null;
    }

    /**
     * Verifies one delivery and completes the matching request, or discards it (nack without
     * requeue plus a security event). Called by the transport for every delivery on the reply
     * queue.
     *
     * @internal
     */
    public function handleDelivery(AuthzDelivery $delivery): void
    {
        $outcome = $this->verifyResponse($delivery->body());
        if (is_string($outcome)) {
            // The fact of the failure only — never a signature value (§8 protocol rule 4).
            $this->logger->warning('axiam_sdk_security: AMQP authz response discarded: ' . $outcome);
            $delivery->nackNoRequeue();

            return;
        }

        [$decision, $correlationId] = $outcome;
        if (!isset($this->pending[$correlationId]) || $this->pending[$correlationId]['decision'] !== null) {
            $this->logger->warning('axiam_sdk_security: AMQP authz response discarded: no outstanding request');
            $delivery->nackNoRequeue();

            return;
        }

        // Retired on acceptance: a second response for it finds a decision already recorded
        // (or, once check() has collected it, no entry) and is dropped.
        $this->pending[$correlationId]['decision'] = $decision;
        $delivery->ack();
    }

    /**
     * Applies the §8 consumer obligations 1–3 to `$body`. Returns `[decision, correlation_id]`, or a
     * string naming the failure. It never re-serializes: the signature is checked over `$body` minus
     * its trailing signature member and the decision is decoded from those same bytes.
     *
     * @return array{0: AuthzDecision, 1: string}|string
     */
    private function verifyResponse(string $body): array|string
    {
        if (StrictJson::isAmbiguousObject($body)) {
            return 'body is not an object with unambiguous keys';
        }
        $members = json_decode($body, true);
        if (!is_array($members)) {
            return 'body is not a JSON object';
        }

        // Rule 1 (strict parse) for the member every response carries.
        if (!array_key_exists('allowed', $members) || !is_bool($members['allowed'])) {
            return 'allowed is missing or not a boolean';
        }

        if (!array_key_exists('hmac_signature', $members)) {
            return $this->acceptUnsigned($members);
        }

        // The canonical bytes: `$body` with the final `,"hmac_signature":"<64 hex>"` taken out of
        // the closing brace. A body not ending in that member is discarded (rule 1) — never
        // repaired by re-serializing.
        $cut = self::cutTrailingSignature($body);
        if ($cut === null) {
            return 'body does not end in the hmac_signature member';
        }
        [$canonical, $sigHex] = $cut;
        if ($members['hmac_signature'] !== $sigHex) {
            return 'hmac_signature is not the trailing member';
        }
        $got = hex2bin($sigHex);
        if ($got === false) {
            return 'hmac_signature is not hex';
        }

        // Rule 2: HMAC-SHA256 under the requester's own tenant subkey, constant time.
        if (!hash_equals(hash_hmac('sha256', $canonical, $this->signingKey, true), $got)) {
            return 'signature does not verify';
        }

        // Everything below reads the VERIFIED canonical bytes, not $body (C2).
        $resp = json_decode($canonical, true);
        if (!is_array($resp)) {
            return 'verified bytes do not decode';
        }
        if (!is_bool($resp['allowed'] ?? null)) {
            return 'allowed is missing or not a boolean';
        }
        $tenantId = $resp['tenant_id'] ?? null;
        $nonce = $resp['nonce'] ?? null;
        $correlationId = $resp['correlation_id'] ?? null;
        if (!is_string($tenantId) || $tenantId === '' || !is_string($nonce) || $nonce === ''
            || !is_string($correlationId) || $correlationId === '') {
            return 'tenant_id, nonce or correlation_id is missing';
        }
        $decision = self::decisionFrom($resp, false);
        if ($decision === null) {
            return 'reason or reason_code is not a string';
        }

        // Rule 3: binding to this requester's tenant and to ONE outstanding request.
        if ($tenantId !== $this->tenantId) {
            return "tenant_id is not the requester's";
        }
        $outstanding = $this->pending[$correlationId] ?? null;
        if ($outstanding === null || $outstanding['decision'] !== null || !hash_equals($outstanding['nonce'], $nonce)) {
            return 'correlation_id and nonce match no outstanding request';
        }

        return [$decision, $correlationId];
    }

    /**
     * A response with no `hmac_signature` member: refused unless `allowUnsignedResponses` is set,
     * in which case it is accepted on its `correlation_id` alone (a pre-1.68 server answers with
     * no `tenant_id` or `nonce`) and logged as a warning.
     *
     * @param array<string,mixed> $members
     *
     * @return array{0: AuthzDecision, 1: string}|string
     */
    private function acceptUnsigned(array $members): array|string
    {
        if (!$this->allowUnsignedResponses) {
            return 'response is unsigned';
        }
        $correlationId = $members['correlation_id'] ?? null;
        if (!is_string($correlationId) || $correlationId === '') {
            return 'unsigned response has no correlation_id';
        }
        if (!isset($this->pending[$correlationId]) || $this->pending[$correlationId]['decision'] !== null) {
            return 'correlation_id matches no outstanding request';
        }
        $decision = self::decisionFrom($members, true);
        if ($decision === null) {
            return 'reason or reason_code is not a string';
        }
        $this->logger->warning('axiam_sdk_security: AMQP authz response accepted UNSIGNED because allowUnsignedResponses is set');

        return [$decision, $correlationId];
    }

    /**
     * @param array<string,mixed> $resp
     */
    private static function decisionFrom(array $resp, bool $unsigned): ?AuthzDecision
    {
        $reason = $resp['reason'] ?? null;
        $reasonCode = $resp['reason_code'] ?? null;
        if (($reason !== null && !is_string($reason)) || ($reasonCode !== null && !is_string($reasonCode))) {
            return null;
        }

        return new AuthzDecision($resp['allowed'] === true, $reason, $reasonCode, $unsigned);
    }

    /**
     * Removes the final `,"hmac_signature":"<64 hex>"` member from `$body`, returning the canonical
     * bytes (the rest, closed with `}`) and the signature hex, or `null` when `$body` does not end
     * in exactly that member.
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

    /**
     * Serializes and signs an `AuthzRequest` in the server's field order, compact, with the
     * signature appended as the trailing member. The members are written exactly as
     * `serde_json` writes them: `/`, `<`, `>`, `&` and non-ASCII raw, U+2028/U+2029 raw — which
     * is why the action and scope must be valid UTF-8 (a string `json_encode` cannot encode is
     * refused rather than repaired).
     *
     * @throws \InvalidArgumentException
     */
    private function buildRequest(
        string $correlationId,
        string $subjectId,
        string $action,
        string $resourceId,
        ?string $scope,
        string $nonce,
    ): string {
        if (preg_match(self::UUID_PATTERN, $subjectId) !== 1) {
            throw new \InvalidArgumentException('axiam: subject_id is not a UUID');
        }
        if (preg_match(self::UUID_PATTERN, $resourceId) !== 1) {
            throw new \InvalidArgumentException('axiam: resource_id is not a UUID');
        }

        $request = [
            'correlation_id' => $correlationId,
            'tenant_id' => $this->tenantId,
            'subject_id' => strtolower($subjectId),
            'action' => $action,
            'resource_id' => strtolower($resourceId),
        ];
        if ($scope !== null) {
            $request['scope'] = $scope;
        }
        $request['key_version'] = self::KEY_VERSION;
        $request['nonce'] = $nonce;
        $request['issued_at'] = gmdate('Y-m-d\TH:i:s\Z', ($this->clock)());

        $canonical = json_encode(
            $request,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_LINE_TERMINATORS,
        );
        if ($canonical === false) {
            throw new \InvalidArgumentException('axiam: action and scope must be valid UTF-8');
        }

        $signature = bin2hex(hash_hmac('sha256', $canonical, $this->signingKey, true));

        return substr($canonical, 0, -1) . self::SIGNATURE_MEMBER . $signature . '"}';
    }

    /** A random (v4) UUID. */
    private static function randomUuid(): string
    {
        $bytes = random_bytes(16);
        $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
        $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
        $hex = bin2hex($bytes);

        return sprintf('%s-%s-%s-%s-%s', substr($hex, 0, 8), substr($hex, 8, 4), substr($hex, 12, 4), substr($hex, 16, 4), substr($hex, 20, 12));
    }
}
