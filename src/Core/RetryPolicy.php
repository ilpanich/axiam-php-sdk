<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

/**
 * Bounded read-only retry policy — CONTRACT.md §16.
 *
 * This SDK had **no** §16 policy before D5 — only §9's single-flight refresh
 * coordination, which is a different mechanism (`OidcClient`'s
 * `for ($attempt = 0; $attempt < 3; $attempt++)` loop coordinates concurrent
 * refreshes; it does not retry a transport failure). §11.2 rule 5 and §14.2
 * rule 6 had both been requiring "the SDK's existing bounded read-only retry
 * policy" against a policy that did not exist here.
 */
final class RetryPolicy
{
    /** Attempt cap: 1 initial + 2 retries (§16.1). */
    public const MAX_ATTEMPTS = 3;

    /** First backoff step, in milliseconds (§16.1). */
    public const BASE_DELAY_MS = 200.0;

    /** Ceiling on any single computed backoff, in milliseconds (§16.1). */
    public const MAX_DELAY_MS = 5000.0;

    /**
     * The un-jittered backoff for a 1-based attempt:
     * `min(MAX_DELAY_MS, BASE_DELAY_MS * 2^(n-1))`.
     *
     * Attempt 1 → 200ms, attempt 2 → 400ms.
     *
     * @param int $attempt The 1-based attempt number.
     * @return float The backoff in milliseconds.
     */
    public static function backoffMs(int $attempt): float
    {
        $shift = max(0, min($attempt - 1, 32));
        $ms = self::BASE_DELAY_MS * (2 ** $shift);

        return $ms > self::MAX_DELAY_MS ? self::MAX_DELAY_MS : $ms;
    }

    /**
     * The actual wait: **full jitter** over `[0, backoff]`, raised to any
     * server-supplied `Retry-After` (§16.1).
     *
     * Full jitter, not `backoff ± 10%`. Partial jitter keeps every client's
     * retries clustered around the same instant, which is the thundering herd
     * retries are supposed to prevent rather than cause.
     *
     * `Retry-After` is a **floor, never a ceiling**: the server is stating when
     * it will be ready, so retrying sooner is not permitted — and a
     * `Retry-After: 0` cannot shorten the wait below what jitter chose.
     *
     * @param int   $attempt      The 1-based attempt that just failed.
     * @param float $retryAfterMs A server-supplied hint in milliseconds, or 0.0.
     * @param float $fraction     The jitter draw in `[0, 1]`, injected so tests can pin it.
     * @return float The wait in milliseconds.
     */
    public static function delayMs(int $attempt, float $retryAfterMs, float $fraction): float
    {
        $clamped = max(0.0, min($fraction, 1.0));
        $jittered = self::backoffMs($attempt) * $clamped;

        return $retryAfterMs > $jittered ? $retryAfterMs : $jittered;
    }

    /**
     * Runs `$operation` under the §16 policy.
     *
     * `$operation` receives the 1-based attempt number so it can label its §19
     * request pair — §19.2 rule 5 requires one pair per attempt so a caller can
     * count real wire calls, and passing 1 every time would make a retried call
     * indistinguishable from a single slow one.
     *
     * `$operation` MUST be side-effect-free. This helper — like every retry
     * helper — cannot tell the difference, so routing a mutation through it
     * would silently duplicate a side effect, or replay a single-use credential
     * (an authorization code, a device code at redemption, a rotating refresh
     * token) into a hard `invalid_grant`.
     *
     * Only {@see NetworkError} is retried. The §2 taxonomy folds
     * `408`/`429`/`5xx`/transport into that one type, so this implements the
     * whole §16.3 table: `AuthError` and `AuthzError` are decisive answers from
     * the server, not transport failures.
     *
     * @template T
     * @param string                  $operationName Canonical name, for the §19 event.
     * @param bool                    $enabled       §16.1 disable switch.
     * @param TelemetryDispatcher     $telemetry     Notified before each retry wait.
     * @param callable(int): T        $operation     The side-effect-free operation.
     * @param (callable(): float)|null $jitter       Injected jitter draw, for tests.
     * @param (callable(float): void)|null $sleep    Injected sleep, for tests.
     * @param (callable(NetworkError): bool)|null $retryable Decides whether a caught
     *        {@see NetworkError} is eligible at all; `null` keeps the previous
     *        behaviour of retrying every one. CONTRACT.md §27 needs this for two
     *        reasons: §27.4 rule 8 retries only `GET`, and §27.4 rule 7 puts
     *        {@see \Axiam\Sdk\Management\ValidationError} UNDER `NetworkError`, so a
     *        body the server has already rejected would otherwise be sent three times.
     * @return T
     */
    public static function execute(
        string $operationName,
        bool $enabled,
        TelemetryDispatcher $telemetry,
        callable $operation,
        ?callable $jitter = null,
        ?callable $sleep = null,
        ?callable $retryable = null,
    ): mixed {
        $attempts = $enabled ? self::MAX_ATTEMPTS : 1;
        $draw = $jitter ?? static fn (): float => mt_rand() / mt_getrandmax();
        // usleep takes microseconds; a test that really waits 200ms is a test
        // nobody runs, so this is injectable (§16.7).
        $wait = $sleep ?? static function (float $ms): void {
            usleep((int) round($ms * 1000));
        };

        for ($attempt = 1; ; $attempt++) {
            try {
                return $operation($attempt);
            } catch (NetworkError $e) {
                if ($attempt >= $attempts || ($retryable !== null && !$retryable($e))) {
                    throw $e;
                }

                $delayMs = self::delayMs($attempt, $e->retryAfterMs ?? 0.0, $draw());

                // §16.5 — without this event a retried-then-succeeded call is
                // invisible: a slow success with no signal the server is failing.
                $telemetry->emit(new RetryEvent(
                    $operationName,
                    $attempt,
                    $delayMs,
                    $e->getMessage(),
                ));

                $wait($delayMs);
            }
        }
    }
}
