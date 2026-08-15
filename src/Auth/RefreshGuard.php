<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

use Axiam\Sdk\Core\AuthError;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Promise\Utils;

/**
 * Shared-promise clear-on-both-paths helper (CONTRACT.md §9, D-06).
 *
 * {@see self::settle()} wraps a refresh call's raw `PromiseInterface` so that,
 * regardless of success or failure, the caller's `$onClear` closure runs exactly
 * once — clearing the caller's own stored promise slot (e.g. `Session::$refreshPromise`)
 * so the NEXT 401 always starts a brand-new refresh attempt (§9.3: no retry loop; a
 * failed refresh is never cached for the next caller, mirroring the C# sibling
 * `Axiam.Sdk.Auth.RefreshGuard`'s "never cache a faulted refresh" invariant).
 *
 * PHP has no cross-object mutable-reference primitive that would let this helper
 * safely OWN a mutable promise-slot on behalf of multiple unrelated session objects
 * (unlike C#'s field-holding `RefreshGuard` class), so the slot itself stays on the
 * owning session (`Axiam\Sdk\Session` today; a future gRPC session would hold its own
 * field the same way). What this class DOES factor out — and what every such session
 * must apply identically — is the clear-on-both-paths bookkeeping and the
 * normalize-to-`AuthError` failure translation, so REST and (later) gRPC never drift
 * on that one piece of behavior (D-06's "ONE mechanism" requirement).
 */
final class RefreshGuard
{
    /**
     * How many times {@see self::join()} yields to the scheduler before giving up on an
     * in-flight refresh and raising {@see AuthError} (CONTRACT.md §9 rule 5 requires the
     * wait to be BOUNDED and to fail with `AuthError` rather than return a stale token
     * set; the specific bound is explicitly not part of the contract). Only ever reached
     * on a concurrent runtime whose leader never settles.
     */
    private const JOIN_MAX_YIELDS = 5000;

    /**
     * Pause per {@see self::join()} yield when the caller is NOT inside a `Fiber` —
     * see {@see self::yieldToScheduler()}. With {@see self::JOIN_MAX_YIELDS} this bounds
     * a non-fiber join at ~5 s.
     */
    private const JOIN_YIELD_MICROSECONDS = 1000;

    /**
     * @param PromiseInterface $refreshCall The raw in-flight refresh request promise.
     * @param \Closure(): void $onClear Clears the caller's stored promise slot. Invoked
     *        exactly once, on EITHER the success or the failure path — never on both,
     *        never on neither.
     * @param (\Closure(mixed): mixed)|null $onSuccess Optional success-path transform
     *        (e.g. CSRF-token capture) run AFTER `$onClear`, before the settled value
     *        is handed back to the caller.
     */
    public static function settle(
        PromiseInterface $refreshCall,
        \Closure $onClear,
        ?\Closure $onSuccess = null,
    ): PromiseInterface {
        return $refreshCall->then(
            function (mixed $result) use ($onClear, $onSuccess): mixed {
                $onClear(); // clear on success (§9.3) — the next 401 starts fresh
                return $onSuccess !== null ? $onSuccess($result) : $result;
            },
            function (\Throwable $reason) use ($onClear): never {
                $onClear(); // clear on failure too (§9.3) — no retry loop, never cached
                throw $reason instanceof AuthError
                    ? $reason
                    : new AuthError('token refresh failed: ' . $reason->getMessage());
            },
        );
    }

    /**
     * Wait for an ALREADY-IN-FLIGHT shared refresh to settle and return its outcome —
     * the waiter's half of CONTRACT.md §9 rule 2 (F-06).
     *
     * A caller that finds the guard occupied MUST end up holding the *leader's* outcome:
     * AXIAM refresh tokens are opaque, server-stored and single-use with rotation, so a
     * second wire call would replay an already-consumed token. The obvious way to wait —
     * `$shared->wait()` — is exactly what must NOT be done here, and is why this method
     * exists:
     *
     *   `GuzzleHttp\Promise\Promise::wait()` does not "wait" in the concurrent sense. It
     *   *drives* the promise: it takes the underlying promise's wait function, NULLS it,
     *   and runs it. The leader already did that when it started its own wire call, so a
     *   second `wait()` from another fiber/coroutine walks the same wait list, finds a
     *   pending promise with no wait function left, and **rejects the leader's promise**
     *   with "Cannot wait on a promise that has no internal wait function". That kills
     *   the in-flight refresh for everyone AND frees the guard slot mid-flight, so the
     *   next caller starts a second `POST /oauth2/token` with a refresh token the leader
     *   has already spent — the precise failure §9 rule 2 forbids.
     *
     * So this observes rather than drives: it registers a callback on the shared promise,
     * drains Guzzle's task queue (which is all that is needed in the overwhelmingly
     * common case — a promise that has already settled and merely has deferred callbacks
     * outstanding), and otherwise yields to whatever scheduler is driving the leader
     * until the outcome arrives. Rule 6(a)/(d) fall out of this by construction: the
     * callback is registered BEFORE any yielding, so the outcome cannot be missed no
     * matter when the leader clears the slot, and a caller that arrives after full
     * settlement never gets here — it acquires the free guard and refreshes afresh.
     *
     * @param PromiseInterface $shared The in-flight refresh promise returned by
     *        `Session::refreshGuard()`'s `promise` key. Already normalized by
     *        {@see self::settle()}, so its failure mode is {@see AuthError}.
     *
     * @return mixed The leader's fulfilment value — for `oidc_refresh`, the decoded
     *         `TokenResponse` array of the ONE wire call every caller shares.
     *
     * @throws AuthError The leader's failure, shared verbatim with every waiter
     *         (§9 rule 2: "on failure, all waiting requests fail with `AuthError`"), or a
     *         fresh one if the bounded wait is exhausted (§9 rule 5).
     */
    public static function join(PromiseInterface $shared): mixed
    {
        $settled = false;
        $value = null;
        $failure = null;

        $shared->then(
            static function (mixed $result) use (&$settled, &$value): mixed {
                $settled = true;
                $value = $result;

                return $result;
            },
            // Deliberately does NOT re-throw: re-throwing would derive a second rejected
            // promise that nobody handles, purely as a side effect of observing. The
            // failure is re-raised from this method's own stack frame instead, below.
            static function (\Throwable $reason) use (&$settled, &$failure): void {
                $settled = true;
                $failure = $reason;
            },
        );

        for ($yields = 0; ; $yields++) {
            // Runs any callback the shared promise has already queued — including the
            // one registered just above when the promise was settled on arrival.
            Utils::queue()->run();
            if ($settled) {
                break;
            }

            if ($yields >= self::JOIN_MAX_YIELDS) {
                throw new AuthError(
                    'timed out waiting for the in-flight single-flight refresh to complete (CONTRACT.md §9)',
                );
            }

            self::yieldToScheduler();
        }

        if ($failure !== null) {
            throw $failure instanceof AuthError
                ? $failure
                : new AuthError('token refresh failed: ' . $failure->getMessage());
        }

        return $value;
    }

    /**
     * Hand control back to whatever is driving the in-flight leader.
     *
     * Inside a `Fiber` that is the fiber scheduler, which resumes this caller when it
     * next runs. Outside one, the caller can only be here on a runtime that provides
     * concurrency some other way (Swoole/RoadRunner coroutines, where the standard
     * library is hooked and this sleep yields the coroutine); on a plain synchronous
     * runtime no second caller can exist in the first place, so this line is
     * unreachable there.
     */
    private static function yieldToScheduler(): void
    {
        if (\Fiber::getCurrent() !== null) {
            \Fiber::suspend();

            return;
        }

        usleep(self::JOIN_YIELD_MICROSECONDS);
    }
}
