<?php

declare(strict_types=1);

namespace Axiam\Sdk\Rest;

use Axiam\Sdk\Core\TelemetryEvent;
use Axiam\Sdk\Core\TelemetryDispatcher;
use Axiam\Sdk\Core\RetryPolicy;
use Axiam\Sdk\Core\DecisionMemo;
use Axiam\Sdk\Core\ErrorMapper;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;

/**
 * REST authorization transport (FND-04, CONTRACT.md §1): `checkAccess()`/`can()`/
 * `batchCheck()` over `POST /api/v1/authz/check[/batch]` — the ALWAYS-available authz
 * path (D-03). Reuses the caller-supplied Guzzle client (the same instance
 * {@see \Axiam\Sdk\Session} wires with {@see AuthMiddleware}/{@see RefreshMiddleware} on
 * its `HandlerStack`), so `Authorization`/`X-Tenant-ID`/`X-CSRF-Token` header injection
 * and the single-flight refresh-on-401 behavior (D-06) apply to authz calls exactly as
 * they do to every other REST call — this class never re-implements any of that.
 *
 * Wire field names match `crates/axiam-api-rest/src/handlers/authz_check.rs` exactly:
 * `action`, `resource_id` (camelCase `resourceId` on the PHP call surface, snake_case on
 * the wire), optional `scope`. `tenant_id` is never sent in the body — the server
 * derives it from the verified JWT (SEC-003). `subject_id` is likewise omitted by
 * default (the server falls back to deriving the subject from the same verified JWT,
 * i.e. whichever session's Bearer token is attached to the request) — but CONTRACT.md
 * §11.2.2 (declarative authorization helpers) requires an explicit, additive
 * `subject_id` override: {@see \Axiam\Sdk\AccessEnforcer} calls a shared AXIAM client
 * on behalf of the REQUEST's authenticated end user, which is a *different* identity
 * than whatever session the shared client itself is authenticated as (typically a
 * service account) — omitting `subject_id` in that scenario would silently check the
 * service account's permissions instead of the end user's. See
 * {@see self::checkAccess()}'s `$subjectId` parameter.
 */
final class AuthzRestClient
{
    /**
     * The §1 single-check route. Used as the §19 `path template` — the route
     * constant, never a URL with ids substituted in, because a metric label
     * carrying a UUID is a cardinality bomb.
     */
    private const CHECK_PATH = '/api/v1/authz/check';

    /** §19: the route CONSTANT, never a URL with ids substituted in. */
    private const BATCH_PATH = '/api/v1/authz/check/batch';

    /**
     * @param Client                       $http      The Guzzle client.
     * @param DecisionMemo|null            $memo      §17 memo; disabled when omitted.
     * @param TelemetryDispatcher|null     $telemetry §19 dispatcher; inert when omitted.
     * @param bool                         $retry     §16.1 disable switch.
     * @param (callable(): float)|null     $jitter    Injected jitter draw, for tests.
     * @param (callable(float): void)|null $sleep     Injected sleep, for tests.
     */
    public function __construct(
        private readonly Client $http,
        private readonly ?DecisionMemo $memo = null,
        private readonly ?TelemetryDispatcher $telemetry = null,
        private readonly bool $retry = true,
        private $jitter = null,
        private $sleep = null,
    ) {
    }

    /**
     * The §19 dispatcher, or an inert one when none was supplied.
     */
    private function dispatcher(): TelemetryDispatcher
    {
        return $this->telemetry ?? new TelemetryDispatcher();
    }

    /**
     * The §17 memo, or a disabled one when none was supplied.
     */
    private function memo(): DecisionMemo
    {
        return $this->memo ?? new DecisionMemo();
    }

    /**
     * `checkAccess` (CONTRACT.md §1). `POST /api/v1/authz/check`. Returns the decoded
     * `allowed` boolean; non-2xx responses are translated via {@see ErrorMapper} (403 ->
     * `AuthzError`, 401 -> `AuthError`, everything else -> `NetworkError`).
     *
     * @param string|null $subjectId Additive, optional (CONTRACT.md §11.2.2): when
     *        given, sent on the wire as `subject_id` so the server evaluates the
     *        check for THIS subject rather than whichever identity the calling
     *        client's own Bearer token represents. `null` (the default) preserves the
     *        pre-§11 behavior exactly — no `subject_id` field is sent, and the server
     *        derives the subject from the verified JWT as before.
     */
    public function checkAccess(string $action, string $resourceId, ?string $scope = null, ?string $subjectId = null): bool
    {
        // Delegates to checkAccessDecision rather than posting directly.
        //
        // It used to post directly, through a private helper that had no §16 retry
        // budget, no §17 memo and no §19 request pair — so the most-used method on this
        // class was the one method that did none of D5, while the D5 conformance suite
        // (which drives checkAccessDecision) stayed green. That is precisely the failure
        // §16.7 was written about: "a tested surface nobody calls is worse than an absent
        // one, because the passing tests are what stop anyone from looking." Here the
        // surface was called and the tests looked elsewhere, which is the same hole
        // seen from the other side.
        //
        // Delegating, rather than duplicating the instrumentation, is what stops it
        // recurring: there is now one instrumented path and no second one to forget.
        return $this->checkAccessDecision($action, $resourceId, $scope, $subjectId)->allowed;
    }

    /**
     * `can` (CONTRACT.md §1): the ergonomic browser/UI-scenario alias for
     * {@see self::checkAccess()} — same endpoint, same semantics (§1 note: "`can` is an
     * alias for `check_access`").
     */
    public function can(string $resource, string $action): bool
    {
        return $this->checkAccess($action, $resource);
    }

    /**
     * `batchCheck` (CONTRACT.md §1): `POST /api/v1/authz/check/batch`. `$checks` is a
     * list of `[action, resourceId, scope?]` tuples; the returned list of `allowed`
     * booleans preserves input order exactly, matching
     * `BatchCheckAccessResponse::results` on the server (same order/length guarantee).
     *
     * @param list<array{action: string, resourceId: string, scope?: string|null}> $checks
     * @return list<bool>
     */
    public function batchCheck(array $checks): array
    {
        // Delegates to batchCheckDecisions for the same reason checkAccess delegates to
        // checkAccessDecision: one instrumented path, and no second one to forget. The
        // key rename below is the only difference between the two call surfaces — this
        // method takes `resourceId`, the decision-returning one takes the wire spelling.
        $decisions = $this->batchCheckDecisions(array_map(
            static fn (array $check): array => array_filter(
                [
                    'action' => $check['action'],
                    'resource_id' => $check['resourceId'],
                    'scope' => $check['scope'] ?? null,
                ],
                static fn (mixed $value): bool => $value !== null,
            ),
            $checks,
        ));

        return array_values(array_map(
            static fn (AccessDecision $decision): bool => $decision->allowed,
            $decisions,
        ));
    }

    /**
     * `POST /api/v1/authz/check` returning the **full** decision, including the
     * CONTRACT.md §11 rule 9 `reason_code`.
     *
     * Exists because {@see self::checkAccess()} returns a bare `bool` that predates that
     * field and cannot carry it without a breaking signature change. The distinction it
     * surfaces is not cosmetic: `no_grant` means "ask an admin for access",
     * `denied_by_rule` means "an admin has already decided", and an application that
     * cannot tell them apart sends users to raise tickets that will be refused.
     */
    public function checkAccessDecision(
        string $action,
        string $resourceId,
        ?string $scope = null,
        ?string $subjectId = null,
    ): AccessDecision {
        // §17: consult the memo first. Disabled by default, in which case this is
        // one array lookup that always misses.
        $key = DecisionMemo::key($subjectId, $resourceId, $action, $scope);
        $memoized = $this->memo()->get($key);
        if ($memoized !== null) {
            return $memoized;
        }

        // §16: a POST, but side-effect-free, so it is retry-eligible. Eligibility is
        // "changes no server state", NOT "is a GET" — gating on the verb would
        // exclude the single most important operation this policy covers.
        $decision = RetryPolicy::execute(
            'checkAccess',
            $this->retry,
            $this->dispatcher(),
            fn (int $attempt): AccessDecision => $this->sendCheck(
                $action,
                $resourceId,
                $scope,
                $subjectId,
                $attempt,
            ),
            $this->jitter,
            $this->sleep,
        );

        // Only a decision the server actually returned is memoized: reaching here
        // means success, so §17.1 rule 7's ban on caching a failure is structural
        // rather than a check that could be forgotten.
        $this->memo()->put($key, $decision);

        return $decision;
    }

    /**
     * One §16 attempt at the single-check call, with its §19 request pair.
     */
    private function sendCheck(
        string $action,
        string $resourceId,
        ?string $scope,
        ?string $subjectId,
        int $attempt,
    ): AccessDecision {
        $end = $this->dispatcher()->startRequest('checkAccess', 'POST', self::CHECK_PATH, $attempt);

        try {
            $response = $this->postCheck($action, $resourceId, $scope, $subjectId);
        } catch (\Throwable $e) {
            $end(null, TelemetryEvent::OUTCOME_FAILURE);
            throw $e;
        }

        $decoded = json_decode((string) $response->getBody(), true);
        if (!is_array($decoded)) {
            $end($response->getStatusCode(), TelemetryEvent::OUTCOME_FAILURE);
            throw \Axiam\Sdk\Core\NetworkError::fromResponse($response, 'authz checkAccess: malformed response body');
        }

        $end($response->getStatusCode(), TelemetryEvent::OUTCOME_SUCCESS);

        return self::toDecision($decoded);
    }

    /**
     * `POST /api/v1/authz/check/batch` returning the **full** decisions, including each
     * `reason_code` (§11 rule 9). Results preserve input order.
     *
     * @param list<array{action:string,resource_id:string,scope?:string|null,subject_id?:string|null}> $checks
     * @return list<AccessDecision>
     */
    public function batchCheckDecisions(array $checks): array
    {
        // §16.2 names batch_check as retry-eligible alongside check_access — it is the
        // same side-effect-free POST, just plural. Deliberately NOT memoized: the §17
        // key is per-check, so a batch would have to split into n entries with n keys,
        // which changes what a partial hit means (some rows from the wire, some from
        // the memo, one composite result). §17 says nothing about batch, so this takes
        // the conservative reading rather than inventing semantics.
        return RetryPolicy::execute(
            'batchCheck',
            $this->retry,
            $this->dispatcher(),
            fn (int $attempt): array => $this->sendBatch($checks, $attempt),
            $this->jitter,
            $this->sleep,
        );
    }

    /**
     * One §16 attempt at the batch call, with its §19 request pair.
     *
     * @param list<array{action:string,resource_id:string,scope?:string|null,subject_id?:string|null}> $checks
     * @return list<AccessDecision>
     */
    private function sendBatch(array $checks, int $attempt): array
    {
        $body = ['checks' => array_map(
            static fn (array $check): array => array_filter(
                $check,
                static fn (mixed $value): bool => $value !== null,
            ),
            $checks,
        )];

        $end = $this->dispatcher()->startRequest('batchCheck', 'POST', self::BATCH_PATH, $attempt);

        try {
            $response = $this->http->post(self::BATCH_PATH, ['json' => $body]);
        } catch (RequestException $e) {
            $end(null, TelemetryEvent::OUTCOME_FAILURE);
            throw $this->mapException($e);
        } catch (GuzzleException $e) {
            $end(null, TelemetryEvent::OUTCOME_FAILURE);
            throw \Axiam\Sdk\Core\NetworkError::fromException($e, 'authz batchCheck request failed');
        }

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            $end($status, TelemetryEvent::OUTCOME_FAILURE);
            throw ErrorMapper::fromResponse($response, 'authz batchCheck failed');
        }

        $decoded = json_decode((string) $response->getBody(), true);
        if (!is_array($decoded) || !isset($decoded['results']) || !is_array($decoded['results'])) {
            $end($status, TelemetryEvent::OUTCOME_FAILURE);
            throw \Axiam\Sdk\Core\NetworkError::fromResponse($response, 'authz batchCheck: malformed response body');
        }

        $end($status, TelemetryEvent::OUTCOME_SUCCESS);

        return array_values(array_map(
            static fn (mixed $result): AccessDecision => self::toDecision(is_array($result) ? $result : []),
            $decoded['results'],
        ));
    }

    /**
     * Map one decoded decision object.
     *
     * §11 rule 9: the reason code is surfaced verbatim, including a value this SDK has
     * never heard of — the outcome is carried by `allowed` alone, so an unknown code can
     * never change it.
     *
     * @param array<string,mixed> $decoded
     */
    private static function toDecision(array $decoded): AccessDecision
    {
        return new AccessDecision(
            allowed: ($decoded['allowed'] ?? false) === true,
            reason: is_string($decoded['reason'] ?? null) ? $decoded['reason'] : null,
            reasonCode: is_string($decoded['reason_code'] ?? null) ? $decoded['reason_code'] : null,
        );
    }

    /** `POST /api/v1/authz/check` — shared by {@see self::checkAccess()} and {@see self::can()}. */
    private function postCheck(string $action, string $resourceId, ?string $scope, ?string $subjectId = null): \Psr\Http\Message\ResponseInterface
    {
        $body = array_filter(
            [
                'action' => $action,
                'resource_id' => $resourceId,
                'scope' => $scope,
                'subject_id' => $subjectId,
            ],
            static fn (mixed $value): bool => $value !== null,
        );

        try {
            $response = $this->http->post(self::CHECK_PATH, ['json' => $body]);
        } catch (RequestException $e) {
            throw $this->mapException($e);
        } catch (GuzzleException $e) {
            throw \Axiam\Sdk\Core\NetworkError::fromException($e, 'authz checkAccess request failed');
        }

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw ErrorMapper::fromResponse($response, 'authz checkAccess failed');
        }

        return $response;
    }

    private function mapException(RequestException $e): \Axiam\Sdk\Core\AxiamException
    {
        // Guzzle 7 exposes getResponse() on RequestException; Guzzle 8 moved it to
        // BadResponseException only (a bare RequestException/ConnectException has no
        // response). Guard on BadResponseException so this holds on ^7.13 and ^8.0.
        $response = $e instanceof BadResponseException ? $e->getResponse() : null;
        if ($response !== null) {
            return ErrorMapper::fromResponse($response, 'authz request failed');
        }

        return \Axiam\Sdk\Core\NetworkError::fromException($e, 'authz request failed');
    }
}
