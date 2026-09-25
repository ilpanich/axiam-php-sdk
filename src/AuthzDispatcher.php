<?php

declare(strict_types=1);

namespace Axiam\Sdk;

use Axiam\Sdk\Auth\TokenIntrospection;
use Axiam\Sdk\Auth\TokenValidation;
use Axiam\Sdk\Auth\UserInfo;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Grpc\Gen\CheckAccessResponse;
use Axiam\Sdk\Grpc\Gen\GetUserInfoResponse;
use Axiam\Sdk\Rest\AccessDecision;
use Axiam\Sdk\Rest\AuthzRestClient;

/**
 * Transparent REST/gRPC authz transport selection (CONTRACT.md §1, D-03, SC#3).
 *
 * `checkAccess()`/`can()`/`batchCheck()` ALWAYS work: with no `grpc` PECL extension (or
 * `restOnly: true`) they route over `POST /api/v1/authz/check[/batch]` via
 * {@see AuthzRestClient} (FND-04). When the extension IS present and `restOnly` is
 * false, the SAME public methods transparently upgrade to
 * {@see \Axiam\Sdk\Grpc\AuthzGrpcClient} — callers never need to know which transport
 * actually ran.
 *
 * PITFALL 4 / T-22-16 (high severity, `mitigate`): `\Axiam\Sdk\Grpc\AuthzGrpcClient`
 * (which `extends \Grpc\BaseStub`) is referenced ONLY inside the
 * `!$this->restOnly && extension_loaded('grpc')` branches below and inside
 * {@see self::grpcClient()}, which those branches are the only callers of. On a
 * REST-only runtime (no `grpc` PECL extension — the actual condition in this SDK's own
 * CI/dev sandbox) that class is never autoloaded, so no "Class 'Grpc\BaseStub' not
 * found" fatal is possible — {@see \Axiam\Sdk\Tests\AuthzDispatcherFallbackTest} proves
 * this empirically. The typed property {@see self::$grpcClient} and
 * {@see self::grpcClient()}'s return type both name `AuthzGrpcClient`, but PHP resolves
 * class names used only in type declarations lazily (confirmed empirically: a typed
 * property/return-type naming a nonexistent class does not fatal a class that never
 * assigns/invokes it) — the guard is what matters, not merely avoiding the class name in
 * source text.
 *
 * D-06: the gRPC path shares {@see \Axiam\Sdk\Session}'s single-flight refresh/token —
 * `$tokenAccessor` is expected to be `Session::accessToken(...)` (or an equivalent live
 * reader), never a second independent refresh mechanism.
 */
final class AuthzDispatcher
{
    private ?\Axiam\Sdk\Grpc\AuthzGrpcClient $grpcClient = null;

    private ?\Axiam\Sdk\Grpc\UserInfoGrpcClient $userInfoClient = null;

    private ?\Axiam\Sdk\Grpc\TokenGrpcClient $tokenClient = null;

    /**
     * @param callable(): (string|null) $tokenAccessor Reads the CURRENT access token
     *        live (D-06) — required only for the gRPC path; ignored entirely when
     *        `restOnly` is true or the `grpc` extension is absent.
     * @param callable(): string $subjectIdAccessor Reads the current authenticated
     *        user's subject UUID — the gRPC wire contract (unlike REST) requires
     *        `subject_id` explicitly, cross-validated server-side against the verified
     *        JWT (SEC-003); required only for the gRPC path.
     * @param string|null $clientCertPem §6.1 (mTLS): PEM client-certificate chain the gRPC
     *        channel presents for mutual TLS; `null` leaves the channel using bearer-token
     *        auth only. Ignored on the REST path (Guzzle receives its own file-based copy).
     * @param Sensitive|null $clientKey §6.1/§7 (mTLS): the matching private key, wrapped in
     *        {@see Sensitive} so it never leaks; revealed only when building the gRPC channel
     *        credentials. Must be present iff `$clientCertPem` is.
     * @param callable(): void $refreshAccessor Drives the shared §9 single-flight token
     *        refresh (expected to be `Session::refreshIfNeeded()->wait()` or equivalent) —
     *        used by {@see self::getUserInfo()}/{@see self::validateToken()}/
     *        {@see self::introspectToken()} to refresh-and-retry once on a gRPC
     *        `UNAUTHENTICATED` (CONTRACT.md §1.1.4), exactly as REST does on a 401. Never a
     *        second, independent refresh mechanism (D-06); `null` disables the retry (the
     *        UNAUTHENTICATED `AuthError` then surfaces directly).
     * @param callable(): bool $canRefreshAccessor CONTRACT.md §6.1 rule 11 / C-12 N4.5:
     *        "never refreshed, on either transport" — reads whether the CALLER's current
     *        credential can be refreshed at all (expected to be `Session::canRefresh()` or
     *        equivalent). A device credential, or an adopted client-credentials/device-grant
     *        token, has no refresh token behind it: on an `UNAUTHENTICATED`, this is
     *        consulted BEFORE `$refreshAccessor` is ever invoked, so such a credential's
     *        failure surfaces as-is instead of driving a `/api/v1/auth/refresh` call that
     *        could never have succeeded for it. `null` (the default) means "always
     *        refreshable" — the pre-N4.5 behavior, unchanged for a caller that never wires
     *        this in.
     */
    public function __construct(
        private readonly AuthzRestClient $restClient,
        private readonly bool $restOnly = false,
        private readonly ?string $grpcTarget = null,
        private readonly ?string $tenantId = null,
        private readonly mixed $tokenAccessor = null,
        private readonly mixed $subjectIdAccessor = null,
        private readonly ?string $customCaPem = null,
        private readonly ?string $clientCertPem = null,
        private readonly ?Sensitive $clientKey = null,
        private readonly mixed $refreshAccessor = null,
        private readonly mixed $canRefreshAccessor = null,
    ) {
    }

    /**
     * `checkAccess` (CONTRACT.md §1).
     *
     * @param string|null $subjectId Additive, optional (CONTRACT.md §11.2.2 —
     *        declarative authorization helpers): when given, the check is evaluated
     *        for THIS subject rather than whichever identity the dispatcher's own
     *        configured session represents. `null` (the default) preserves the
     *        pre-§11 behavior exactly on both transports — REST omits `subject_id`
     *        from the wire body (server derives it from the verified JWT) and gRPC
     *        falls back to {@see self::currentSubjectId()} (the dispatcher's own
     *        session subject), exactly as before this parameter was added.
     */
    public function checkAccess(string $action, string $resourceId, ?string $scope = null, ?string $subjectId = null): bool
    {
        return $this->checkAccessDecision($action, $resourceId, $scope, $subjectId)->allowed;
    }

    /**
     * `checkAccess`, returning the **full** decision including CONTRACT.md §11 rule 9's
     * `reason_code` — the transport-agnostic counterpart of
     * {@see \Axiam\Sdk\Rest\AuthzRestClient::checkAccessDecision()}, dispatched over
     * whichever transport {@see self::checkAccess()} itself would have used.
     *
     * Exists for {@see \Axiam\Sdk\AccessEnforcer}, which needs `reasonCode` to decide
     * whether a CONTRACT.md §28.5 rule 5 `insufficient_scope` challenge applies to a
     * denial — a distinction {@see self::checkAccess()}'s bare `bool` cannot carry.
     *
     * @param string|null $subjectId See {@see self::checkAccess()}'s own docblock.
     */
    public function checkAccessDecision(string $action, string $resourceId, ?string $scope = null, ?string $subjectId = null): AccessDecision
    {
        if (!$this->restOnly && extension_loaded('grpc')) {
            // Class referenced ONLY inside this guarded branch (Pitfall 4 / T-22-16) —
            // on a runtime without the grpc PECL extension, this line never executes,
            // so Grpc/AuthzGrpcClient.php (which extends \Grpc\BaseStub) is never
            // autoloaded.
            $response = $this->grpcClient()->checkAccess(
                $this->tenantId ?? '',
                $subjectId ?? $this->currentSubjectId(),
                $action,
                $resourceId,
                $scope,
            );

            return self::toDecision($response);
        }

        // D-03: authz ALWAYS works — transparent fallback, not a degraded mode.
        return $this->restClient->checkAccessDecision($action, $resourceId, $scope, $subjectId);
    }

    /**
     * SDK-Q10 (contract 1.19): `reason` (field 4) is canonical; `deny_reason` (field 2,
     * deprecated) is read only when `reason` is absent — the same fallback
     * {@see \Axiam\Sdk\Rest\AuthzRestClient}'s own REST decoder applies, so the two
     * transports can never disagree about which field wins.
     */
    private static function toDecision(CheckAccessResponse $response): AccessDecision
    {
        $reasonCode = $response->getReasonCode();
        $denyReason = $response->getDenyReason();

        return new AccessDecision(
            allowed: $response->getAllowed(),
            reason: $response->hasReason() ? $response->getReason() : ($denyReason !== '' ? $denyReason : null),
            reasonCode: $reasonCode !== '' ? $reasonCode : null,
        );
    }

    /** `can` (CONTRACT.md §1) — the browser/UI-scenario alias for {@see self::checkAccess()}. */
    public function can(string $resource, string $action): bool
    {
        return $this->checkAccess($action, $resource);
    }

    /**
     * `batchCheck` (CONTRACT.md §1) — results preserve input order, mirroring
     * {@see AuthzRestClient::batchCheck()}'s contract exactly regardless of transport.
     *
     * @param list<array{action: string, resourceId: string, scope?: string|null}> $checks
     * @return list<bool>
     */
    public function batchCheck(array $checks): array
    {
        if (!$this->restOnly && extension_loaded('grpc')) {
            // Class referenced ONLY inside this guarded branch (Pitfall 4 / T-22-16).
            $request = new \Axiam\Sdk\Grpc\Gen\BatchCheckAccessRequest();
            $subjectId = $this->currentSubjectId();

            $items = [];
            foreach ($checks as $check) {
                $item = new \Axiam\Sdk\Grpc\Gen\CheckAccessRequest();
                $item->setTenantId($this->tenantId ?? '');
                $item->setSubjectId($subjectId);
                $item->setAction($check['action']);
                $item->setResourceId($check['resourceId']);
                if (($check['scope'] ?? null) !== null) {
                    $item->setScope($check['scope']);
                }
                $items[] = $item;
            }
            $request->setRequests($items);

            $response = $this->grpcClient()->batchCheckAccess($request);

            $results = [];
            foreach ($response->getResults() as $result) {
                $results[] = $result->getAllowed();
            }

            return $results;
        }

        // D-03: authz ALWAYS works — transparent fallback, not a degraded mode.
        return $this->restClient->batchCheck($checks);
    }

    /**
     * `getUserInfo` (CONTRACT.md §1.1) — the gRPC-ONLY OIDC-style userinfo operation, the
     * low-latency counterpart of the server's REST `GET /oauth2/userinfo`. Unlike
     * {@see self::checkAccess()}/{@see self::batchCheck()} it has NO REST fallback: §1.1.6
     * explicitly forbids substituting the REST endpoint, so on a runtime without the `grpc`
     * PECL extension (or with `restOnly: true`) this raises a {@see NetworkError} rather than
     * silently degrading.
     *
     * Behavior (mirrors the checkAccess gRPC path + the REST 401 refresh path exactly):
     *  - §1.1.3 precondition: with no current access token, raises {@see AuthError}
     *    client-side WITHOUT any wire call.
     *  - §1.1.2 metadata: `authorization: Bearer <token>` + `x-tenant-id` on the RPC, via the
     *    same {@see \Axiam\Sdk\Grpc\UserInfoGrpcClient} channel machinery AuthzGrpcClient uses.
     *  - §1.1.4 auth-failure: a gRPC `UNAUTHENTICATED` (surfaced as {@see AuthError}) drives
     *    the shared §9 single-flight refresh (`$refreshAccessor`) and retries the RPC exactly
     *    once; a second failure propagates (no loop, §9.3).
     *  - §1.1.5 return shape: a typed {@see UserInfo} — `sub`/`tenantId`/`orgId` always set,
     *    `email`/`preferredUsername` present only when the token carried the "email"/"profile"
     *    scope (the server gates them; an absent optional is surfaced as `null`).
     */
    public function getUserInfo(): UserInfo
    {
        // §1.1.3 precondition: no token -> AuthenticationError, client-side, no wire call
        // (mirrors AxiamClient's "no active session" guards). Checked FIRST — a prior
        // successful login is a hard precondition of the operation regardless of transport.
        $token = $this->tokenAccessor !== null ? ($this->tokenAccessor)() : null;
        if (!\is_string($token) || $token === '') {
            throw new AuthError('getUserInfo requires a prior successful login (no access token available) — CONTRACT.md §1.1.3');
        }

        // §1.1.6: gRPC-only — never fall back to REST /oauth2/userinfo. On a REST-only
        // runtime this operation is genuinely unavailable; surface that as a transport error.
        // The UserInfoGrpcClient class name below is referenced ONLY past this guard (Pitfall
        // 4 / T-22-16), so a runtime without the grpc PECL extension never autoloads it.
        if ($this->restOnly || !extension_loaded('grpc')) {
            throw NetworkError::fromException(
                new \RuntimeException('the grpc PECL extension is required (getUserInfo is a gRPC-only operation with no REST fallback)'),
                'getUserInfo unavailable',
            );
        }

        $response = $this->getUserInfoWithRefreshRetry(fn (): GetUserInfoResponse => $this->userInfoClient()->getUserInfo());

        return $this->toUserInfo($response);
    }

    /**
     * §1.1.4 refresh-and-retry-once orchestration, factored out of {@see self::getUserInfo()}
     * so it is unit-testable WITHOUT the ext-grpc extension (the concrete gRPC call is passed
     * in as `$rpc`). Runs `$rpc`; on an {@see AuthError} — the taxonomy type
     * {@see \Axiam\Sdk\Grpc\UserInfoGrpcClient} maps a gRPC `UNAUTHENTICATED` to — it drives
     * the shared §9 single-flight refresh (`$refreshAccessor`) exactly once and re-runs `$rpc`
     * exactly once. A second failure (or an absent `$refreshAccessor`) propagates unchanged:
     * no retry loop, a failed refresh is never retried (§9.3), mirroring the REST 401 path.
     *
     * @param callable(): GetUserInfoResponse $rpc
     */
    private function getUserInfoWithRefreshRetry(callable $rpc): GetUserInfoResponse
    {
        try {
            return $rpc();
        } catch (AuthError $e) {
            if ($this->refreshAccessor === null || !$this->canRefresh()) {
                throw $e;
            }
            ($this->refreshAccessor)();

            return $rpc();
        }
    }

    /**
     * CONTRACT.md §6.1 rule 11 / C-12 N4.5: true when `$canRefreshAccessor` is unset
     * (the pre-N4.5 default, "always refreshable") or reports the current credential
     * as refreshable. False short-circuits {@see self::getUserInfoWithRefreshRetry()}/
     * {@see self::withRefreshRetry()} before `$refreshAccessor` is ever invoked.
     */
    private function canRefresh(): bool
    {
        return $this->canRefreshAccessor === null || (bool) ($this->canRefreshAccessor)();
    }

    /** Maps the wire {@see GetUserInfoResponse} to the typed {@see UserInfo} (§1.1.5). */
    private function toUserInfo(GetUserInfoResponse $response): UserInfo
    {
        return new UserInfo(
            sub: $response->getSub(),
            tenantId: $response->getTenantId(),
            orgId: $response->getOrgId(),
            // Optional proto fields: surface an unset claim as null (never ''), so callers
            // can distinguish "scope not granted" from "granted but empty".
            email: $response->hasEmail() ? $response->getEmail() : null,
            preferredUsername: $response->hasPreferredUsername() ? $response->getPreferredUsername() : null,
        );
    }

    /**
     * `validateToken` (CONTRACT.md §1.1.1/§10.3, contract 1.51) — signature + expiry,
     * plus the confirmation §10.3 exists for. Wraps `axiam.v1.TokenService/ValidateToken`.
     *
     * The CALLER'S own token authenticates the RPC (via the same channel machinery every
     * other gRPC call here uses); `$inspectedAccessToken` — a DIFFERENT credential — is
     * the one being asked about (§1.1.1 rule 1). Behaviour otherwise mirrors
     * {@see self::getUserInfo()} exactly: §1.1 rule 3's client-side precondition (no
     * caller token -> {@see AuthError}, zero wire calls), no REST substitution (§1.1.1
     * rule 7), and a gRPC `UNAUTHENTICATED` on the CALLER'S credential drives the shared
     * §9 single-flight refresh and retries once.
     */
    public function validateToken(Sensitive|string $inspectedAccessToken): TokenValidation
    {
        $this->assertCallerToken('validateToken');
        $this->assertGrpcAvailable('validateToken');

        return $this->withRefreshRetry(
            fn (): TokenValidation => $this->tokenClient()->validateToken($inspectedAccessToken),
        );
    }

    /**
     * `introspectToken` (CONTRACT.md §1.1.1/§10.3, contract 1.51) — the RFC 7662 set,
     * plus the confirmation. Wraps `axiam.v1.TokenService/IntrospectToken`. See
     * {@see self::validateToken()} for the shared rules; this is its RFC-7662 sibling.
     */
    public function introspectToken(Sensitive|string $inspectedAccessToken): TokenIntrospection
    {
        $this->assertCallerToken('introspectToken');
        $this->assertGrpcAvailable('introspectToken');

        return $this->withRefreshRetry(
            fn (): TokenIntrospection => $this->tokenClient()->introspectToken($inspectedAccessToken),
        );
    }

    /**
     * §1.1 rule 3 / §1.1.1 rule 2: with no CALLER token, raise {@see AuthError}
     * client-side, with zero wire calls. The interceptor's `UNAUTHENTICATED` would
     * otherwise send the call to the refresh guard with nothing to refresh.
     */
    private function assertCallerToken(string $operation): void
    {
        $token = $this->tokenAccessor !== null ? ($this->tokenAccessor)() : null;
        if (!\is_string($token) || $token === '') {
            throw new AuthError(sprintf(
                '%s requires a prior successful login (no access token available) — CONTRACT.md §1.1 rule 3',
                $operation,
            ));
        }
    }

    /**
     * §1.1.1 rule 7 / §1.1 rule 6: gRPC-only, no REST substitution. On a REST-only
     * runtime this operation is genuinely unavailable.
     */
    private function assertGrpcAvailable(string $operation): void
    {
        if ($this->restOnly || !extension_loaded('grpc')) {
            throw NetworkError::fromException(
                new \RuntimeException(sprintf(
                    'the grpc PECL extension is required (%s is a gRPC-only operation with no REST fallback)',
                    $operation,
                )),
                $operation . ' unavailable',
            );
        }
    }

    /**
     * §9 refresh-and-retry-once, shared by {@see self::validateToken()} and
     * {@see self::introspectToken()} — the same shape as
     * {@see self::getUserInfoWithRefreshRetry()}, generalised over the return type. An
     * {@see AuthError} — the taxonomy type {@see \Axiam\Sdk\Grpc\TokenGrpcClient} maps a
     * gRPC `UNAUTHENTICATED` to — drives the shared refresh (`$refreshAccessor`) exactly
     * once and re-runs `$rpc` exactly once. A second failure (or an absent
     * `$refreshAccessor`) propagates unchanged (§9.3).
     *
     * @template T
     *
     * @param callable(): T $rpc
     *
     * @return T
     */
    private function withRefreshRetry(callable $rpc): mixed
    {
        try {
            return $rpc();
        } catch (AuthError $e) {
            if ($this->refreshAccessor === null || !$this->canRefresh()) {
                throw $e;
            }
            ($this->refreshAccessor)();

            return $rpc();
        }
    }

    /**
     * Lazily constructs the token gRPC client the FIRST time
     * {@see self::validateToken()}/{@see self::introspectToken()} actually needs it
     * (`??=`) — the exact sibling of {@see self::userInfoClient()}, referenced ONLY from
     * inside those methods' `extension_loaded('grpc')` guard (Pitfall 4 / T-22-16).
     * Reuses the SAME target/tenant/token/TLS configuration as the other channels
     * (§1.1.1 rule 1 — "the SDK's existing channel", not a second one).
     */
    private function tokenClient(): \Axiam\Sdk\Grpc\TokenGrpcClient
    {
        return $this->tokenClient ??= new \Axiam\Sdk\Grpc\TokenGrpcClient(
            $this->grpcTarget ?? throw new \Axiam\Sdk\Core\AxiamException(
                'AuthzDispatcher: grpcTarget must be configured to use the gRPC transport',
            ),
            $this->tokenAccessor ?? static fn (): ?string => null,
            $this->tenantId ?? throw new \Axiam\Sdk\Core\AxiamException(
                'AuthzDispatcher: tenantId must be configured to use the gRPC transport',
            ),
            $this->customCaPem,
            $this->clientCertPem,
            $this->clientKey,
        );
    }

    /**
     * Lazily constructs the gRPC client the FIRST time a guarded branch above actually
     * needs it (`??=`) — never called from anywhere else in this class, and this class
     * is the only caller in the whole SDK (Pitfall 4 / T-22-16).
     */
    private function grpcClient(): \Axiam\Sdk\Grpc\AuthzGrpcClient
    {
        return $this->grpcClient ??= new \Axiam\Sdk\Grpc\AuthzGrpcClient(
            $this->grpcTarget ?? throw new \Axiam\Sdk\Core\AxiamException(
                'AuthzDispatcher: grpcTarget must be configured to use the gRPC transport',
            ),
            $this->tokenAccessor ?? static fn (): ?string => null,
            $this->tenantId ?? throw new \Axiam\Sdk\Core\AxiamException(
                'AuthzDispatcher: tenantId must be configured to use the gRPC transport',
            ),
            $this->customCaPem,
            $this->clientCertPem,
            $this->clientKey,
        );
    }

    /**
     * Lazily constructs the userinfo gRPC client the FIRST time {@see self::getUserInfo()}
     * actually needs it (`??=`) — the exact sibling of {@see self::grpcClient()}, referenced
     * ONLY from inside {@see self::getUserInfo()}'s `extension_loaded('grpc')` guard (Pitfall
     * 4 / T-22-16). Reuses the SAME target/tenant/token/TLS configuration as the authz
     * channel (§1.1.1 — "the same gRPC channel the SDK already builds", not a second one).
     */
    private function userInfoClient(): \Axiam\Sdk\Grpc\UserInfoGrpcClient
    {
        return $this->userInfoClient ??= new \Axiam\Sdk\Grpc\UserInfoGrpcClient(
            $this->grpcTarget ?? throw new \Axiam\Sdk\Core\AxiamException(
                'AuthzDispatcher: grpcTarget must be configured to use the gRPC transport',
            ),
            $this->tokenAccessor ?? static fn (): ?string => null,
            $this->tenantId ?? throw new \Axiam\Sdk\Core\AxiamException(
                'AuthzDispatcher: tenantId must be configured to use the gRPC transport',
            ),
            $this->customCaPem,
            $this->clientCertPem,
            $this->clientKey,
        );
    }

    private function currentSubjectId(): string
    {
        return $this->subjectIdAccessor !== null ? (string) ($this->subjectIdAccessor)() : '';
    }
}
