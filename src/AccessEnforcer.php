<?php

declare(strict_types=1);

namespace Axiam\Sdk;

use Axiam\Sdk\Attributes\RequireAccess;
use Axiam\Sdk\Attributes\RequireRole;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\NetworkError;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * The single CONTRACT.md §11 ("Declarative Authorization Helpers") enforcement
 * implementation, shared by BOTH framework bridges
 * ({@see \Axiam\Sdk\Symfony\AxiamAccessAttributeListener} and
 * {@see \Axiam\Sdk\Laravel\AxiamAccessMiddleware}) so the `#[RequireAuth]` /
 * `#[RequireAccess]` / `#[RequireRole]` semantics can never drift between the two
 * integrations. Neither bridge re-implements resource resolution, subject propagation,
 * or the error-mapping table below — both call into this class exclusively.
 *
 * **Composition with the §10 guard (CONTRACT.md §11.2.1):** this class NEVER extracts
 * or verifies a token itself. It only ever reads the identity already injected by the
 * CONTRACT.md §10 guard (the `axiam_user` request attribute populated by
 * {@see \Axiam\Sdk\Laravel\AxiamMiddleware} / {@see \Axiam\Sdk\Symfony\AxiamAuthSubscriber}),
 * passed in by the caller as `$identity`. A `null` identity is always a 401.
 *
 * **Subject propagation (CONTRACT.md §11.2.2):** the authorization check is made for
 * the REQUEST's authenticated end user, never for the shared {@see AxiamClient}'s own
 * session (which, in a framework bridge, is typically a service account, or not
 * authenticated at all). {@see self::enforceAccess()} always passes
 * `subjectId: $identity['user_id']` to {@see AxiamClient::checkAccess()} — the additive
 * `$subjectId` parameter that method gained specifically so this class can do so
 * without checking the wrong identity's permissions.
 *
 * **Resource resolution (CONTRACT.md §11.2.3)**, in order of precedence:
 *   1. {@see RequireAccess::$resourceId} — a static UUID literal, when set;
 *   2. {@see RequireAccess::$resourceParam} — a route/path parameter name, looked up in
 *      the `$routeParams` map the caller supplies;
 *   3. the `$resolver` callback the caller supplies, consulted when the configured
 *      route parameter is absent from `$routeParams` (or when `resourceParam` itself is
 *      `null`, signaling "resolve some other way").
 * A missing or non-UUID-shaped resource value at every step is a 400 `invalid_request`
 * — never a silent allow, never an empty/nil-UUID fallback.
 *
 * **Error mapping (CONTRACT.md §11.2.5)**, identical JSON body shape
 * `{ "error": ..., "message": ... }` on every failure path:
 *   - no identity                              -> 401 `authentication_failed`
 *   - unresolvable resource id                  -> 400 `invalid_request`
 *   - `checkAccess` denies, or the server 403s  -> 403 `authorization_denied`
 *   - the calling client's OWN session 401s mid-check, or a transport-level
 *     {@see NetworkError} occurs                -> 503 `authz_unavailable` (fail
 *     closed: deny, never allow, on any transport/availability failure — an `AuthError`
 *     here reflects a problem with the shared client's own credentials, not a verdict
 *     about the end user, so it is treated the same as "the authz service could not be
 *     reached" rather than manufacturing a false "authenticate again" prompt for a
 *     request whose OWN identity was already verified by the §10 guard)
 *
 * **No decision caching (CONTRACT.md §11.2.6):** every {@see self::enforceAccess()}
 * call performs a fresh `checkAccess` round-trip; nothing here memoizes an allow/deny
 * outcome across requests.
 *
 * **Redaction (CONTRACT.md §11.2.8):** no method on this class ever logs or echoes a
 * token or credential value. A denied/errored check is logged at debug level only,
 * carrying just the `action` and resolved `resourceId` — never the identity's raw
 * claims or any bearer token.
 */
final class AccessEnforcer
{
    /** RFC 4122-shaped UUID (any version/variant) — matches every sibling SDK's own resource-id validation intent. */
    private const UUID_PATTERN = '/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/';

    private readonly LoggerInterface $logger;

    /**
     * @param AxiamClient          $client The shared client used for the actual
     *        `checkAccess` round-trip (REST by default, gRPC when the client is so
     *        configured — CONTRACT.md §11.2.7: no new transport code, the existing
     *        `checkAccess` surface is reused as-is).
     * @param LoggerInterface|null $logger Injectable logger (diagnostic-only: `action`
     *        + resolved `resourceId` on a deny/error, NEVER a token/credential value —
     *        CONTRACT.md §11.2.8). Defaults to a silent {@see NullLogger}.
     */
    public function __construct(
        private readonly AxiamClient $client,
        ?LoggerInterface $logger = null,
    ) {
        $this->logger = $logger ?? new NullLogger();
    }

    /**
     * `require_auth` (CONTRACT.md §11.1): the endpoint requires an authenticated AXIAM
     * identity — nothing more. Pure sugar over the CONTRACT.md §10 guard for a route
     * where that guard is applied per-endpoint rather than globally.
     *
     * @param array{user_id: string, tenant_id: string, roles: list<string>}|null $identity
     *        The identity the CONTRACT.md §10 guard already injected (the `axiam_user`
     *        request attribute), or `null` when no such identity is present
     *        (unauthenticated, or the §10 guard is not installed on this route).
     *
     * @return JsonResponse|null `null` when authenticated (caller proceeds); a 401
     *         `authentication_failed` {@see JsonResponse} otherwise.
     */
    public function enforceAuth(?array $identity): ?JsonResponse
    {
        if ($identity === null) {
            return $this->authenticationFailed();
        }

        return null;
    }

    /**
     * `require_role` (CONTRACT.md §11.1, MAY-level): a LOCAL check (no server
     * round-trip, CONTRACT.md §11.2.9) that the identity's already-verified `roles`
     * intersect with at least one of {@see RequireRole::$roles}. Requires an
     * authenticated identity first (a role check needs somewhere to read roles from),
     * so an unauthenticated caller still gets 401, not 403.
     *
     * Role names are tenant-defined; this check is intentionally coarse and is NOT a
     * substitute for {@see self::enforceAccess()}, which is the authoritative,
     * server-verified check (CONTRACT.md §11.2.9).
     *
     * @param array{user_id: string, tenant_id: string, roles: list<string>}|null $identity
     *        The identity the CONTRACT.md §10 guard already injected, or `null`.
     * @param RequireRole $attribute The `#[RequireRole(...)]` attribute instance
     *        carrying the acceptable role list.
     *
     * @return JsonResponse|null `null` when the identity holds at least one of the
     *         required roles (caller proceeds); a 401 `authentication_failed` or 403
     *         `authorization_denied` {@see JsonResponse} otherwise.
     */
    public function enforceRole(?array $identity, RequireRole $attribute): ?JsonResponse
    {
        $authFailure = $this->enforceAuth($identity);
        if ($authFailure !== null) {
            return $authFailure;
        }

        /** @var list<string> $identity — narrowed: enforceAuth() above returned null, so $identity is non-null here. */
        $roles = is_array($identity['roles'] ?? null) ? $identity['roles'] : [];
        if (array_intersect($attribute->roles, $roles) === []) {
            $this->logger->debug('axiam_sdk: require_role denied', ['required_roles' => $attribute->roles]);

            return $this->authorizationDenied(sprintf(
                'missing required role (one of: %s)',
                implode(', ', $attribute->roles),
            ));
        }

        return null;
    }

    /**
     * `require_access` (CONTRACT.md §11.1): the endpoint requires the authenticated
     * caller to pass an AXIAM authorization check for `$attribute->action` on a
     * resource resolved from the request. This is the ONE codepath both framework
     * bridges call for `#[RequireAccess]` enforcement — see this class's own docblock
     * for the full resource-resolution and error-mapping tables.
     *
     * @param array{user_id: string, tenant_id: string, roles: list<string>}|null $identity
     *        The identity the CONTRACT.md §10 guard already injected, or `null`.
     * @param RequireAccess        $attribute   The `#[RequireAccess(...)]` attribute instance.
     * @param array<string,mixed>  $routeParams The inbound request's route/path
     *        parameters (e.g. Symfony's `$request->attributes->get('_route_params')`
     *        or Laravel's `$route->parameters()`), consulted when
     *        {@see RequireAccess::$resourceParam} is set.
     * @param (callable(): (string|null))|null $resolver A language-idiomatic resolver
     *        callback (CONTRACT.md §11.2.3c) for resource identifiers that live
     *        somewhere other than a route parameter (a body field, a header, a
     *        composite lookup) — consulted only when the configured
     *        {@see RequireAccess::$resourceParam} is `null` or absent from
     *        `$routeParams`.
     *
     * @return JsonResponse|null `null` when the check is allowed (caller proceeds); a
     *         401/400/403/503 {@see JsonResponse} otherwise (see this class's docblock
     *         for the exact mapping).
     */
    public function enforceAccess(
        ?array $identity,
        RequireAccess $attribute,
        array $routeParams = [],
        ?callable $resolver = null,
    ): ?JsonResponse {
        $authFailure = $this->enforceAuth($identity);
        if ($authFailure !== null) {
            return $authFailure;
        }

        $resource = $this->resolveResource($attribute, $routeParams, $resolver);
        if ($resource instanceof JsonResponse) {
            return $resource;
        }

        /** @var array{user_id: string, tenant_id: string, roles: list<string>} $identity */
        $subjectId = $identity['user_id'];

        try {
            $allowed = $this->client->checkAccess($attribute->action, $resource, $attribute->scope, $subjectId);
        } catch (NetworkError) {
            // Fail closed (CONTRACT.md §11.2.5): a transport failure is NEVER a
            // silent allow, and is distinguished from a genuine deny so operators can
            // tell "couldn't decide" from "decided no".
            $this->logger->debug('axiam_sdk: require_access unavailable (network error)', [
                'action' => $attribute->action,
                'resource_id' => $resource,
            ]);

            return $this->authzUnavailable();
        } catch (AuthError) {
            // The SHARED client's own session failed to authenticate the outbound
            // check call — not a verdict about the request's end user (who was
            // already verified by the §10 guard before this method was ever called).
            // Fail closed exactly like a NetworkError, per this class's docblock.
            $this->logger->debug('axiam_sdk: require_access unavailable (client auth error)', [
                'action' => $attribute->action,
                'resource_id' => $resource,
            ]);

            return $this->authzUnavailable();
        } catch (AuthzError $e) {
            $this->logger->debug('axiam_sdk: require_access denied (server error)', [
                'action' => $attribute->action,
                'resource_id' => $resource,
            ]);

            return $this->authorizationDenied($e->getMessage());
        }

        if (!$allowed) {
            $this->logger->debug('axiam_sdk: require_access denied', [
                'action' => $attribute->action,
                'resource_id' => $resource,
            ]);

            return $this->authorizationDenied(sprintf('forbidden: cannot %s %s', $attribute->action, $resource));
        }

        return null;
    }

    /**
     * Resolves the target resource UUID per CONTRACT.md §11.2.3's precedence order.
     *
     * @param array<string,mixed> $routeParams
     * @param (callable(): (string|null))|null $resolver
     *
     * @return string|JsonResponse The resolved UUID, or a 400 `invalid_request`
     *         {@see JsonResponse} when no step yields a valid one.
     */
    private function resolveResource(RequireAccess $attribute, array $routeParams, ?callable $resolver): string|JsonResponse
    {
        if ($attribute->resourceId !== null) {
            return $this->uuidOrInvalid($attribute->resourceId, 'the RequireAccess resourceId literal');
        }

        if ($attribute->resourceParam !== null) {
            $value = $routeParams[$attribute->resourceParam] ?? null;
            if (is_string($value) && $value !== '') {
                return $this->uuidOrInvalid($value, sprintf("route parameter '%s'", $attribute->resourceParam));
            }

            if ($resolver === null) {
                return $this->invalidRequest(sprintf(
                    "route parameter '%s' is missing or empty, and no resolver was supplied",
                    $attribute->resourceParam,
                ));
            }
        }

        if ($resolver !== null) {
            $resolved = $resolver();

            return $this->uuidOrInvalid($resolved, 'the resource resolver callback');
        }

        return $this->invalidRequest(
            'no resource identifier could be resolved (resourceId, resourceParam, and resolver were all unavailable)',
        );
    }

    /** @return string|JsonResponse `$value` unchanged when it is a well-formed UUID; a 400 {@see JsonResponse} otherwise. */
    private function uuidOrInvalid(?string $value, string $source): string|JsonResponse
    {
        if (!is_string($value) || $value === '' || preg_match(self::UUID_PATTERN, $value) !== 1) {
            return $this->invalidRequest(sprintf('%s did not resolve to a valid UUID', $source));
        }

        return $value;
    }

    /** 401 `authentication_failed` (CONTRACT.md §11.2.5). */
    private function authenticationFailed(): JsonResponse
    {
        return new JsonResponse(
            ['error' => 'authentication_failed', 'message' => 'authentication required'],
            401,
        );
    }

    /** 403 `authorization_denied` (CONTRACT.md §11.2.5). */
    private function authorizationDenied(string $message): JsonResponse
    {
        return new JsonResponse(['error' => 'authorization_denied', 'message' => $message], 403);
    }

    /** 400 `invalid_request` (CONTRACT.md §11.2.3/§11.2.5). */
    private function invalidRequest(string $message): JsonResponse
    {
        return new JsonResponse(['error' => 'invalid_request', 'message' => $message], 400);
    }

    /** 503 `authz_unavailable`, fail-closed (CONTRACT.md §11.2.5). */
    private function authzUnavailable(): JsonResponse
    {
        return new JsonResponse(
            ['error' => 'authz_unavailable', 'message' => 'authorization service unavailable'],
            503,
        );
    }
}
