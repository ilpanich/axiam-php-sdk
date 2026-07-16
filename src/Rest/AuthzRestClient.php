<?php

declare(strict_types=1);

namespace Axiam\Sdk\Rest;

use Axiam\Sdk\Core\ErrorMapper;
use GuzzleHttp\Client;
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
    public function __construct(private readonly Client $http)
    {
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
        return $this->decodeAllowed($this->postCheck($action, $resourceId, $scope, $subjectId));
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
        $body = [
            'checks' => array_map(
                static fn (array $check): array => array_filter(
                    [
                        'action' => $check['action'],
                        'resource_id' => $check['resourceId'],
                        'scope' => $check['scope'] ?? null,
                    ],
                    static fn (mixed $value): bool => $value !== null,
                ),
                $checks,
            ),
        ];

        try {
            $response = $this->http->post('/api/v1/authz/check/batch', ['json' => $body]);
        } catch (RequestException $e) {
            throw $this->mapException($e);
        } catch (GuzzleException $e) {
            throw \Axiam\Sdk\Core\NetworkError::fromException($e, 'authz batchCheck request failed');
        }

        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw ErrorMapper::fromResponse($response, 'authz batchCheck failed');
        }

        $decoded = json_decode((string) $response->getBody(), true);
        if (!is_array($decoded) || !isset($decoded['results']) || !is_array($decoded['results'])) {
            throw \Axiam\Sdk\Core\NetworkError::fromResponse($response, 'authz batchCheck: malformed response body');
        }

        return array_map(
            static fn (mixed $result): bool => is_array($result) && ($result['allowed'] ?? false) === true,
            $decoded['results'],
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
            $response = $this->http->post('/api/v1/authz/check', ['json' => $body]);
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

    private function decodeAllowed(\Psr\Http\Message\ResponseInterface $response): bool
    {
        $decoded = json_decode((string) $response->getBody(), true);
        if (!is_array($decoded)) {
            throw \Axiam\Sdk\Core\NetworkError::fromResponse($response, 'authz checkAccess: malformed response body');
        }

        return ($decoded['allowed'] ?? false) === true;
    }

    private function mapException(RequestException $e): \Axiam\Sdk\Core\AxiamException
    {
        $response = $e->getResponse();
        if ($response !== null) {
            return ErrorMapper::fromResponse($response, 'authz request failed');
        }

        return \Axiam\Sdk\Core\NetworkError::fromException($e, 'authz request failed');
    }
}
