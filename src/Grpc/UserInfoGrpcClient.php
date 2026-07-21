<?php

declare(strict_types=1);

namespace Axiam\Sdk\Grpc;

use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Grpc\Gen\GetUserInfoRequest;
use Axiam\Sdk\Grpc\Gen\GetUserInfoResponse;

/**
 * gRPC userinfo transport (CONTRACT.md §1.1/§5/§6/§9, contract 1.3) — the low-latency
 * gRPC counterpart of the server's REST `GET /oauth2/userinfo` endpoint. This is the
 * hand-written service-client sibling of {@see AuthzGrpcClient}: it mirrors that class's
 * channel/metadata/status-mapping machinery exactly, differing only in the single RPC it
 * exposes (`GetUserInfo` instead of `CheckAccess`/`BatchCheckAccess`).
 *
 * PITFALL 4 / T-22-16 (`extension_loaded('grpc')` guard, high severity): this class
 * `extends \Grpc\BaseStub`, exactly like {@see AuthzGrpcClient}. PHP only resolves an
 * `extends` clause's target when THIS FILE is actually included/executed (which PSR-4
 * autoloading defers until something references `Axiam\Sdk\Grpc\UserInfoGrpcClient` by
 * name) — so merely having this class exist in the SDK never fatals a REST-only runtime.
 * The invariant this SDK MUST preserve is the same one AuthzGrpcClient documents:
 * **nothing outside {@see \Axiam\Sdk\AuthzDispatcher}'s `extension_loaded('grpc')`-guarded
 * branches may ever reference this class name** — {@see \Axiam\Sdk\AuthzDispatcher} is the
 * ONLY call site in this SDK, and it references this class exclusively inside that guard.
 *
 * No grpc_php_plugin was available to generate a `*ServiceClient` stub (buf CLI
 * unavailable — the PHP SDK deliberately does not use grpc_php_plugin; see the README's
 * "Regenerating the gRPC stubs" section), so this class hand-implements `GetUserInfo`
 * directly against `\Grpc\BaseStub::_simpleRequest()` — the exact same primitive
 * grpc_php_plugin's own generated service-client classes call internally — using the
 * committed message stubs in {@see \Axiam\Sdk\Grpc\Gen}.
 *
 * §1.1.4 (refresh): this class NEVER re-implements token refresh. `$tokenAccessor` is a
 * non-blocking closure that reads the CURRENT access token live (the exact same "read
 * live, never cache a second copy" discipline {@see \Axiam\Sdk\Session::accessToken()}
 * follows for REST). On an UNAUTHENTICATED gRPC status it surfaces {@see AuthError} and
 * lets the caller ({@see \Axiam\Sdk\AuthzDispatcher::getUserInfo()}) drive the §9
 * single-flight refresh and retry the RPC once — mirroring the REST 401 path exactly.
 *
 * §6/D-12: the channel is ALWAYS constructed via `\Grpc\ChannelCredentials::createSsl()`
 * (strict TLS, system trust roots) or, when `$customCaPem` is supplied, that same factory
 * with the custom CA bytes — the ONLY escape hatch (§6). There is no insecure-channel
 * construction path anywhere in this class.
 *
 * §6.1 (mTLS): when a client identity (`$clientCertPem` + `$clientKey`) is configured it is
 * passed to the SAME `createSsl(rootCerts, privateKey, certChain)` factory, so the channel
 * presents a client certificate for mutual TLS. This is strictly additive — it changes only
 * what the CLIENT presents, never how the server is verified (§6.1.2). The private key
 * arrives wrapped in {@see \Axiam\Sdk\Core\Sensitive} and is revealed only at the
 * `createSsl()` call site; it is never stored in plaintext, logged, or exposed.
 *
 * §5: `x-tenant-id` metadata is injected on EVERY RPC; `authorization` metadata is
 * injected whenever `$tokenAccessor` returns a non-empty token.
 */
final class UserInfoGrpcClient extends \Grpc\BaseStub
{
    /**
     * @param string $hostname gRPC target, e.g. "api.axiam.example:9443".
     * @param callable(): (string|null) $tokenAccessor Reads the CURRENT access token
     *        live (shares the Session single-flight refresh mechanism) — never caches a
     *        copy, never triggers a refresh itself.
     * @param string $tenantId Injected as the `x-tenant-id` metadata key on every RPC (§5).
     * @param string|null $customCaPem PEM-encoded custom CA bundle (§6's ONLY escape
     *        hatch); omit to use the system trust roots.
     * @param string|null $clientCertPem §6.1 (mTLS): PEM client-certificate chain this
     *        channel presents for mutual TLS; omit for bearer-token-only auth. Must be
     *        present together with `$clientKey`.
     * @param \Axiam\Sdk\Core\Sensitive|null $clientKey §6.1/§7 (mTLS): the matching private
     *        key, wrapped in {@see \Axiam\Sdk\Core\Sensitive} so it never leaks; revealed only
     *        to build the channel credentials, never retained in plaintext.
     * @param array<string, mixed> $options Additional `\Grpc\BaseStub` constructor
     *        options (e.g. a caller-supplied per-call deadline); `credentials` is always
     *        set by this constructor and cannot be overridden via `$options`.
     */
    public function __construct(
        string $hostname,
        private readonly mixed $tokenAccessor,
        private readonly string $tenantId,
        private readonly ?string $customCaPem = null,
        ?string $clientCertPem = null,
        ?\Axiam\Sdk\Core\Sensitive $clientKey = null,
        array $options = [],
    ) {
        // §6.1.4: the client identity (when configured) rides on the SAME strict-TLS
        // createSsl() factory used for server verification — presenting a client cert never
        // relaxes how the server is verified (§6.1.2). `$rootCerts = null` keeps the system
        // trust roots; a private key is revealed from Sensitive only here, at the point of use.
        $rootCerts = $this->customCaPem;
        $privateKey = $clientKey?->reveal();
        $credentials = \Grpc\ChannelCredentials::createSsl($rootCerts, $privateKey, $clientCertPem);

        parent::__construct($hostname, array_merge($options, [
            'credentials' => $credentials,
        ]));
    }

    /**
     * `GetUserInfo` (CONTRACT.md §1.1) — returns the authenticated caller's OIDC-style
     * identity claims. The request is empty; identity is derived entirely server-side from
     * the `authorization` bearer metadata this call carries (§1.1.1/§1.1.2). `sub`,
     * `tenant_id`, and `org_id` are always populated; `email`/`preferred_username` are gated
     * on the "email"/"profile" token scopes respectively.
     */
    public function getUserInfo(): GetUserInfoResponse
    {
        return $this->unary(
            '/axiam.v1.UserInfoService/GetUserInfo',
            new GetUserInfoRequest(),
            [GetUserInfoResponse::class, 'decode'],
        );
    }

    /**
     * Issues a unary RPC and unwraps its (response, status) pair, mapping a non-OK status to
     * the SDK's error taxonomy (§2).
     *
     * @template T of object
     *
     * @param string             $method      Fully-qualified RPC method path.
     * @param object             $argument    Request message.
     * @param callable(string): T $deserialize Decodes the response body into the message type
     *                                        this call returns — the parameter that binds `T`.
     *
     * @return T Decoded response message.
     */
    private function unary(string $method, object $argument, callable $deserialize): object
    {
        [$response, $status] = $this->_simpleRequest(
            $method,
            $argument,
            $deserialize,
            $this->metadata(),
        )->wait();

        if ($status->code !== \Grpc\STATUS_OK) {
            throw $this->mapStatus((int) $status->code, (string) ($status->details ?? 'gRPC call failed'));
        }

        return $response;
    }

    /**
     * §5: Authorization + x-tenant-id metadata on EVERY RPC.
     *
     * @return array<string, list<string>> gRPC metadata map (each header maps to a list of values).
     */
    private function metadata(): array
    {
        $metadata = ['x-tenant-id' => [$this->tenantId]];

        $token = ($this->tokenAccessor)();
        if (\is_string($token) && $token !== '') {
            $metadata['authorization'] = ['Bearer ' . $token];
        }

        return $metadata;
    }

    /** CONTRACT.md §2 gRPC status -> error-type mapping. */
    private function mapStatus(int $code, string $details): \Axiam\Sdk\Core\AxiamException
    {
        return match ($code) {
            \Grpc\STATUS_UNAUTHENTICATED => new AuthError(sprintf('userinfo gRPC call failed: unauthenticated — %s', $details)),
            \Grpc\STATUS_PERMISSION_DENIED => new AuthzError(sprintf('userinfo gRPC call failed: permission denied — %s', $details)),
            default => NetworkError::fromException(new \RuntimeException($details), 'userinfo gRPC call failed'),
        };
    }
}
