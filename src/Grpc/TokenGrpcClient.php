<?php

declare(strict_types=1);

namespace Axiam\Sdk\Grpc;

use Axiam\Sdk\Auth\TokenIntrospection;
use Axiam\Sdk\Auth\TokenValidation;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Grpc\Gen\IntrospectTokenRequest;
use Axiam\Sdk\Grpc\Gen\IntrospectTokenResponse;
use Axiam\Sdk\Grpc\Gen\ValidateTokenRequest;
use Axiam\Sdk\Grpc\Gen\ValidateTokenResponse;

/**
 * gRPC token-validation transport (CONTRACT.md §1.1.1/§10.3, contract 1.51) — wraps
 * `axiam.v1.TokenService/ValidateToken` and `/IntrospectToken`, the RPCs §10.3 obliges a
 * gRPC-validating SDK to read `cnf` from and no method in this SDK's public surface
 * wrapped before 1.51.
 *
 * The hand-written service-client sibling of {@see AuthzGrpcClient} and
 * {@see UserInfoGrpcClient}: same channel/metadata/status-mapping machinery, differing
 * only in the two RPCs it exposes.
 *
 * PITFALL 4 / T-22-16 (`extension_loaded('grpc')` guard, high severity): this class
 * `extends \Grpc\BaseStub`, exactly like its two siblings. The invariant is the same one
 * they document: **nothing outside {@see \Axiam\Sdk\AuthzDispatcher}'s
 * `extension_loaded('grpc')`-guarded branches may ever reference this class name** —
 * {@see \Axiam\Sdk\AuthzDispatcher} is the only call site.
 *
 * **Two tokens, kept apart (§1.1.1 rule 1).** Every call here carries TWO credentials.
 * The CALLER's own access token authenticates the RPC itself, exactly as for every other
 * call this SDK makes — it travels in `authorization` metadata via `$tokenAccessor`,
 * enforced by the server's interceptor like any other, including its own `cnf`. The
 * INSPECTED token — the one being asked about — is a required {@see Sensitive} argument
 * and travels in the request MESSAGE. It has no default and can never fall back to the
 * caller's own token.
 */
final class TokenGrpcClient extends \Grpc\BaseStub
{
    /**
     * @param string                     $hostname     gRPC target, e.g. "api.axiam.example:9443".
     * @param callable(): (string|null) $tokenAccessor Reads the CALLER'S current access
     *        token live — never the inspected token, which is a separate parameter on
     *        each call below.
     * @param string                     $tenantId     Injected as the `x-tenant-id`
     *        metadata key on every RPC (§5).
     * @param string|null                $customCaPem  PEM-encoded custom CA bundle
     *        (§6's ONLY escape hatch); omit to use the system trust roots.
     * @param string|null                $clientCertPem §6.1 (mTLS): PEM client-certificate
     *        chain this channel presents for mutual TLS; omit for bearer-token-only auth.
     * @param Sensitive|null             $clientKey    §6.1/§7 (mTLS): the matching
     *        private key.
     * @param array<string, mixed>       $options      Additional `\Grpc\BaseStub`
     *        constructor options; `credentials` is always set by this constructor.
     */
    public function __construct(
        string $hostname,
        private readonly mixed $tokenAccessor,
        private readonly string $tenantId,
        private readonly ?string $customCaPem = null,
        ?string $clientCertPem = null,
        ?Sensitive $clientKey = null,
        array $options = [],
    ) {
        $rootCerts = $this->customCaPem;
        $privateKey = $clientKey?->reveal();
        $credentials = \Grpc\ChannelCredentials::createSsl($rootCerts, $privateKey, $clientCertPem);

        parent::__construct($hostname, array_merge($options, [
            'credentials' => $credentials,
        ]));
    }

    /**
     * `ValidateToken` (CONTRACT.md §1.1.1) — signature + expiry, plus the confirmation
     * §10.3 exists for.
     *
     * @param Sensitive|string $inspectedAccessToken The token being asked about. Secret
     *        material (§1.1.1 rule 2) — hold it behind {@see Sensitive} where the caller
     *        can.
     */
    public function validateToken(Sensitive|string $inspectedAccessToken): TokenValidation
    {
        $request = new ValidateTokenRequest();
        $request->setAccessToken(self::reveal($inspectedAccessToken));

        return TokenValidation::fromWire($this->unary(
            '/axiam.v1.TokenService/ValidateToken',
            $request,
            self::decoder(ValidateTokenResponse::class),
        ));
    }

    /**
     * `IntrospectToken` (CONTRACT.md §1.1.1) — the RFC 7662 set, plus the confirmation.
     *
     * @param Sensitive|string $inspectedAccessToken The token being asked about. Secret
     *        material (§1.1.1 rule 2).
     */
    public function introspectToken(Sensitive|string $inspectedAccessToken): TokenIntrospection
    {
        $request = new IntrospectTokenRequest();
        $request->setAccessToken(self::reveal($inspectedAccessToken));

        return TokenIntrospection::fromWire($this->unary(
            '/axiam.v1.TokenService/IntrospectToken',
            $request,
            self::decoder(IntrospectTokenResponse::class),
        ));
    }

    private static function reveal(Sensitive|string $value): string
    {
        return $value instanceof Sensitive ? $value->reveal() : $value;
    }

    /**
     * Builds a `(string): T` deserializer for the committed {@see \Axiam\Sdk\Grpc\Gen}
     * message stubs — the same fix documented on
     * {@see AuthzGrpcClient::decoder()}/{@see UserInfoGrpcClient::decoder()}
     * (`[$class, 'decode']` is not a valid `callable` here).
     *
     * @template T of object
     *
     * @param class-string<T> $class
     *
     * @return callable(string): T
     */
    private static function decoder(string $class): callable
    {
        return static function (string $data) use ($class): object {
            $message = new $class();
            $message->mergeFromString($data);

            return $message;
        };
    }

    /**
     * Issues a unary RPC and unwraps its (response, status) pair, mapping a non-OK
     * status to the SDK's error taxonomy (§2).
     *
     * @template T of object
     *
     * @param string               $method      Fully-qualified RPC method path.
     * @param object               $argument    Request message.
     * @param callable(string): T $deserialize Decodes the response body into T.
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
     * §5: `authorization` (CALLER'S token, §1.1.1 rule 1) + `x-tenant-id` metadata on
     * EVERY RPC.
     *
     * @return array<string, list<string>>
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
            \Grpc\STATUS_UNAUTHENTICATED => new AuthError(sprintf('token gRPC call failed: unauthenticated — %s', $details)),
            \Grpc\STATUS_PERMISSION_DENIED => new AuthzError(sprintf('token gRPC call failed: permission denied — %s', $details)),
            default => NetworkError::fromException(new \RuntimeException($details), 'token gRPC call failed'),
        };
    }
}
