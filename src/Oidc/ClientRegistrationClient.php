<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\ErrorMapper;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\RetryPolicy;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Core\TelemetryDispatcher;
use Axiam\Sdk\Management\FieldError;
use Axiam\Sdk\Management\ValidationError;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Http\Message\ResponseInterface;

/**
 * The RFC 7592 client configuration engine (CONTRACT.md §28.12, contract 1.53) behind
 * {@see \Axiam\Sdk\AxiamClient::readClientRegistration()},
 * {@see \Axiam\Sdk\AxiamClient::updateClientRegistration()} and
 * {@see \Axiam\Sdk\AxiamClient::deleteClientRegistration()}. Internal: the three methods on
 * the client are the public surface.
 *
 * Four rules shape all three (§28.12.2):
 *
 * 1. **The URI is used verbatim, and only at the configured AXIAM.** A URI whose scheme,
 *    host or port differs from the client's base URL — or an `http` URI unless the base URL
 *    is itself `http` on a loopback host — is refused locally with a
 *    {@see ValidationError}, before any request. The token is a bearer: a helper that
 *    followed a URI to another origin would hand it to whoever wrote the URI.
 * 2. **The token travels in `Authorization: Bearer` only** — never in the query, never in a
 *    body.
 * 3. **It is not the SDK's session.** The requests go out on a transport built for them:
 *    no cookie jar, no {@see \Axiam\Sdk\Rest\AuthMiddleware} (so no session token, CSRF
 *    token or tenant header), no {@see \Axiam\Sdk\Rest\RefreshMiddleware} (so a `401` never
 *    reaches the §9 guard), and no redirect following.
 * 4. **Neither write is retried.** An update that reached the server and lost its response
 *    has already rotated the token; a delete whose `204` was lost would read `401` on a
 *    retry. Only the read follows §16 — and never on a `4xx` other than `408`/`429`.
 *
 * @internal
 */
final class ClientRegistrationClient
{
    /** The hosts `http` is tolerated on (§28.12.2 rule 1), lower-case, IPv6 unbracketed. */
    private const LOOPBACK_HOSTS = ['localhost', '127.0.0.1', '::1'];

    /**
     * @param ClientInterface     $http         A transport with no cookie jar, no session
     *                                          middleware and redirects off.
     * @param string              $baseUrl      The configured AXIAM base URL.
     * @param bool                $retryEnabled §16.1's switch, for the read.
     * @param TelemetryDispatcher $telemetry    §19, notified before a retry wait.
     */
    public function __construct(
        private readonly ClientInterface $http,
        private readonly string $baseUrl,
        private readonly bool $retryEnabled,
        private readonly TelemetryDispatcher $telemetry,
    ) {
    }

    /**
     * `GET registration_client_uri` (RFC 7592 §2.1). Retried per §16 on a transport
     * failure, `5xx`, `408` or `429`; never on another `4xx`.
     */
    public function read(string $uri, Sensitive $token): ClientRegistration
    {
        $this->checkUri($uri, 'read_client_registration');

        // The status of the last attempt, so the §16 predicate can tell a `5xx` from the
        // bodiless `400` §2 also maps to NetworkError — that one is an answer, not a fault.
        $lastStatus = null;
        $retryable = static function () use (&$lastStatus): bool {
            return $lastStatus === null || $lastStatus >= 500 || $lastStatus === 408 || $lastStatus === 429;
        };

        return RetryPolicy::execute(
            'read_client_registration',
            $this->retryEnabled,
            $this->telemetry,
            function () use ($uri, $token, &$lastStatus): ClientRegistration {
                $lastStatus = null;
                $response = $this->send('GET', $uri, $token, null, 'read_client_registration');
                $lastStatus = $response->getStatusCode();

                return self::decode($response, 'read_client_registration');
            },
            null,
            null,
            $retryable,
        );
    }

    /**
     * `PUT registration_client_uri` (RFC 7592 §2.2) — a full replacement, never retried.
     */
    public function update(string $uri, Sensitive $token, ClientRegistration $metadata): ClientRegistration
    {
        $this->checkUri($uri, 'update_client_registration');
        $response = $this->send('PUT', $uri, $token, $metadata->updateBody(), 'update_client_registration');

        return self::decode($response, 'update_client_registration');
    }

    /** `DELETE registration_client_uri` (RFC 7592 §2.3) — `204` is success; never retried. */
    public function delete(string $uri, Sensitive $token): void
    {
        $this->checkUri($uri, 'delete_client_registration');
        $response = $this->send('DELETE', $uri, $token, null, 'delete_client_registration');
        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw ErrorMapper::fromOAuth2Response($response, 'delete_client_registration failed');
        }
    }

    /**
     * §28.12.2 rule 1: refuse a URI that is not at the configured AXIAM origin.
     *
     * The refusal names no part of the URI: it is caller input, and an error message is the
     * thing most often logged.
     */
    private function checkUri(string $uri, string $operation): void
    {
        $refuse = static function (string $why) use ($operation): ValidationError {
            $message = sprintf('%s: registration_client_uri %s (CONTRACT.md §28.12.2 rule 1)', $operation, $why);

            return new ValidationError($message, [new FieldError('registration_client_uri', $why)]);
        };

        $target = self::origin($uri);
        if ($target === null) {
            throw $refuse('is not an absolute URL');
        }
        if ($target[0] !== 'https' && $target[0] !== 'http') {
            throw $refuse('must be an https URL');
        }
        $base = self::origin($this->baseUrl);
        if ($base === null || $target !== $base) {
            throw $refuse(
                'is not at the configured AXIAM origin (scheme, host and port must match the client\'s base URL)'
            );
        }
        if ($target[0] === 'http' && !in_array($base[1], self::LOOPBACK_HOSTS, true)) {
            throw $refuse('must be https unless the base URL is http on a loopback host');
        }
    }

    /**
     * `[scheme, host, port]` — lower-cased, IPv6 unbracketed, the scheme's default port
     * filled in — or `null` for anything that is not an absolute URL.
     *
     * @return array{0:string,1:string,2:int}|null
     */
    private static function origin(string $url): ?array
    {
        $parts = parse_url($url);
        if ($parts === false || !isset($parts['scheme'], $parts['host']) || $parts['host'] === '') {
            return null;
        }
        $scheme = strtolower($parts['scheme']);
        $host = strtolower(trim($parts['host'], '[]'));
        $port = $parts['port'] ?? match ($scheme) {
            'https' => 443,
            'http' => 80,
            default => 0,
        };

        return [$scheme, $host, $port];
    }

    /**
     * One request carrying the registration token as its bearer and nothing of the session.
     *
     * @param array<string,mixed>|null $body
     */
    private function send(string $method, string $uri, Sensitive $token, ?array $body, string $operation): ResponseInterface
    {
        $options = [
            'http_errors' => false,
            'allow_redirects' => false,
            'headers' => [
                'Authorization' => 'Bearer ' . $token->reveal(),
                'Accept' => 'application/json',
            ],
        ];
        if ($body !== null) {
            $options['json'] = $body;
        }

        try {
            return $this->http->request($method, $uri, $options);
        } catch (GuzzleException $e) {
            throw NetworkError::fromException($e, $operation . ' request failed');
        }
    }

    /** A `2xx` decodes to the registration; anything else is §28.12.3's mapping. */
    private static function decode(ResponseInterface $response, string $operation): ClientRegistration
    {
        $status = $response->getStatusCode();
        if ($status < 200 || $status >= 300) {
            throw ErrorMapper::fromOAuth2Response($response, $operation . ' failed');
        }
        $wire = json_decode((string) $response->getBody(), true);
        if (!is_array($wire)) {
            throw NetworkError::fromMessage($operation . ': the response is not a JSON object');
        }

        return ClientRegistration::fromArray($wire);
    }
}
