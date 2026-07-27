<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

use Psr\Http\Message\ResponseInterface;

/**
 * Central status→error mapper (CONTRACT.md §2, D-10). {@see self::fromStatus()} is the
 * single translation point from an HTTP status code to a typed {@see AxiamException}
 * subtype — no other class in the SDK is permitted to hand-roll this branching:
 * 401 → {@see AuthError}; 403/409 → {@see AuthzError}; everything else
 * (400/408/429/5xx/transport) → {@see NetworkError}.
 */
final class ErrorMapper
{
    /**
     * The single translation point. When a live PSR-7 `$response` is available, pass
     * it so a resulting {@see NetworkError} can build its redacted header summary via
     * {@see NetworkError::fromResponse()}; otherwise a status-only {@see NetworkError}
     * is built via {@see NetworkError::fromException()}.
     */
    public static function fromStatus(
        int $status,
        ?ResponseInterface $response = null,
        string $context = 'AXIAM API error',
    ): AxiamException {
        return match (true) {
            $status === 401 => new AuthError(sprintf('%s: unauthenticated (HTTP 401)', $context)),
            \in_array($status, [403, 409], true) => self::authzErrorFrom($response, sprintf('%s: forbidden (HTTP %d)', $context, $status)),
            $response !== null => NetworkError::fromResponse($response, $context),
            default => NetworkError::fromException(new \RuntimeException(sprintf('HTTP %d', $status)), $context),
        };
    }

    /**
     * Builds an {@see AuthzError} from the (already-consumed-safe) `$message`, parsing
     * `action`/`resource_id` out of the server's `authorization_denied` JSON body when a
     * live `$response` is available. Both fields are `null` when the body is missing,
     * unparsable, or simply doesn't carry them — a malformed/absent body never prevents
     * the AuthzError from being constructed.
     */
    private static function authzErrorFrom(?ResponseInterface $response, string $message): AuthzError
    {
        if ($response === null) {
            return new AuthzError($message);
        }

        $decoded = json_decode((string) $response->getBody(), true);
        if (!\is_array($decoded)) {
            return new AuthzError($message);
        }

        $action = $decoded['action'] ?? null;
        $resourceId = $decoded['resource_id'] ?? null;

        return new AuthzError(
            $message,
            \is_string($action) ? $action : null,
            \is_string($resourceId) ? $resourceId : null,
        );
    }

    /**
     * Convenience wrapper for callers that already hold a live PSR-7 response —
     * delegates to {@see self::fromStatus()}, the single translation point.
     */
    public static function fromResponse(ResponseInterface $response, string $context = 'AXIAM API error'): AxiamException
    {
        return self::fromStatus($response->getStatusCode(), $response, $context);
    }

    /**
     * The `/oauth2/*` translation point (CONTRACT.md §12.3 rule 3): a `400` from
     * `POST /oauth2/token`, or a `401` from `POST /oauth2/introspect` /
     * `POST /oauth2/revoke`, carrying an `OAuth2ErrorResponse` body (`{error,
     * error_description}`) MUST surface as {@see OAuthProtocolError} rather than the
     * generic {@see self::fromStatus()} mapping (which would otherwise collapse a `400`
     * into a plain {@see NetworkError}, or a `401` into a plain {@see AuthError} that
     * would wrongly enter the §9 single-flight refresh guard, §12.3 rule 3).
     *
     * Falls back to {@see self::fromStatus()} when the body does not look like an
     * `OAuth2ErrorResponse` (missing/non-string `error`), so a genuinely malformed or
     * unexpected error body from an `/oauth2/*` endpoint still gets a sensible mapping
     * instead of a confusing `OAuthProtocolError` with an empty `error` field.
     */
    public static function fromOAuth2Response(ResponseInterface $response, string $context = 'oauth2 request failed'): AxiamException
    {
        $decoded = json_decode((string) $response->getBody(), true);
        if (is_array($decoded) && is_string($decoded['error'] ?? null) && $decoded['error'] !== '') {
            $description = $decoded['error_description'] ?? null;

            return new OAuthProtocolError($decoded['error'], is_string($description) ? $description : '');
        }

        return self::fromStatus($response->getStatusCode(), $response, $context);
    }
}
