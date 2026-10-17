<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management;

use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Core\ErrorMapper;
use Psr\Http\Message\ResponseInterface;

/**
 * The §27 status→error mapper (CONTRACT.md §27.4 rule 7).
 *
 * Deliberately a *narrowing* of {@see ErrorMapper}, not a replacement: three statuses
 * get a §27 sub-type and everything else falls through to the §2 mapping unchanged, so
 * the management surface cannot drift from the rest of the SDK on `401`, `403` or `5xx`.
 *
 * The three it does claim, and why each parent is the one rule 7 names:
 *
 * | status     | type                    | parent        |
 * |------------|-------------------------|---------------|
 * | `404`      | {@see NotFoundError}    | `AuthzError`  |
 * | `409`      | {@see ConflictError}    | `AuthzError`  |
 * | `400`,`422`| {@see ValidationError}  | `NetworkError`|
 *
 * Two of them carry more than a status (contract 1.62, §36.3 rule 2 and §36.4). A `409` keeps
 * the body's `reason_code` — verbatim, an unknown value included — on {@see
 * ConflictError::getReasonCode()}; a caller branches on it, never on the message. A `403` stays
 * the plain §2 {@see \Axiam\Sdk\Core\AuthzError} (with `action` and `resource_id` where the
 * body has them), and both it and the `409` append the server's own `message` to their text, as
 * a `400` does — the write gate's value refusal (`session_timeout_secs is above the tenant's
 * cap of 3600`) names no permission, so the message is all the person has.
 *
 * `404` under `AuthzError` is the counter-intuitive one: on a multi-tenant surface the
 * server answers `404` for another tenant's object *so that* a caller cannot enumerate
 * it, and re-drawing that line client-side would undo the protection. `409` keeps the
 * parent §2 already gave it. `400`/`422` inherit §2's `400` row.
 */
final class ManagementErrorMapper
{
    /**
     * Maps one management response to its typed exception.
     *
     * @param ResponseInterface $response The error response; its body is a rewindable PSR-7 stream and is only ever read, never consumed.
     * @param string            $context  Operation name, prefixed onto the message.
     */
    public static function fromResponse(ResponseInterface $response, string $context): AxiamException
    {
        $status = $response->getStatusCode();

        if ($status === 404) {
            return new NotFoundError(sprintf('%s: not found (HTTP 404)', $context));
        }

        if ($status === 409) {
            $decoded = json_decode((string) $response->getBody(), true);
            $reasonCode = \is_array($decoded) && \is_string($decoded['reason_code'] ?? null) && $decoded['reason_code'] !== ''
                ? $decoded['reason_code']
                : null;

            return new ConflictError(
                self::withServerMessage(sprintf('%s: conflict (HTTP 409)', $context), $decoded),
                $reasonCode,
            );
        }

        if ($status === 400 || $status === 422) {
            $decoded = json_decode((string) $response->getBody(), true);
            $serverMessage = \is_array($decoded) && \is_string($decoded['message'] ?? null) && $decoded['message'] !== ''
                ? $decoded['message']
                : null;

            // The server's `message` names the field and the rule (CONTRACT.md §29.4, §30.4)
            // and, by the server's own rules, never echoes a secret, a URL or a certificate —
            // so it is carried, for the person reading the error. Never parsed.
            return new ValidationError(
                $serverMessage === null
                    ? sprintf('%s: invalid request (HTTP %d)', $context, $status)
                    : sprintf('%s: invalid request (HTTP %d): %s', $context, $status, $serverMessage),
                self::fieldErrors($decoded),
                $serverMessage,
            );
        }

        // Everything else — 401, 403, 5xx, transport — is §2's to classify.
        $error = ErrorMapper::fromStatus($status, $response, $context);

        // A 403 keeps §2's type and its `action` / `resource_id`; only the person-readable text
        // gains the server's own `message` (§27.6.2 item 5: "the outcome carries the server's
        // message"). It is never parsed.
        if ($status === 403 && $error instanceof AuthzError) {
            $message = self::withServerMessage($error->getMessage(), json_decode((string) $response->getBody(), true));
            if ($message !== $error->getMessage()) {
                return new AuthzError($message, $error->getAction(), $error->getResourceId());
            }
        }

        return $error;
    }

    /**
     * `$base` followed by the body's non-empty string `message`, when it has one.
     */
    private static function withServerMessage(string $base, mixed $decoded): string
    {
        $message = \is_array($decoded) && \is_string($decoded['message'] ?? null) ? $decoded['message'] : '';

        return $message === '' ? $base : $base . ': ' . $message;
    }

    /**
     * Pulls per-field complaints out of a validation body.
     *
     * Tolerant by design: a `400` whose body is empty, HTML, or shaped differently than
     * expected still produces a {@see ValidationError} — just one with no fields. A
     * malformed error body must never turn into a *different* error than the status says.
     *
     * @return list<FieldError>
     */
    private static function fieldErrors(mixed $decoded): array
    {
        if (!\is_array($decoded)) {
            return [];
        }

        $raw = $decoded['fields'] ?? $decoded['errors'] ?? null;
        if (!\is_array($raw)) {
            return [];
        }

        $fields = [];
        foreach ($raw as $key => $entry) {
            if (\is_array($entry)) {
                $name = $entry['field'] ?? $entry['name'] ?? (\is_string($key) ? $key : null);
                $message = $entry['message'] ?? $entry['detail'] ?? null;
                if (\is_string($name) && \is_string($message)) {
                    $fields[] = new FieldError($name, $message);
                }
            } elseif (\is_string($entry) && \is_string($key)) {
                $fields[] = new FieldError($key, $entry);
            }
        }

        return $fields;
    }
}
