<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management;

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
     * @param ResponseInterface $response The error response; its body is read at most once.
     * @param string            $context  Operation name, prefixed onto the message.
     */
    public static function fromResponse(ResponseInterface $response, string $context): AxiamException
    {
        $status = $response->getStatusCode();

        if ($status === 404) {
            return new NotFoundError(sprintf('%s: not found (HTTP 404)', $context));
        }

        if ($status === 409) {
            return new ConflictError(sprintf('%s: conflict (HTTP 409)', $context));
        }

        if ($status === 400 || $status === 422) {
            return new ValidationError(
                sprintf('%s: invalid request (HTTP %d)', $context, $status),
                self::fieldErrors($response),
            );
        }

        // Everything else — 401, 403, 5xx, transport — is §2's to classify.
        return ErrorMapper::fromStatus($status, $response, $context);
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
    private static function fieldErrors(ResponseInterface $response): array
    {
        $decoded = json_decode((string) $response->getBody(), true);
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
