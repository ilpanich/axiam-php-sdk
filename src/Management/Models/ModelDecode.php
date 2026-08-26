<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Models;

use Axiam\Sdk\Core\NetworkError;

/**
 * Reads a REQUIRED field out of a decoded response body.
 *
 * Hand-written rather than generated, and used by all 145 generated models.
 *
 * Without it, a server response missing a field `openapi.json` declares required fails
 * as PHP's own `Undefined array key` warning and then, in production where warnings are
 * not exceptions, as a `TypeError` several frames inside a constructor — neither of which
 * names the field, the model, or the fact that the SERVER sent something unexpected. An
 * operator reading that has no way to tell a truncated response from an SDK bug.
 *
 * This turns the whole class into one {@see NetworkError} that says which model wanted
 * which field, which is both accurate (a short body IS a transport-level problem) and
 * actionable.
 */
final class ModelDecode
{
    /**
     * Returns `$data[$key]`, or throws naming the model that needed it.
     *
     * @param array<string,mixed> $data  The decoded response body.
     * @param string              $key   The wire field name.
     * @param string              $model The model being decoded, for the message.
     * @throws NetworkError when the field is absent.
     */
    public static function need(array $data, string $key, string $model): mixed
    {
        if (!array_key_exists($key, $data)) {
            throw NetworkError::fromMessage(sprintf(
                'the server\'s response is missing "%s", which %s requires — the response '
                . 'may be truncated, or the server may be older than this SDK',
                $key,
                $model,
            ));
        }

        return $data[$key];
    }
}
