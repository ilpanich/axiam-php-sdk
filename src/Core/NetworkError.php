<?php

declare(strict_types=1);

namespace Axiam\Sdk\Core;

use Psr\Http\Message\ResponseInterface;

/**
 * Transport-level failure: connection refused, timeout, TLS error, DNS failure, or a
 * server-side 5xx (CONTRACT.md §2).
 *
 * Redact-before-wrap (D-10/D-11, CR-04 carry-forward): {@see self::fromResponse()} is
 * the ONLY construction path that accepts a live PSR-7 {@see ResponseInterface}, and it
 * strips the `Set-Cookie`/`Authorization`/`Cookie` header VALUES into a sanitized
 * summary string BEFORE the constructor ever runs. There is no public constructor and
 * no path that stores the raw `$response` object (or any wrapped exception that might
 * itself carry one) as this exception's message, cause, or any other property — this
 * structurally prevents the token-leak-via-error class of bug first found in the
 * TypeScript sibling SDK (Phase 17 CR-04, its `src/core/errorMapper.ts`
 * `sanitizeAxiosError`) and mirrored by every later sibling SDK's `NetworkError`.
 * Not `final`, so CONTRACT.md §27.4 rule 7 can classify `400`/`422` as
 * {@see \Axiam\Sdk\Management\ValidationError} inside this type — §2's own `400` row
 * already lands here, and the sub-type keeps that mapping. **The redact-before-wrap
 * invariant above is untouched by that**: the constructor a subclass can reach takes a
 * `string` and a `\Throwable`, never a {@see ResponseInterface}, so a subclass has no
 * more access to a live response than any other caller — {@see self::fromResponse()}
 * remains the only path from a response into this type.
 */
class NetworkError extends AxiamException
{
    /** @var list<string> lowercase header names whose VALUES are never echoed. */
    private const SENSITIVE_HEADERS = ['set-cookie', 'authorization', 'cookie'];

    /**
     * A server-supplied `Retry-After` hint in milliseconds (CONTRACT.md §16.1),
     * `null` when the response carried none.
     *
     * A parsed duration, never the raw header text, so the sanitization discipline
     * this class exists to enforce is untouched: a float cannot carry a token, a
     * URL, or anything else a header might. §16 honors it as a **floor** on the
     * backoff — the server is stating when it will be ready, so retrying sooner is
     * not permitted.
     */
    public ?float $retryAfterMs = null;

    /**
     * Builds the exception from an ALREADY-SANITIZED message. `protected` rather than
     * `private` so §27.4 rule 7's {@see \Axiam\Sdk\Management\ValidationError} can
     * extend this type; it accepts no {@see ResponseInterface}, so widening it does not
     * widen what a subclass can reach (see class doc).
     */
    protected function __construct(string $message, ?\Throwable $previous = null)
    {
        // $previous, when given, MUST already be sanitized by the caller (a fresh
        // \RuntimeException carrying only a redacted summary string) — never the raw
        // wrapped exception or response object, since either can carry a live PSR-7
        // response with the same sensitive headers (see class doc). This satisfies
        // CONTRACT.md §2's cause-chaining requirement (getPrevious() !== null) without
        // reintroducing the token-leak-via-cause class of bug the class doc describes.
        parent::__construct($message, previous: $previous);
    }

    /**
     * Builds a NetworkError from a live PSR-7 response. Header NAMES are preserved for
     * debuggability; VALUES of `Set-Cookie`/`Authorization`/`Cookie` are replaced with
     * `[SENSITIVE]` before the summary string is built. The `$response` argument itself
     * is never stored — only the resulting sanitized string survives past this method.
     */
    public static function fromResponse(ResponseInterface $response, string $context = 'HTTP error'): self
    {
        $sanitizedHeaders = [];
        foreach (array_keys($response->getHeaders()) as $name) {
            $value = \in_array(strtolower($name), self::SENSITIVE_HEADERS, true)
                ? '[SENSITIVE]'
                : $response->getHeaderLine($name);
            $sanitizedHeaders[] = $name . ': ' . $value;
        }

        $message = sprintf(
            '%s: HTTP %d — headers: [%s]',
            $context,
            $response->getStatusCode(),
            implode('; ', $sanitizedHeaders)
        );

        $error = new self($message);
        $error->retryAfterMs = self::parseRetryAfterMs($response);

        return $error;
    }

    /**
     * Reads `Retry-After` as milliseconds, `null` when absent or unusable.
     *
     * Both RFC 7231 forms are accepted: delta-seconds and an HTTP-date. The date
     * form is not hypothetical — CDNs and proxies commonly send it on `429`/`503`,
     * and treating it as unparseable would silently discard the server's own
     * statement about when it will be ready. A non-positive value collapses to
     * `null` rather than becoming a floor, since a negative minimum wait is
     * meaningless.
     */
    private static function parseRetryAfterMs(ResponseInterface $response): ?float
    {
        $header = trim($response->getHeaderLine('Retry-After'));
        if ($header === '') {
            return null;
        }

        if (ctype_digit($header)) {
            $seconds = (int) $header;

            return $seconds > 0 ? $seconds * 1000.0 : null;
        }

        $timestamp = strtotime($header);
        if ($timestamp === false) {
            return null;
        }

        $deltaMs = ($timestamp - time()) * 1000.0;

        return $deltaMs > 0 ? $deltaMs : null;
    }

    /**
     * Builds a NetworkError from a caught transport exception (socket/TLS/DNS/timeout
     * failure). The caught exception's own message is defensively regex-sanitized in
     * case a lower-level exception echoed a sensitive header verbatim; the exception
     * itself is never stored as a cause (see class doc).
     */
    public static function fromException(\Throwable $exception, string $context = 'Transport error'): self
    {
        $sanitizedSummary = sprintf('%s: %s', $exception::class, self::sanitizeMessage($exception->getMessage()));

        $message = sprintf('%s: %s', $context, $sanitizedSummary);

        // Chain a SANITIZED stand-in for the original exception as $previous, so
        // getPrevious() !== null (CONTRACT.md §2 MUST: "carry the underlying OS/
        // transport error as a cause"), without ever attaching the raw $exception
        // itself — it (or something it wraps) could carry a live PSR-7 response with
        // the same sensitive headers this class exists to redact (see class doc).
        return new self($message, new \RuntimeException($sanitizedSummary));
    }

    /**
     * Builds a `NetworkError` from a plain message with no live response or exception
     * to redact — e.g. a malformed/short response BODY already decoded into a plain
     * array by the caller, with no `ResponseInterface`/headers left to sanitize.
     * `$message` still passes through {@see self::sanitizeMessage()} as defense in
     * depth, matching {@see self::fromException()}'s own discipline.
     */
    public static function fromMessage(string $message): self
    {
        return new self(self::sanitizeMessage($message));
    }

    /**
     * Defense-in-depth: strips any `set-cookie`/`authorization`/`cookie`-shaped
     * fragment from an arbitrary string, in case a leaked header fragment reaches a
     * message via a path other than {@see self::fromResponse()}.
     */
    private static function sanitizeMessage(string $raw): string
    {
        return (string) preg_replace(
            '/(set-cookie|authorization|cookie)\s*:\s*[^\r\n]+/i',
            '$1: [SENSITIVE]',
            $raw
        );
    }
}
