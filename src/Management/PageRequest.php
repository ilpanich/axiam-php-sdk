<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management;

/**
 * One page's worth of `?offset=`/`?limit=`/`?search=` for a paginated §27 list call
 * (CONTRACT.md §27.4 rule 4).
 *
 * A value object rather than three loose arguments so a caller cannot transpose them at a
 * call site — `new PageRequest(limit: 50)` reads what it means, `list(50, 0)` does not.
 */
final class PageRequest
{
    /** The server's own default page size when a call names no limit. */
    public const DEFAULT_LIMIT = 50;

    /**
     * @param int         $offset How many items to skip; clamped at 0.
     * @param int         $limit  How many items to ask for; clamped to at least 1.
     * @param string|null $search A free-text filter applied by the SERVER, before
     *                            `offset`/`limit` — see {@see self::$search}.
     */
    public function __construct(
        public readonly int $offset = 0,
        public readonly int $limit = self::DEFAULT_LIMIT,
        public readonly ?string $search = null,
    ) {
    }

    /**
     * The page after this one — same size and same term, advanced by exactly this page's
     * `limit`.
     *
     * Advancing by `limit` rather than by the number of items actually returned is
     * deliberate: a short page is not proof of the end (§27.4 rule 4 says auto-paging
     * stops on an EMPTY page, not a short one), and advancing by a short count would
     * re-request items the caller has already seen.
     *
     * Carrying `$search` forward is what makes {@see ManagementTransport::walk()} filter
     * the WHOLE walk rather than only its first request. A walk that dropped the term on
     * page two would return the matches followed by the unfiltered tail, which reads as a
     * server bug from the caller's side (§27.4 rule 4).
     */
    public function next(): self
    {
        return new self($this->offset + $this->limit, $this->limit, $this->search);
    }

    /**
     * This request with `$search` replaced — a COPY, so a shared request cannot be
     * repointed at a different query by unrelated code.
     */
    public function matching(?string $search): self
    {
        return new self($this->offset, $this->limit, $search);
    }

    /**
     * The `?offset=`/`?limit=`/`?search=` triple as query parameters.
     *
     * `search` is present only when there is a term to send. §27.4 rule 4 makes absent
     * and blank the SAME request: a search box that fires on every keystroke sends one
     * the moment it is cleared, and "rows containing the empty string" is a different
     * question from "all rows".
     *
     * @return array<string,int|string>
     */
    public function toQuery(): array
    {
        $query = ['offset' => max(0, $this->offset), 'limit' => max(1, $this->limit)];
        $term = self::normalizeSearch($this->search);
        if ($term !== null) {
            $query['search'] = $term;
        }

        return $query;
    }

    /**
     * The term as it goes on the wire, or `null` when there is nothing to send.
     *
     * Trims, then treats a blank result as absent — the same normalisation the server
     * applies. The server's LENGTH cap is deliberately not re-implemented here: a
     * client-side truncation the server would not have made is a silently different
     * query, and the caller would have no way to tell (§27.4 rule 4).
     */
    public static function normalizeSearch(?string $search): ?string
    {
        if ($search === null) {
            return null;
        }
        $trimmed = trim($search);

        return $trimmed === '' ? null : $trimmed;
    }
}
