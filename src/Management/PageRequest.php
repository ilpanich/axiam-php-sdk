<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management;

/**
 * One page's worth of `?offset=`/`?limit=` for a paginated §27 list call
 * (CONTRACT.md §27.4 rule 4).
 *
 * A value object rather than two loose ints so a caller cannot transpose them at a call
 * site — `new PageRequest(limit: 50)` reads what it means, `list(50, 0)` does not.
 */
final class PageRequest
{
    /** The server's own default page size when a call names no limit. */
    public const DEFAULT_LIMIT = 50;

    /**
     * @param int $offset How many items to skip; clamped at 0.
     * @param int $limit  How many items to ask for; clamped to at least 1.
     */
    public function __construct(
        public readonly int $offset = 0,
        public readonly int $limit = self::DEFAULT_LIMIT,
    ) {
    }

    /**
     * The page after this one — same size, advanced by exactly this page's `limit`.
     *
     * Advancing by `limit` rather than by the number of items actually returned is
     * deliberate: a short page is not proof of the end (§27.4 rule 4 says auto-paging
     * stops on an EMPTY page, not a short one), and advancing by a short count would
     * re-request items the caller has already seen.
     */
    public function next(): self
    {
        return new self($this->offset + $this->limit, $this->limit);
    }

    /**
     * The `?offset=`/`?limit=` pair as query parameters.
     *
     * @return array<string,int>
     */
    public function toQuery(): array
    {
        return ['offset' => max(0, $this->offset), 'limit' => max(1, $this->limit)];
    }
}
