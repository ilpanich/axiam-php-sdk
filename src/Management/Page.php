<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management;

/**
 * One page of a paginated §27 list response (CONTRACT.md §27.4 rule 4).
 *
 * `$total` is the server's count of everything matching the query, NOT
 * `count($this->items)`. Confusing the two is the single most common way a management
 * client silently processes only the first fifty of four hundred objects, so this class
 * keeps them as separate, separately-named properties and never derives one from the
 * other.
 *
 * A bare JSON array response is NOT a page and is never modelled as one (§27.4 rule 4);
 * the generated surface returns those as a plain `list<T>`.
 *
 * @template T
 * @implements \IteratorAggregate<int,T>
 */
final class Page implements \IteratorAggregate, \Countable
{
    /**
     * @param list<T>      $items The items on THIS page.
     * @param int          $total The server's total across all pages.
     * @param PageRequest  $request The request that produced this page, so
     *                              {@see self::nextRequest()} can continue from it.
     */
    public function __construct(
        public readonly array $items,
        public readonly int $total,
        public readonly PageRequest $request,
    ) {
    }

    /**
     * The items on this page — iterate the page directly and you get these.
     *
     * @return \ArrayIterator<int,T>
     */
    public function getIterator(): \ArrayIterator
    {
        return new \ArrayIterator($this->items);
    }

    /**
     * How many items are on THIS page. Deliberately not `$total`: `count($page)` must
     * agree with what iterating the page yields, or the two disagree silently.
     */
    public function count(): int
    {
        return \count($this->items);
    }

    /**
     * True when this page carried nothing. §27.4 rule 4 makes THIS, not a short page,
     * the auto-paging stop condition.
     */
    public function isEmpty(): bool
    {
        return $this->items === [];
    }

    /**
     * The request that would fetch the page after this one.
     *
     * Carries this page's `search` term forward with it (§27.4 rule 4) — that is
     * {@see PageRequest::next()}'s job, not this one's, so every walk built on
     * `nextRequest()` filters the whole walk rather than only its first request.
     */
    public function nextRequest(): PageRequest
    {
        return $this->request->next();
    }
}
