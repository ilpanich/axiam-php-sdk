<?php

declare(strict_types=1);

namespace Axiam\Sdk\Reactor;

/**
 * One hookable event from the CONTRACT.md §22.5 registry: its wire name, what a
 * reply may change, and what happens when the reactor does not answer.
 *
 * Mirrors `ReactorEventSpec` in `crates/axiam-core/src/models/reactor.rs`, which
 * is the single source of truth §22.5 restates. The live copy is served at
 * `GET /api/v1/reactors/events` and is what an admin UI should read; this local
 * mirror exists because the delivery path validates an incoming event name and a
 * handler's patch keys with no network call available.
 */
final class ReactorEventSpec
{
    /**
     * @param string        $name                 Wire name, and the second half of the routing key.
     * @param bool          $interceptable        Whether an interceptor may register for this event
     *                                            at all. False means listen-only.
     * @param bool          $mutable              Whether an interceptor's reply may carry a patch.
     * @param list<string>  $mutableFields        The COMPLETE allow-list: exact field names, or a
     *                                            namespace prefix ending in `.` — see
     *                                            {@see self::patchFieldAllowed()}.
     * @param string        $defaultFailurePolicy What a registration naming no policy gets for this
     *                                            event, before §22.8's strictest-wins composition.
     * @param string        $description          The one-liner the admin surface shows.
     */
    public function __construct(
        public readonly string $name,
        public readonly bool $interceptable,
        public readonly bool $mutable,
        public readonly array $mutableFields,
        public readonly string $defaultFailurePolicy,
        public readonly string $description,
    ) {
    }

    /**
     * Whether `$field` may appear in a patch for this event (§22.5).
     *
     * An allow-list entry ending in `.` is a NAMESPACE PREFIX: it matches a field
     * that starts with the entry **and has at least one character after the dot**.
     * So `ext.` admits `ext.department` and `ext.a.b.c`, and refuses:
     *
     *  - `ext.` itself — it names the namespace, not a claim, and admitting it
     *    would let a reactor set a claim literally called `ext.`;
     *  - `ext` — not in the namespace;
     *  - `extra`, `external_id` — a prefix match on the *string* is not a match on
     *    the namespace;
     *  - `evil.ext.department` — not a suffix match either.
     *
     * Everything else follows from that one rule. `token.pre_issue` cannot reach
     * `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `scope`, `scp`, `azp`,
     * `act`, `client_id` or any other standard claim, because none of them begins
     * with `ext.`. A hook that can rewrite `sub` is a hook that can mint a token
     * for anyone, and no amount of correct signing changes that — a **correctly
     * signed** reply setting `sub` is refused exactly as a forged one is.
     *
     * Mirrors `ReactorEventSpec::patch_field_allowed` in
     * `crates/axiam-core/src/models/reactor.rs`.
     */
    public function patchFieldAllowed(string $field): bool
    {
        if (!$this->mutable) {
            return false;
        }

        foreach ($this->mutableFields as $allowed) {
            if (str_ends_with($allowed, '.')) {
                // Namespace prefix: at least one character must follow the dot.
                if (strlen($field) > strlen($allowed) && str_starts_with($field, $allowed)) {
                    return true;
                }
                continue;
            }
            if ($field === $allowed) {
                return true;
            }
        }

        return false;
    }
}
