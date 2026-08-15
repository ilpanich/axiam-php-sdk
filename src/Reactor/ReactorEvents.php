<?php

declare(strict_types=1);

namespace Axiam\Sdk\Reactor;

/**
 * The CONTRACT.md §22.5 event registry, §22.8's budget constants and §22.1's
 * topology helpers.
 *
 * The registry is served live at `GET /api/v1/reactors/events`, and that is the
 * copy an admin UI SHOULD read. This class restates it because a reactor runtime
 * has to validate an incoming event name and a handler's patch keys on the
 * delivery path, where a network call is not available — the same reason the
 * contract restates it in prose and the server keeps it as pure data in
 * `crates/axiam-core/src/models/reactor.rs`.
 *
 * WHAT IS DELIBERATELY ABSENT IS LOAD-BEARING. The three hot-path decision
 * operations — the single authorization check, the batch check and token
 * introspection — are **not hookable** (§22.7, a MUST NOT), so they appear in no
 * constant, no list and no example anywhere under `src/Reactor/`. Their wire
 * names are not written here either, so `ReactorHotPathExclusionTest` can enforce
 * the rule with a plain scan of this directory rather than a judgement call about
 * which mentions are innocent.
 *
 * The reason is arithmetic, not policy: a reactor round-trip is milliseconds and
 * the check path's budget is microseconds. An application that needs external
 * input on an authorization decision writes a **deny grant**, which the engine
 * evaluates in the hot path at hot-path cost.
 */
final class ReactorEvents
{
    /**
     * Fires before an access token is issued. Mutable: claims under the `ext.`
     * namespace only.
     */
    public const TOKEN_PRE_ISSUE = 'token.pre_issue';

    /**
     * Fires after credentials verify and before any session or token is issued —
     * on password login, on SAML ACS and on the OIDC callback alike (§22.5,
     * SEC-095). Veto-only, and the only event on which `require_mfa` is
     * meaningful.
     */
    public const LOGIN_POST_AUTH = 'login.post_auth';

    /** Fires before a user is created. */
    public const USER_PRE_CREATE = 'user.pre_create';

    /** Fires before a user profile is updated. */
    public const USER_PRE_UPDATE = 'user.pre_update';

    /**
     * Fires before a role or permission assignment. Veto-only — four-eyes
     * workflows live here.
     */
    public const GRANT_PRE_ASSIGN = 'grant.pre_assign';

    /** Failure policy (§22.8): proceed as if the reactor had replied `allow`. */
    public const FAIL_OPEN = 'fail_open';

    /**
     * Failure policy (§22.8): deny the underlying operation, with an audited
     * reason naming the failure.
     */
    public const FAIL_CLOSED = 'fail_closed';

    /**
     * Registration mode (§22.9): synchronous request/response — the server waits
     * and the reply can veto or mutate within the event's allow-list.
     */
    public const MODE_INTERCEPT = 'intercept';

    /**
     * Registration mode (§22.5): fire-and-forget observation. The server never
     * waits and never reads a reply, so a listener cannot affect any outcome —
     * and a listener handler MUST NOT publish one.
     */
    public const MODE_LISTEN = 'listen';

    /** The per-dispatch timeout a registration gets when it names none (§22.8). */
    public const DEFAULT_TIMEOUT_MS = 500;

    /** Lower bound on `timeout_ms` at registration; `0` is refused (§22.8). */
    public const MIN_TIMEOUT_MS = 1;

    /** Upper bound on `timeout_ms` at registration (§22.8). */
    public const MAX_TIMEOUT_MS = 5000;

    /**
     * Wall-clock ceiling on a whole dispatch chain (§22.8). Reactors not reached
     * inside it are **not contacted**, and each of their own failure policies is
     * applied anyway — so an unreached `fail_closed` veto still denies.
     */
    public const CHAIN_CEILING_MS = 5000;

    /**
     * The topic exchange every reactor event is published to (§22.1). The SERVER
     * declares it; a reactor runtime never does.
     */
    public const EXCHANGE = 'axiam.reactor.events';

    /**
     * Type of {@see self::EXCHANGE} (§22.1). Stated for assertions and admin
     * tooling only — a reactor never declares an exchange.
     */
    public const EXCHANGE_TYPE = 'topic';

    /**
     * The §22.5 registry, mirroring `EVENT_REGISTRY` in
     * `crates/axiam-core/src/models/reactor.rs`.
     *
     * A fresh {@see ReactorEventSpec} list is built per call so a caller cannot
     * edit the SDK's own allow-lists in place: an allow-list a caller can widen is
     * not an allow-list.
     *
     * @return list<ReactorEventSpec>
     */
    public static function all(): array
    {
        return [
            new ReactorEventSpec(
                name: self::TOKEN_PRE_ISSUE,
                interceptable: true,
                mutable: true,
                // Custom claims only. Every standard claim is unreachable because
                // none of them begins with `ext.`.
                mutableFields: ['ext.'],
                defaultFailurePolicy: self::FAIL_OPEN,
                description: 'Enrich or veto token issuance. May add claims under `ext.` only.',
            ),
            new ReactorEventSpec(
                name: self::LOGIN_POST_AUTH,
                interceptable: true,
                mutable: false,
                mutableFields: [],
                defaultFailurePolicy: self::FAIL_CLOSED,
                description: 'After credentials verify, before session issuance: veto or require step-up MFA.',
            ),
            new ReactorEventSpec(
                name: self::USER_PRE_CREATE,
                interceptable: true,
                mutable: true,
                mutableFields: ['username', 'email', 'metadata.'],
                defaultFailurePolicy: self::FAIL_CLOSED,
                description: "Validate or normalize a new user's profile fields.",
            ),
            new ReactorEventSpec(
                name: self::USER_PRE_UPDATE,
                interceptable: true,
                mutable: true,
                mutableFields: ['username', 'email', 'metadata.'],
                defaultFailurePolicy: self::FAIL_CLOSED,
                description: 'Validate or normalize a profile update.',
            ),
            new ReactorEventSpec(
                name: self::GRANT_PRE_ASSIGN,
                interceptable: true,
                mutable: false,
                mutableFields: [],
                defaultFailurePolicy: self::FAIL_CLOSED,
                description: 'Veto a role or permission assignment (four-eyes workflows). Veto-only.',
            ),
        ];
    }

    /**
     * Looks an event up by wire name, returning null for any name outside the
     * §22.5 registry.
     *
     * The hot-path decision operations §22.7 excludes are absent **by
     * construction** rather than by a filter that could be forgotten: they are not
     * in {@see self::all()}, so this returns null for them like any other unknown
     * name, and the runtime refuses such a delivery before a handler ever sees it.
     */
    public static function specFor(string $name): ?ReactorEventSpec
    {
        foreach (self::all() as $spec) {
            if ($spec->name === $name) {
                return $spec;
            }
        }

        return null;
    }

    /**
     * Composes the failure policy a registration naming none inherits from its
     * events (§22.8): the **strictest default wins**, in either array order.
     *
     * A reactor registered for both `token.pre_issue` (open) and
     * `login.post_auth` (closed) can veto a login, so it inherits `fail_closed`.
     * Taking the first event's default instead would let the order of a JSON array
     * decide whether an unreachable fraud check passes — which is why §22.8 states
     * this as a MUST NOT reimplement rather than as a note.
     *
     * An unknown event name contributes `fail_closed`: the server will refuse the
     * registration outright, and guessing open on a name this SDK does not
     * recognise is the wrong way to be wrong. An empty list is `fail_closed` for
     * the same reason.
     *
     * @param list<string> $events
     */
    public static function defaultFailurePolicy(array $events): string
    {
        if ($events === []) {
            return self::FAIL_CLOSED;
        }

        foreach ($events as $name) {
            $spec = self::specFor($name);
            if ($spec === null || $spec->defaultFailurePolicy === self::FAIL_CLOSED) {
                return self::FAIL_CLOSED;
            }
        }

        return self::FAIL_OPEN;
    }

    /**
     * Renders the topic routing key for one event: `<tenant_id>.<event>` (§22.1).
     * Mirrors `routing_key()` in `crates/axiam-amqp/src/reactor/protocol.rs`.
     *
     * Exported for logging, assertions and admin tooling. A reactor runtime never
     * binds it: bindings are the server's, derived from the registration's
     * `events`.
     */
    public static function routingKey(string $tenantId, string $event): string
    {
        return $tenantId . '.' . $event;
    }

    /**
     * Renders the durable per-reactor queue the **server** declares:
     * `axiam.reactor.q.<tenant_id>.<reactor_id>` (§22.1). Mirrors `queue_name()`
     * in `crates/axiam-amqp/src/reactor/protocol.rs`.
     *
     * Deriving the name is not the same as declaring it. A reactor consumes this
     * queue and nothing else; it never declares, redeclares or binds it, and never
     * derives a name for a reactor other than the one it is configured as. A
     * reactor that can bind is a reactor that can bind itself to
     * `*.token.pre_issue` and read another tenant's issuance events.
     */
    public static function queueName(string $tenantId, string $reactorId): string
    {
        return 'axiam.reactor.q.' . $tenantId . '.' . $reactorId;
    }
}
