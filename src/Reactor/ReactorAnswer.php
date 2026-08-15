<?php

declare(strict_types=1);

namespace Axiam\Sdk\Reactor;

/**
 * What a reactor handler decided (CONTRACT.md §22.4, §22.10).
 *
 * One of three answers — allow, deny or mutate — with `require_mfa` available on
 * `login.post_auth` as a flag on the allow answer.
 *
 * The constructor is private and the only way in is the four named constructors
 * below, which is what makes §22.4's rules **structural rather than documented**:
 *
 *  1. There is no way to spell `allow` + `patch`, because the allow constructors
 *     take no patch. A patch attached to an `allow` is a reply whose author and
 *     whose reader disagree about what will happen; the server refuses it rather
 *     than resolving it.
 *  2. `require_mfa` is not a separate decision value — it rides on `allow`, and
 *     `allow` + `require_mfa: true` on `login.post_auth` resolves to *proceed only
 *     after step-up*.
 *  3. A mutation is carried **unfiltered**. This SDK never reduces a handler's
 *     patch to the event's allowed subset (§22.4 rule 1, §22.10 rule 3).
 */
final class ReactorAnswer
{
    /** Wire value: proceed unchanged (§22.4). */
    public const ALLOW = 'allow';

    /** Wire value: refuse the operation (§22.4). */
    public const DENY = 'deny';

    /** Wire value: proceed, applying a field-allow-listed patch (§22.4). */
    public const MUTATE = 'mutate';

    /**
     * What the server substitutes when a deny carries no reason. Stated here so a
     * caller reading a deny answer back sees the same string the audit record
     * will.
     */
    public const DEFAULT_DENY_REASON = 'denied by reactor';

    /**
     * @param array<string, string>|null $patch
     */
    private function __construct(
        private readonly string $decision,
        private readonly ?string $reason,
        private readonly ?array $patch,
        private readonly bool $requireMfa,
    ) {
    }

    /** Proceed unchanged. */
    public static function allow(): self
    {
        return new self(self::ALLOW, null, null, false);
    }

    /**
     * Proceed only after step-up authentication — `allow` + `require_mfa: true`.
     *
     * Valid on `login.post_auth` ONLY. The runtime refuses it on any other event
     * rather than putting a reply on the wire the server would reject as
     * `require_mfa_not_supported` (§22.4 row 7).
     *
     * On the federated sign-in paths (SAML ACS, OIDC callback) there is no step-up
     * branch to take, so a `require_mfa` answer **fails** the sign-in rather than
     * being silently dropped. A reactor that needs step-up there should answer
     * {@see self::deny()} and drive enrolment out of band (§22.5).
     */
    public static function allowWithStepUp(): self
    {
        return new self(self::ALLOW, null, null, true);
    }

    /**
     * Refuse the operation.
     *
     * The reason is audited; a deny with no reason still denies, and the server
     * substitutes {@see self::DEFAULT_DENY_REASON}. An empty reason is therefore
     * omitted from the reply rather than sent as `""` — the omission is inside the
     * signed bytes (§22.2), so it is not cosmetic.
     *
     * A deny short-circuits the chain: no later reactor is consulted (§22.6).
     */
    public static function deny(string $reason = ''): self
    {
        return new self(self::DENY, $reason === '' ? null : $reason, null, false);
    }

    /**
     * Proceed, applying `$patch` — a flat map of string to string, valid on a
     * mutable event only. There is no nested or typed patch in v1.
     *
     * The patch is sent **UNFILTERED** (§22.4 rule 1, §22.10 rule 3). One
     * forbidden key rejects the *whole* patch server-side, including the fields
     * that would have been fine, and this SDK does NOT quietly drop the offender
     * to rescue the rest: doing so would leave the reactor author believing a
     * field was set when it was dropped, which is the exact failure the server
     * refuses to produce. Use {@see ReactorEventSpec::patchFieldAllowed()} to
     * check a key before you build the patch, not after.
     *
     * @param array<string, string> $patch
     */
    public static function mutate(array $patch): self
    {
        return new self(self::MUTATE, null, $patch, false);
    }

    /** The wire decision string: `allow`, `deny` or `mutate`. */
    public function decision(): string
    {
        return $this->decision;
    }

    /** The deny reason, or null when absent (in which case it is omitted). */
    public function reason(): ?string
    {
        return $this->reason;
    }

    /**
     * The mutation patch, or null on a non-mutate answer.
     *
     * @return array<string, string>|null
     */
    public function patch(): ?array
    {
        return $this->patch;
    }

    /** Whether this answer demands step-up authentication. */
    public function requireMfa(): bool
    {
        return $this->requireMfa;
    }
}
