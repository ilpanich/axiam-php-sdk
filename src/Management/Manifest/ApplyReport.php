<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

/**
 * What {@see ManifestApi::apply()} actually did — including, when it stopped early, what
 * it had already done.
 *
 * §27.7 is explicit that apply STOPS AT THE FIRST FAILURE and DOES NOT ROLL BACK. That is
 * not a limitation to apologise for: a partial apply against a live IAM tenant is a state
 * an operator must be able to inspect and resume from, and an automatic rollback would
 * issue a second wave of writes at exactly the moment the server is already telling you
 * something is wrong.
 *
 * So this report is the recovery tool. `$applied` is what landed, in order; `$failure` is
 * why it stopped; `$remaining` is what was never attempted.
 */
final class ApplyReport
{
    /**
     * @param list<PlannedChange> $applied   Changes that succeeded, in the order they ran.
     * @param PlannedChange|null  $failed    The change that failed, or `null` if none did.
     * @param \Throwable|null     $failure   Why it failed, or `null`.
     * @param list<PlannedChange> $remaining Changes never attempted because of the failure.
     */
    public function __construct(
        public readonly array $applied,
        public readonly ?PlannedChange $failed = null,
        public readonly ?\Throwable $failure = null,
        public readonly array $remaining = [],
    ) {
    }

    /** True when every planned change landed. */
    public function isComplete(): bool
    {
        return $this->failed === null;
    }

    /**
     * A human-readable account of the run, suitable for a log line or a CI summary.
     *
     * @return list<string>
     */
    public function describe(): array
    {
        $lines = array_map(
            static fn (PlannedChange $c): string => 'applied  ' . $c->describe(),
            $this->applied,
        );

        if ($this->failed !== null) {
            $lines[] = sprintf(
                'FAILED   %s: %s',
                $this->failed->describe(),
                $this->failure?->getMessage() ?? 'unknown error',
            );
            foreach ($this->remaining as $change) {
                $lines[] = 'skipped  ' . $change->describe();
            }
        }

        return $lines;
    }
}
