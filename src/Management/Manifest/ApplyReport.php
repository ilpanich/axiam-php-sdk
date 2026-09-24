<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

use Axiam\Sdk\Management\Models\ServiceAccountCreatedResponse;

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
     * @param list<ServiceAccountCreatedResponse> $createdServiceAccounts Every service
     *        account this apply created, `client_secret` included — the ONE time it is
     *        ever returned (§27.5 rule 5, CONTRACT.md §27.6.1 addition 3). Kept here even
     *        when a LATER step of the same apply fails: the account and its secret exist
     *        on the server regardless, and losing the report would lose the only chance
     *        to read the secret at all. `apply()` never rotates one to reconcile drift.
     */
    public function __construct(
        public readonly array $applied,
        public readonly ?PlannedChange $failed = null,
        public readonly ?\Throwable $failure = null,
        public readonly array $remaining = [],
        public readonly array $createdServiceAccounts = [],
    ) {
    }

    /** True when every planned change landed. */
    public function isComplete(): bool
    {
        return $this->failed === null;
    }

    /**
     * Every service account this apply created, with the one-time secret the server
     * returned for it. See {@see self::$createdServiceAccounts}.
     *
     * @return list<ServiceAccountCreatedResponse>
     */
    public function createdServiceAccounts(): array
    {
        return $this->createdServiceAccounts;
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
