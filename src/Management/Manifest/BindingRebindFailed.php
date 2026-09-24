<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

use Axiam\Sdk\Core\AxiamException;

/**
 * A role binding's `Update` failed at its RE-ASSIGNMENT (§27.6.1 addition 2, contract 1.51).
 *
 * There is no update endpoint for a role binding: changing its resource or `inherit`
 * means unassign, then assign. This is not atomic, and the contract does not say what a
 * failed rebind leaves behind (C-12 question 7) — this SDK's answer is: the previous
 * assignment had already been removed by the time the assign was attempted, so `apply()`
 * tries to assign it again and this exception carries BOTH results.
 *
 * Unlike {@see ManifestException}, this is never a refusal to start — it is thrown from
 * inside `apply()`, after at least one write (the unassign) has already reached the
 * server, and it is what {@see \Axiam\Sdk\Management\Manifest\ApplyReport::$failure}
 * holds for a rebind that failed this way.
 */
final class BindingRebindFailed extends AxiamException
{
    /**
     * @param string      $message      Why the new assignment was refused.
     * @param bool        $restored     Whether the previous assignment was put back.
     *                                  `true` means the subject holds the role exactly as
     *                                  before the failed rebind; `false` means it holds
     *                                  NO such role now.
     * @param string|null $restoreError Why the restore itself failed, when `$restored` is
     *                                  `false`.
     */
    public function __construct(
        string $message,
        public readonly bool $restored,
        public readonly ?string $restoreError = null,
    ) {
        parent::__construct($message);
    }
}
