<?php

declare(strict_types=1);

namespace Axiam\Sdk\Ssf;

/**
 * One RFC 8936 `setErrs` entry: the RFC 8935 §2.4 `err` code and an optional description.
 *
 * AXIAM records the code and never stores the description (§32.6).
 */
final class SetErr
{
    /**
     * @param string      $err         An RFC 8935 §2.4 code (`invalid_request`, `invalid_key`, …).
     * @param string|null $description Optional text for a person; never stored by AXIAM.
     */
    public function __construct(
        public readonly string $err,
        public readonly ?string $description = null,
    ) {
    }

    /** The entry for a refusal: its {@see SetFailureReason::pushErrorCode()}. */
    public static function fromReason(SetFailureReason $reason): self
    {
        return new self($reason->pushErrorCode());
    }

    /**
     * The wire form, `{"err": …}` plus `description` when set.
     *
     * @return array{err: string, description?: string}
     */
    public function toArray(): array
    {
        $out = ['err' => $this->err];
        if ($this->description !== null) {
            $out['description'] = $this->description;
        }

        return $out;
    }
}
