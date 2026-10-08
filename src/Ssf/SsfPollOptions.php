<?php

declare(strict_types=1);

namespace Axiam\Sdk\Ssf;

/**
 * Arguments to {@see SsfReceiver::poll()} (RFC 8936). Every member is passed through exactly
 * as given; an unset (`null`) one is not sent, so a poll with no options sends `{}`.
 */
final class SsfPollOptions
{
    /**
     * @param int|null              $maxEvents         `maxEvents` — the server clamps it to 100; `0` acknowledges and returns nothing.
     * @param bool|null             $returnImmediately `returnImmediately` — without it the server long-polls up to 30 s.
     * @param list<string>|null     $ack               `ack` — the `jti`s you **processed** since the last poll.
     * @param array<string,SetErr>|null $setErrs       `setErrs` — the `jti`s you refuse, each with its code.
     */
    public function __construct(
        public readonly ?int $maxEvents = null,
        public readonly ?bool $returnImmediately = null,
        public readonly ?array $ack = null,
        public readonly ?array $setErrs = null,
    ) {
    }

    /**
     * The JSON object `poll()` sends: only the members set.
     *
     * @return array<string,mixed>
     */
    public function toArray(): array
    {
        $out = [];
        if ($this->maxEvents !== null) {
            $out['maxEvents'] = $this->maxEvents;
        }
        if ($this->returnImmediately !== null) {
            $out['returnImmediately'] = $this->returnImmediately;
        }
        if ($this->ack !== null) {
            $out['ack'] = array_values($this->ack);
        }
        if ($this->setErrs !== null) {
            $errs = [];
            foreach ($this->setErrs as $jti => $setErr) {
                $errs[(string) $jti] = $setErr->toArray();
            }
            // An object even when empty: `setErrs` is a map, never a JSON array.
            $out['setErrs'] = (object) $errs;
        }

        return $out;
    }
}
