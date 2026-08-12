<?php

declare(strict_types=1);

namespace Axiam\Sdk;

use Axiam\Sdk\Core\Sensitive;

/**
 * A configured `WWW-Authenticate: UMA` challenge emitter (CONTRACT.md §20.3, emit half).
 *
 * Hand one to {@see AccessEnforcer} and a `#[RequireAccess]` denial stops being a bare
 * 403: the enforcer mints a fresh permission ticket for the action the caller lacked and
 * returns it in the header, so a UMA-aware client knows where to go for authority instead
 * of only being told "no". Because both framework bridges delegate every decision to that
 * one enforcer, configuring it once covers Laravel and Symfony alike.
 *
 * **Opt-in, and deliberately so.** Emitting a challenge means minting a credential — a
 * wire call to the Protection API, and a live ticket, produced on a path the caller did
 * not explicitly request. An enforcer that did that on every denial by default would turn
 * each unauthorized request into a Protection API call, which is a denial-of-service
 * amplifier pointed at your own authorization server. So it happens only where an
 * application constructed the enforcer with one.
 *
 * **Failure is not escalation.** If minting fails — the PAT expired, the Protection API is
 * down, the resource declares none of the requested scopes — the denial still surfaces as
 * an ordinary 403 without a challenge. A caller who was going to be refused is refused
 * either way; letting a Protection API outage turn a deny into a 503 would hand the outage
 * a second consequence, and letting it turn into an allow would be a security bug.
 */
final class UmaChallenger
{
    /**
     * @param string     $realm  The protection realm to name in the header.
     * @param string     $asUri  The authorization server to send the caller to — normally
     *        this deployment's issuer, read from discovery rather than concatenated by
     *        hand (§12.3 rule 6).
     * @param Sensitive|string $pat A Protection API Token: a *client-credentials* token
     *        carrying the `uma_protection` scope (§20.2 rule 1). A user token cannot stand
     *        in — a minted ticket is bound to the `client_id` that minted it.
     * @param AxiamClient $client The client whose `umaRequestTicket` mints the ticket.
     */
    public function __construct(
        public readonly string $realm,
        public readonly string $asUri,
        public readonly Sensitive|string $pat,
        public readonly AxiamClient $client,
    ) {
    }

    /**
     * Renders without the PAT (§7): a challenger is configuration an application may
     * reasonably log, and the credential inside it is not.
     */
    public function __toString(): string
    {
        return sprintf('UmaChallenger(realm=%s, asUri=%s, pat=[SENSITIVE])', $this->realm, $this->asUri);
    }
}
