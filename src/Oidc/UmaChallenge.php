<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\Sensitive;

/**
 * A parsed `WWW-Authenticate: UMA` challenge (UMA 2.0 §3.2, CONTRACT.md §20.3).
 */
final class UmaChallenge
{
    /**
     * @param string|null $realm The protection realm the resource server named.
     * @param string|null $asUri The authorization server the resource server nominates. **Not automatically trusted** — see {@see self::parse()}.
     * @param Sensitive|null $ticket The ticket to exchange — a bearer credential for its 60-second life.
     */
    public function __construct(
        public readonly ?string $realm = null,
        public readonly ?string $asUri = null,
        public readonly ?Sensitive $ticket = null,
    ) {
    }

    /**
     * Parse a `WWW-Authenticate: UMA …` header value (§20.3).
     *
     * **This deliberately does not exchange the ticket.** Parsing a challenge and
     * acting on it are separate decisions: the `as_uri` names an authorization server
     * the caller has not necessarily chosen to trust, and auto-exchanging would send
     * the requesting party's `claim_token` to whatever host answered the 403. The
     * caller decides.
     *
     * @return self|null The parsed challenge, or null when the header is not a UMA challenge.
     */
    public static function parse(string $header): ?self
    {
        $trimmed = trim($header);
        if (!str_starts_with($trimmed, 'UMA')) {
            return null;
        }
        $rest = substr($trimmed, 3);
        // "UMA" alone is a valid, if useless, challenge; anything else must be
        // separated by whitespace so `UMAX realm="…"` is not read as UMA.
        if ($rest !== '' && trim($rest[0]) !== '') {
            return null;
        }

        $realm = null;
        $asUri = null;
        $ticket = null;
        foreach (explode(',', $rest) as $part) {
            $eq = strpos($part, '=');
            if ($eq === false) {
                continue;
            }
            $key = trim(substr($part, 0, $eq));
            $value = trim(trim(substr($part, $eq + 1)), '"');
            switch ($key) {
                case 'realm':
                    $realm = $value;
                    break;
                case 'as_uri':
                    $asUri = $value;
                    break;
                case 'ticket':
                    $ticket = new Sensitive($value);
                    break;
                default:
                    // Unknown parameters are ignored rather than rejected: UMA 2.0
                    // permits a server to add its own, and refusing the whole
                    // challenge over one would lose the ticket with it.
                    break;
            }
        }

        return new self($realm, $asUri, $ticket);
    }

    /**
     * Format a `WWW-Authenticate: UMA` header value (§20.3, emit half).
     *
     * The resource-server side: having obtained a ticket from `umaRequestTicket`,
     * tell the caller where to redeem it.
     */
    public static function header(string $realm, string $asUri, Sensitive|string $ticket): string
    {
        $value = $ticket instanceof Sensitive ? $ticket->reveal() : $ticket;

        return sprintf('UMA realm="%s", as_uri="%s", ticket="%s"', $realm, $asUri, $value);
    }
}
