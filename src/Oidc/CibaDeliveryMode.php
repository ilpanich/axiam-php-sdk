<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * How a CIBA client receives the outcome, as it registered (CONTRACT.md §33.3 rule 1). There
 * is no push mode: AXIAM does not offer it.
 */
enum CibaDeliveryMode: string
{
    /** The client polls the token endpoint ({@see OidcClient::cibaAwait()}). */
    case Poll = 'poll';

    /**
     * AXIAM pings the client's registered notification endpoint, presenting the request's
     * `client_notification_token` as a bearer; the client then polls once.
     */
    case Ping = 'ping';
}
