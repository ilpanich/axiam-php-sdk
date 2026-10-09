<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Management\FieldError;
use Axiam\Sdk\Management\ValidationError;

/**
 * Arguments to {@see OidcClient::cibaInitiate()} — `CibaInitiateRequest` (CONTRACT.md §33.2).
 *
 * Exactly one hint: `loginHint` (a username, then an e-mail address, within the tenant) or
 * `idTokenHint` (an ID token this deployment issued to this client). `binding_message` and
 * `login_hint` can be personal data: the SDK never logs them. There is no parameter for
 * `login_hint_token`, `user_code` or `request_uri` — AXIAM refuses each (§33.3 rule 3).
 *
 * Every member set is sent, and nothing else; the server's bounds (§33.3 rule 5) are the
 * server's to check, so none is pre-validated here. With a `signer`, every member travels
 * inside one signed `request` JWT instead (§33.2's signed form).
 */
final class CibaInitiateRequest
{
    /**
     * @param string $scope Space-separated; must include `openid`.
     * @param string|null $loginHint Whom to authenticate — exactly one of this and `$idTokenHint`.
     * @param string|null $idTokenHint An ID token this deployment issued to this client.
     * @param string|null $bindingMessage Shown to the user on the approval page — what lets them
     *        tell the request they started from one an attacker did. Required for a `fapi2` client.
     * @param int|null $requestedExpiry The requested lifetime, 30–600 s (absent: 300). Sent as a
     *        string on the form, as a number inside a signed request.
     * @param string|null $acrValues Space-separated authentication context classes.
     * @param string|null $resource An RFC 8707 resource indicator.
     * @param CibaDeliveryMode $delivery Poll or ping, as the client registered.
     * @param Sensitive|null $clientNotificationToken Ping mode only, and required there: the
     *        bearer AXIAM presents at the ping. Keep it to check the ping with
     *        {@see OidcClient::cibaHandlePing()}; AXIAM never returns it.
     * @param CibaRequestSigner|null $signer Sends the request as one signed JWT (`request`) —
     *        required of a client that registered a signing algorithm, refused from one that did not.
     *
     * @throws ValidationError locally: both hints or neither; a ping request without a non-empty
     *         notification token; a poll request with one.
     */
    public function __construct(
        public readonly string $scope,
        public readonly ?string $loginHint = null,
        public readonly ?string $idTokenHint = null,
        public readonly ?string $bindingMessage = null,
        public readonly ?int $requestedExpiry = null,
        public readonly ?string $acrValues = null,
        public readonly ?string $resource = null,
        public readonly CibaDeliveryMode $delivery = CibaDeliveryMode::Poll,
        public readonly ?Sensitive $clientNotificationToken = null,
        public readonly ?CibaRequestSigner $signer = null,
    ) {
        if (($loginHint === null) === ($idTokenHint === null)) {
            throw self::refuse('login_hint', 'set exactly one of login_hint and id_token_hint');
        }
        if ($delivery === CibaDeliveryMode::Ping
            && ($clientNotificationToken === null || $clientNotificationToken->reveal() === '')) {
            throw self::refuse(
                'client_notification_token',
                'a ping-mode request needs a client_notification_token: without one AXIAM has nothing to ping with',
            );
        }
        if ($delivery === CibaDeliveryMode::Poll && $clientNotificationToken !== null) {
            throw self::refuse('client_notification_token', 'a poll-mode request carries no client_notification_token');
        }
    }

    /**
     * The authentication-request members this request sets, exactly — the wire spelling, with
     * `requested_expiry` as an integer (the form sends it as a string, a signed request as a
     * number).
     *
     * @return array<string,string|int|Sensitive>
     */
    public function members(): array
    {
        $out = ['scope' => $this->scope];
        if ($this->loginHint !== null) {
            $out['login_hint'] = $this->loginHint;
        }
        if ($this->idTokenHint !== null) {
            $out['id_token_hint'] = $this->idTokenHint;
        }
        if ($this->bindingMessage !== null) {
            $out['binding_message'] = $this->bindingMessage;
        }
        if ($this->requestedExpiry !== null) {
            $out['requested_expiry'] = $this->requestedExpiry;
        }
        if ($this->acrValues !== null) {
            $out['acr_values'] = $this->acrValues;
        }
        if ($this->resource !== null) {
            $out['resource'] = $this->resource;
        }
        if ($this->clientNotificationToken !== null) {
            $out['client_notification_token'] = $this->clientNotificationToken;
        }

        return $out;
    }

    private static function refuse(string $field, string $why): ValidationError
    {
        return new ValidationError(
            sprintf('ciba_initiate: %s (CONTRACT.md §33.2)', $why),
            [new FieldError($field, $why)],
        );
    }
}
