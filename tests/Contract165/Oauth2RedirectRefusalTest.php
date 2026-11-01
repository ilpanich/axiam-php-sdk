<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract165;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Oidc\OidcClient;
use Axiam\Sdk\Oidc\OidcConfiguration;
use GuzzleHttp\Promise\Create;
use GuzzleHttp\Promise\PromiseInterface;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * CONTRACT.md §12.1 rule 3 / §37.2 rule 12 (C165-22): no redirect is followed from a POST to an
 * `/oauth2/*` endpoint, on the three `/oauth2/token` calls that do not go through `postForm` —
 * `oidcRefresh` (async), the device poll and the CIBA poll. A 307/308 answered by the AXIAM host
 * points at a second host that would answer 200 with a token set; the second host must see nothing.
 */
final class Oauth2RedirectRefusalTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const OTHER_HOST = 'other.test';
    private const TENANT_UUID = '22222222-2222-2222-2222-222222222222';
    private const CLIENT_ID = 'relay-app';
    private const CLIENT_SECRET = 'relay-client-secret';
    private const REFRESH_TOKEN = 'the-refresh-token';
    private const DEVICE_CODE = 'the-device-code';
    private const AUTH_REQ_ID = 'the-auth-req-id';

    /** @var list<RequestInterface> */
    private array $sent = [];

    private function configuration(): OidcConfiguration
    {
        return new OidcConfiguration(
            issuer: self::BASE_URL,
            authorization_endpoint: self::BASE_URL . '/oauth2/authorize',
            token_endpoint: self::BASE_URL . '/oauth2/token',
            userinfo_endpoint: self::BASE_URL . '/oauth2/userinfo',
            jwks_uri: self::BASE_URL . '/oauth2/jwks',
            revocation_endpoint: self::BASE_URL . '/oauth2/revoke',
            introspection_endpoint: self::BASE_URL . '/oauth2/introspect',
            response_types_supported: ['code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['EdDSA'],
            scopes_supported: ['openid'],
            token_endpoint_auth_methods_supported: ['client_secret_post'],
            claims_supported: ['sub'],
            grant_types_supported: ['refresh_token', OidcClient::CIBA_GRANT_TYPE],
            backchannel_authentication_endpoint: self::BASE_URL . '/oauth2/bc-authorize',
        );
    }

    /**
     * An AXIAM host that answers every request with `$status` + a `Location` on the second host, and a
     * second host that answers 200 with a token set (what a followed redirect would consume).
     */
    private function client(int $status, bool $retry = false): AxiamClient
    {
        $this->sent = [];
        $captured = &$this->sent;
        $handler = static function (RequestInterface $request) use (&$captured, $status): PromiseInterface {
            $captured[] = $request;
            if ($request->getUri()->getHost() === self::OTHER_HOST) {
                return Create::promiseFor(new Response(200, ['Content-Type' => 'application/json'], (string) json_encode([
                    'access_token' => 'stolen-access-token',
                    'token_type' => 'Bearer',
                    'expires_in' => 900,
                ])));
            }

            return Create::promiseFor(new Response($status, ['Location' => 'http://' . self::OTHER_HOST . '/oauth2/token']));
        };

        return new AxiamClient(
            self::BASE_URL,
            'acme-tenant',
            oidcClientId: self::CLIENT_ID,
            oidcClientSecret: self::CLIENT_SECRET,
            oidcTenantId: self::TENANT_UUID,
            transportHandler: $handler,
            retryEnabled: $retry,
        );
    }

    private function assertRefused(\Throwable $e, int $status): void
    {
        self::assertInstanceOf(NetworkError::class, $e);
        $message = $e->getMessage();
        foreach ([self::REFRESH_TOKEN, self::DEVICE_CODE, self::AUTH_REQ_ID, self::CLIENT_SECRET, self::OTHER_HOST, 'stolen'] as $secret) {
            self::assertStringNotContainsString($secret, $message, 'no secret and no Location in the error (' . $status . ')');
        }
        self::assertCount(1, $this->sent, 'exactly one request, and the other host sees none (' . $status . ')');
        self::assertSame('api.test', $this->sent[0]->getUri()->getHost());
        foreach ($this->sent as $request) {
            self::assertNotSame(self::OTHER_HOST, $request->getUri()->getHost());
        }
    }

    public function testOidcRefreshDoesNotFollowARedirect(): void
    {
        foreach ([307, 308] as $status) {
            $client = $this->client($status);
            try {
                $client->oidcRefresh(self::REFRESH_TOKEN, configuration: $this->configuration());
                self::fail('expected a NetworkError');
            } catch (NetworkError $e) {
                $this->assertRefused($e, $status);
            }
        }
    }

    public function testTheDevicePollDoesNotFollowARedirect(): void
    {
        foreach ([307, 308] as $status) {
            // Retry enabled: a 3xx is the poll's decided answer and is not §16-retried.
            $client = $this->client($status, retry: true);
            try {
                $client->devicePoll(self::DEVICE_CODE, configuration: $this->configuration());
                self::fail('expected a NetworkError');
            } catch (NetworkError $e) {
                $this->assertRefused($e, $status);
            }
        }
    }

    public function testTheCibaPollDoesNotFollowARedirect(): void
    {
        foreach ([307, 308] as $status) {
            $client = $this->client($status, retry: true);
            try {
                $client->cibaPoll(new Sensitive(self::AUTH_REQ_ID), configuration: $this->configuration());
                self::fail('expected a NetworkError');
            } catch (NetworkError $e) {
                $this->assertRefused($e, $status);
            }
        }
    }
}
