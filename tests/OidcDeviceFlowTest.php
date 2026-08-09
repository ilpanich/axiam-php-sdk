<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\OAuthProtocolError;
use Axiam\Sdk\Oidc\DeviceAuthorization;
use Axiam\Sdk\Oidc\OidcClient;
use Axiam\Sdk\Oidc\OidcConfiguration;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * Device Authorization Grant — CONTRACT.md §14.
 *
 * `deviceLogin` takes an injectable `$sleep`, so these tests assert the §14.2
 * arithmetic — the interval the SDK actually waits, `slow_down` raising it permanently,
 * and the `expires_in` deadline — **exactly**, by recording what would have been slept,
 * rather than spending it in wall-clock time. A test that really slept would take a
 * half-minute to assert one `slow_down` and still only prove it approximately.
 */
final class OidcDeviceFlowTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';
    private const CLIENT_ID = 'my-device';
    private const TENANT_UUID = '22222222-2222-2222-2222-222222222222';
    private const DEVICE_CODE = 'device-code-value';
    private const USER_CODE = 'WDJB-MJHT';

    private function configuration(bool $withDeviceEndpoint = true): OidcConfiguration
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
            grant_types_supported: ['authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'],
            device_authorization_endpoint: $withDeviceEndpoint
                ? self::BASE_URL . '/oauth2/device_authorization'
                : null,
        );
    }

    /**
     * @param array<int,Response> $queue
     * @param array<int,mixed>|null $history
     */
    private function client(array $queue, ?array &$history = null): AxiamClient
    {
        $mock = new MockHandler($queue);
        $stack = HandlerStack::create($mock);
        if ($history !== null) {
            $stack->push(Middleware::history($history));
        }

        // No client secret: §14.1 says a device that cannot show a browser cannot hold
        // one, and the SDK must not refuse such a client.
        return new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            oidcClientId: self::CLIENT_ID,
            oidcClientSecret: null,
            oidcTenantId: self::TENANT_UUID,
            transportHandler: $stack,
        );
    }

    /** @param array<string,mixed> $overrides */
    private static function deviceAuthorizationResponse(array $overrides = []): Response
    {
        $body = array_merge([
            'device_code' => self::DEVICE_CODE,
            'user_code' => self::USER_CODE,
            'verification_uri' => self::BASE_URL . '/device',
            'verification_uri_complete' => self::BASE_URL . '/device?user_code=' . self::USER_CODE,
            'expires_in' => 30,
            'interval' => 1,
        ], $overrides);

        return new Response(200, [], (string) json_encode(array_filter(
            $body,
            static fn (mixed $v): bool => $v !== null,
        )));
    }

    private static function oauthError(string $code, int $status = 400): Response
    {
        return new Response($status, [], (string) json_encode([
            'error' => $code,
            'error_description' => $code . ' description',
        ]));
    }

    private static function tokenSuccess(): Response
    {
        return new Response(200, [], (string) json_encode([
            'access_token' => 'device-access-token',
            'token_type' => 'Bearer',
            'expires_in' => 900,
            'refresh_token' => 'device-refresh-token',
        ]));
    }

    // ===================================================================================
    // deviceAuthorize
    // ===================================================================================

    public function testDeviceAuthorizeIsUnauthenticatedAndFormEncoded(): void
    {
        $history = [];
        $client = $this->client([self::deviceAuthorizationResponse()], $history);

        $authorization = $client->deviceAuthorize(
            scope: 'openid profile',
            configuration: $this->configuration(),
        );

        $request = $history[0]['request'];
        $body = (string) $request->getBody();

        self::assertStringStartsWith('application/x-www-form-urlencoded', $request->getHeaderLine('Content-Type'));
        self::assertStringNotContainsString('client_secret', $body, '§14.1: deviceAuthorize MUST NOT send client_secret');
        self::assertStringContainsString('scope=openid+profile', $body);
        self::assertStringNotContainsString('tenant_id=', $body, '§12.1 note 2: tenant_id is a query parameter');
        self::assertStringContainsString('tenant_id=' . self::TENANT_UUID, (string) $request->getUri());

        self::assertSame(self::USER_CODE, $authorization->userCode);
        self::assertSame(1, $authorization->interval);
        self::assertNotNull($authorization->verificationUriComplete);
    }

    /**
     * @return iterable<string,array{0:int|null}>
     */
    public static function absentIntervalProvider(): iterable
    {
        yield 'omitted' => [null];
        yield 'server-sent zero' => [0];
    }

    /** @dataProvider absentIntervalProvider */
    public function testAbsentOrZeroIntervalDefaultsToFiveSeconds(?int $interval): void
    {
        // §14.2 rule 2: an SDK MUST NOT hard-code a faster floor, and a server-sent 0 is
        // treated as absent — polling with no delay is never what the server meant.
        $client = $this->client([
            self::deviceAuthorizationResponse(['expires_in' => 600, 'interval' => $interval]),
        ]);

        $authorization = $client->deviceAuthorize(configuration: $this->configuration());

        self::assertSame(OidcClient::DEFAULT_POLL_INTERVAL_SECONDS, $authorization->interval);
    }

    public function testDeviceAuthorizeErrorsWhenNoEndpointIsAdvertised(): void
    {
        $client = $this->client([]);

        $this->expectException(AuthError::class);
        $this->expectExceptionMessageMatches('/device_authorization_endpoint/');

        $client->deviceAuthorize(configuration: $this->configuration(withDeviceEndpoint: false));
    }

    public function testDeviceCodeIsRedactedButUserCodeIsNot(): void
    {
        $client = $this->client([self::deviceAuthorizationResponse()]);

        $authorization = $client->deviceAuthorize(configuration: $this->configuration());

        // §14.5: device_code is a bearer credential and must never render.
        self::assertStringNotContainsString(self::DEVICE_CODE, print_r($authorization->deviceCode, true));
        self::assertStringNotContainsString(self::DEVICE_CODE, (string) json_encode($authorization->deviceCode));
        self::assertSame(self::DEVICE_CODE, $authorization->deviceCode->reveal());
        // §14.5: user_code is NOT wrapped — it exists to be read aloud, and wrapping it
        // would defeat the one thing it is for.
        self::assertSame(self::USER_CODE, $authorization->userCode);
    }

    // ===================================================================================
    // §14.2 polling arithmetic — asserted exactly, via the injected sleeper
    // ===================================================================================

    public function testAuthorizationPendingLoopsRatherThanRaising(): void
    {
        $slept = [];
        $client = $this->client([
            self::deviceAuthorizationResponse(),
            self::oauthError('authorization_pending'),
            self::oauthError('authorization_pending'),
            self::tokenSuccess(),
        ]);

        $tokens = $client->deviceLogin(
            onUserCode: static function (DeviceAuthorization $a): void {
            },
            configuration: $this->configuration(),
            sleep: static function (int $s) use (&$slept): void {
                $slept[] = $s;
            },
        );

        self::assertSame('device-access-token', $tokens->accessToken->reveal());
        self::assertSame([1, 1, 1], $slept, 'the interval comes from the response and does not drift');
    }

    public function testSlowDownRaisesTheIntervalPermanently(): void
    {
        // The rule implementations get wrong: backing off for one round and returning to
        // the original interval earns another `slow_down`, forever.
        $slept = [];
        $client = $this->client([
            self::deviceAuthorizationResponse(['expires_in' => 600, 'interval' => 5]),
            self::oauthError('slow_down'),
            self::oauthError('authorization_pending'),
            self::oauthError('slow_down'),
            self::tokenSuccess(),
        ]);

        $client->deviceLogin(
            onUserCode: static function (DeviceAuthorization $a): void {
            },
            configuration: $this->configuration(),
            sleep: static function (int $s) use (&$slept): void {
                $slept[] = $s;
            },
        );

        // 5 → slow_down → 10 → (pending, still 10) → slow_down → 15.
        self::assertSame([5, 10, 10, 15], $slept);
    }

    public function testPollingStopsAtExpiresInEvenWhileTheServerSaysPending(): void
    {
        // 2-second grant, 1-second interval: one poll at t=1, then the t=2 tick is the
        // deadline and must not be sent.
        $history = [];
        $client = $this->client([
            self::deviceAuthorizationResponse(['expires_in' => 2, 'interval' => 1]),
            self::oauthError('authorization_pending'),
        ], $history);

        try {
            $client->deviceLogin(
                onUserCode: static function (DeviceAuthorization $a): void {
                },
                configuration: $this->configuration(),
                sleep: static function (int $s): void {
                },
            );
            self::fail('expected the client-side deadline to fire');
        } catch (OAuthProtocolError $e) {
            self::assertSame(
                'expired_token',
                $e->error,
                '§14.2 rule 4: reported under the same code the server would have used, so a '
                . "caller's branch does not care which side noticed first",
            );
        }

        // device_authorization + exactly one poll: nothing is sent past the deadline.
        self::assertCount(2, $history);
    }

    /**
     * @return iterable<string,array{0:string}>
     */
    public static function terminalAnswerProvider(): iterable
    {
        yield 'access_denied' => ['access_denied'];
        yield 'expired_token' => ['expired_token'];
        yield 'invalid_grant' => ['invalid_grant'];
    }

    /** @dataProvider terminalAnswerProvider */
    public function testTerminalAnswersStopTheLoopAtOnce(string $code): void
    {
        // §14.2 rule 3: "a human said no" and "nobody answered" are the only two pieces of
        // information the device can act on, so they must not be collapsed.
        $history = [];
        $client = $this->client([
            self::deviceAuthorizationResponse(),
            self::oauthError($code),
        ], $history);

        try {
            $client->deviceLogin(
                onUserCode: static function (DeviceAuthorization $a): void {
                },
                configuration: $this->configuration(),
                sleep: static function (int $s): void {
                },
            );
            self::fail('expected a terminal error');
        } catch (OAuthProtocolError $e) {
            self::assertSame($code, $e->error);
        }

        self::assertCount(2, $history, 'a terminal answer must stop the loop at once');
    }

    public function testServerErrorMidPollIsRetriedNotTerminal(): void
    {
        $client = $this->client([
            self::deviceAuthorizationResponse(['expires_in' => 600]),
            self::oauthError('authorization_pending'),
            new Response(500),
            new Response(503),
            self::tokenSuccess(),
        ]);

        $tokens = $client->deviceLogin(
            onUserCode: static function (DeviceAuthorization $a): void {
            },
            configuration: $this->configuration(),
            sleep: static function (int $s): void {
            },
        );

        // §14.2 rule 6: a server restart must not lose a grant the user has already approved.
        self::assertSame('device-access-token', $tokens->accessToken->reveal());
    }

    // ===================================================================================
    // §14.3 deviceLogin
    // ===================================================================================

    public function testDeviceLoginSurfacesTheUserCodeBeforeTheFirstPoll(): void
    {
        $history = [];
        $client = $this->client([
            self::deviceAuthorizationResponse(),
            self::tokenSuccess(),
        ], $history);

        $order = [];
        $seen = null;
        $client->deviceLogin(
            onUserCode: static function (DeviceAuthorization $a) use (&$order, &$seen, &$history): void {
                // The request count at callback time is the ordering proof: the
                // authorization request has happened, no poll has.
                $order[] = 'userCode@' . count($history);
                $seen = $a->userCode;
            },
            configuration: $this->configuration(),
            sleep: static function (int $s): void {
            },
        );

        self::assertSame(['userCode@1'], $order, '§14.3 rule 2: displayed BEFORE polling begins');
        self::assertSame(self::USER_CODE, $seen);
    }

    /**
     * @return iterable<string,array{0:bool}>
     */
    public static function adoptionProvider(): iterable
    {
        yield 'not adopted' => [false];
        yield 'adopted' => [true];
    }

    /**
     * §14.6 as amended by the contract 1.7 errata: assert the RETURNED token set — and,
     * because this SDK's adoption is a flag, assert BOTH directions of that flag.
     *
     * @dataProvider adoptionProvider
     */
    public function testDeviceLoginReturnsTheTokenSetAndAdoptsOnlyWhenAsked(bool $adopt): void
    {
        $client = $this->client([
            self::deviceAuthorizationResponse(),
            self::tokenSuccess(),
        ]);

        $tokens = $client->deviceLogin(
            onUserCode: static function (DeviceAuthorization $a): void {
            },
            configuration: $this->configuration(),
            adoptAsCredential: $adopt,
            sleep: static function (int $s): void {
            },
        );

        self::assertSame('device-access-token', $tokens->accessToken->reveal());
        self::assertSame('Bearer', $tokens->tokenType);
    }

    // ===================================================================================
    // devicePoll standalone
    // ===================================================================================

    public function testDevicePollSurfacesPendingForHandRolledLoops(): void
    {
        $client = $this->client([self::oauthError('authorization_pending')]);

        try {
            $client->devicePoll(self::DEVICE_CODE, configuration: $this->configuration());
            self::fail('expected authorization_pending to surface');
        } catch (OAuthProtocolError $e) {
            self::assertSame('authorization_pending', $e->error);
        }
    }

    public function testDevicePollSendsTheDeviceCodeGrant(): void
    {
        $history = [];
        $client = $this->client([self::tokenSuccess()], $history);

        $client->devicePoll(self::DEVICE_CODE, configuration: $this->configuration());

        $body = (string) $history[0]['request']->getBody();
        self::assertStringContainsString('grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code', $body);
        self::assertStringContainsString('device_code=' . self::DEVICE_CODE, $body);
    }
}
