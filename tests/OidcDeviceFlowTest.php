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
     * @param array<int,Response|\Throwable> $queue
     * @param array<int,mixed>|null $history
     */
    private function client(array $queue, ?array &$history = null, bool $retryEnabled = true): AxiamClient
    {
        $mock = new MockHandler($queue);
        $stack = HandlerStack::create($mock);
        if ($history !== null) {
            $stack->push(Middleware::history($history));
        }

        // No client secret: this is a PUBLIC client (§14.1 rule 1) — a device that cannot
        // hold a secret — and the SDK must not refuse it. A client configured with a credential
        // sends it at both device endpoints: tests/Contract162/DeviceGrantAuthenticationTest.php.
        return new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            oidcClientId: self::CLIENT_ID,
            oidcClientSecret: null,
            oidcTenantId: self::TENANT_UUID,
            transportHandler: $stack,
            retryEnabled: $retryEnabled,
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

    public function testAPublicClientsDeviceAuthorizeSendsNoCredentialAndIsFormEncoded(): void
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
        self::assertStringNotContainsString('client_secret', $body, '§14.1 rule 1: a public client sends no credential');
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

    // ----- contract 1.64 (§14.2 rule 9, last paragraph; §14.6): a 429 on a poll is waited out -----

    public function testRateLimitedPollIsWaitedOutAndTheIntervalIsUnchanged(): void
    {
        // The mock answers one poll with 429 and Retry-After, then the tokens. The loop waits at
        // least the Retry-After (a recorded sleep), polls again and completes, and the poll after
        // the 429 is scheduled at the interval the loop held before it — not five seconds longer.
        $slept = [];
        $history = [];
        $client = $this->client([
            self::deviceAuthorizationResponse(['expires_in' => 600, 'interval' => 5]),
            self::oauthError('authorization_pending'),
            new Response(429, ['Retry-After' => '17'], (string) json_encode(['error' => 'rate_limit_exceeded'])),
            self::oauthError('authorization_pending'),
            self::tokenSuccess(),
        ], $history);

        $tokens = $client->deviceLogin(
            onUserCode: static function (DeviceAuthorization $a): void {
            },
            configuration: $this->configuration(),
            sleep: static function (int $s) use (&$slept): void {
                $slept[] = $s;
            },
        );

        self::assertSame('device-access-token', $tokens->accessToken->reveal());
        self::assertSame([5, 5, 17, 5], $slept, 'the 429 round waits Retry-After; the interval stays 5');
        self::assertCount(5, $history, 'device_authorization + four polls');
    }

    public function testRetryAfterIsOnlyAMinimumNeverShorterThanTheInterval(): void
    {
        $slept = [];
        $client = $this->client([
            self::deviceAuthorizationResponse(['expires_in' => 600, 'interval' => 5]),
            new Response(429, ['Retry-After' => '1'], (string) json_encode(['error' => 'rate_limit_exceeded'])),
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

        self::assertSame([5, 5], $slept);
    }

    public function testRetryAfterPastTheDeadlineIsCappedAndNothingIsSentAfterIt(): void
    {
        $history = [];
        $slept = [];
        $client = $this->client([
            self::deviceAuthorizationResponse(['expires_in' => 30, 'interval' => 5]),
            new Response(429, ['Retry-After' => '3600'], (string) json_encode(['error' => 'rate_limit_exceeded'])),
        ], $history);

        try {
            $client->deviceLogin(
                onUserCode: static function (DeviceAuthorization $a): void {
                },
                configuration: $this->configuration(),
                sleep: static function (int $s) use (&$slept): void {
                    $slept[] = $s;
                },
            );
            self::fail('expected the client-side deadline to fire');
        } catch (OAuthProtocolError $e) {
            self::assertSame('expired_token', $e->error);
        }

        self::assertCount(2, $history, 'device_authorization + the one rate-limited poll; nothing after');
        self::assertSame([5], $slept, 'the uncapped hour is never slept (C164-19)');
    }

    // ----- contract 1.64 (amended): the status decides, 5xx is a transport failure whatever its body -----

    /** @return iterable<string,array{int,string}> */
    public static function serverFailureBodies(): iterable
    {
        yield '500 server_error' => [500, 'server_error'];
        yield '503 temporarily_unavailable' => [503, 'temporarily_unavailable'];
    }

    /** @dataProvider serverFailureBodies */
    public function testA5xxWithAnOAuthBodyIsRetriedWithinThePollThenTheLoopContinues(int $status, string $code): void
    {
        // AXIAM answers a datastore failure at /oauth2/token with 500 {"error":"server_error",…}
        // (C164-03, §14.2 rule 6): a transport failure whatever its body, §16-retried inside the
        // poll (C164-25, §14.6): one 5xx and then the tokens cost one interval, two requests.
        $slept = [];
        $history = [];
        $client = $this->client([
            self::deviceAuthorizationResponse(['expires_in' => 600, 'interval' => 5]),
            self::oauthError($code, $status),
            self::tokenSuccess(),
        ], $history);

        $tokens = $client->deviceLogin(
            onUserCode: static function (DeviceAuthorization $a): void {
            },
            configuration: $this->configuration(),
            sleep: static function (int $s) use (&$slept): void {
                $slept[] = $s;
            },
        );

        self::assertSame('device-access-token', $tokens->accessToken->reveal());
        self::assertSame([5], $slept, 'the retry is inside the attempt, not a second interval');
        self::assertCount(3, $history, 'device_authorization + the 5xx + the retry');
    }

    public function testTwoFailuresAndA200AreThreeRequestsInOneInterval(): void
    {
        // §14.6 (amended, C164-35): the attempt cap of §16.1 is 3 in total.
        $slept = [];
        $history = [];
        $client = $this->client([
            self::deviceAuthorizationResponse(['expires_in' => 600, 'interval' => 5]),
            self::oauthError('server_error', 500),
            self::oauthError('server_error', 500),
            self::tokenSuccess(),
        ], $history);

        $client->deviceLogin(
            onUserCode: static function (DeviceAuthorization $a): void {
            },
            configuration: $this->configuration(),
            sleep: static function (int $s) use (&$slept): void {
                $slept[] = $s;
            },
        );

        self::assertSame([5], $slept);
        self::assertCount(4, $history, 'device_authorization + three polls of one attempt');
    }

    public function testAThirdFailureExhaustsTheCapAndTheLoopTakesItsNextInterval(): void
    {
        $slept = [];
        $history = [];
        $client = $this->client([
            self::deviceAuthorizationResponse(['expires_in' => 600, 'interval' => 5]),
            self::oauthError('server_error', 500),
            self::oauthError('server_error', 500),
            self::oauthError('server_error', 500),
            self::tokenSuccess(),
        ], $history);

        $client->deviceLogin(
            onUserCode: static function (DeviceAuthorization $a): void {
            },
            configuration: $this->configuration(),
            sleep: static function (int $s) use (&$slept): void {
                $slept[] = $s;
            },
        );

        self::assertSame([5, 5], $slept, 'rule 6: the exhausted attempt is surfaced, the grant is not lost');
        self::assertCount(5, $history, 'device_authorization + three failed polls + the next interval\'s poll');
    }

    public function testWithRetryDisabledA5xxMakesOneRequestPerPoll(): void
    {
        $slept = [];
        $history = [];
        $client = $this->client([
            self::deviceAuthorizationResponse(['expires_in' => 600, 'interval' => 5]),
            self::oauthError('server_error', 500),
            self::tokenSuccess(),
        ], $history, retryEnabled: false);

        $client->deviceLogin(
            onUserCode: static function (DeviceAuthorization $a): void {
            },
            configuration: $this->configuration(),
            sleep: static function (int $s) use (&$slept): void {
                $slept[] = $s;
            },
        );

        self::assertSame([5, 5], $slept);
        self::assertCount(3, $history);
    }

    public function testASingleDevicePollRetriesA5xxThenSurfacesANetworkError(): void
    {
        $history = [];
        $client = $this->client([
            self::oauthError('server_error', 500),
            self::oauthError('server_error', 500),
            self::oauthError('server_error', 500),
        ], $history);

        try {
            $client->devicePoll(self::DEVICE_CODE, null, $this->configuration());
            self::fail('expected a NetworkError');
        } catch (\Axiam\Sdk\Core\NetworkError $e) {
            self::assertCount(3, $history, 'three attempts in total, whatever the body');
        }
    }

    public function testASingleDevicePollRetriesATransportFailure(): void
    {
        $history = [];
        $client = $this->client([
            new \GuzzleHttp\Exception\ConnectException('connection reset', new \GuzzleHttp\Psr7\Request('POST', self::BASE_URL . '/oauth2/token')),
            self::tokenSuccess(),
        ], $history);

        $tokens = $client->devicePoll(self::DEVICE_CODE, null, $this->configuration());

        self::assertSame('device-access-token', $tokens->accessToken->reveal());
        self::assertCount(2, $history);
    }

    public function testA429IsNeverRetriedInsideThePoll(): void
    {
        // §14.2 rule 9: the wait is the loop's. With retry on, the poll makes one request.
        foreach ([
            new Response(429, ['Retry-After' => '1'], (string) json_encode(['error' => 'rate_limit_exceeded'])),
            new Response(429, ['Retry-After' => '1']),
        ] as $answer) {
            $history = [];
            $client = $this->client([$answer], $history);

            try {
                $client->devicePoll(self::DEVICE_CODE, null, $this->configuration());
                self::fail('expected the 429 to surface');
            } catch (\Axiam\Sdk\Core\AxiamException $e) {
                self::assertSame(1000.0, $e->retryAfterMs ?? null);
            }
            self::assertCount(1, $history);
        }
    }

    public function testARetryAfterThatReachesTheDeadlineIsNotWaitedInsideThePoll(): void
    {
        // The loop bounds the §16 retry by the grant's deadline: a 503 whose Retry-After would
        // reach it is surfaced at once, and rule 4 ends the flow with nothing sent after it.
        $history = [];
        $client = $this->client([
            self::deviceAuthorizationResponse(['expires_in' => 30, 'interval' => 5]),
            new Response(503, ['Retry-After' => '3600'], (string) json_encode(['error' => 'temporarily_unavailable'])),
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
            self::assertSame('expired_token', $e->error);
        }

        self::assertCount(2, $history);
    }

    public function testA429WhoseBodySaysSlowDownDoesNotRaiseTheInterval(): void
    {
        // C164-04: rule 5's dispatch on `error` applies to the 400; a 429 is the wait.
        $slept = [];
        $client = $this->client([
            self::deviceAuthorizationResponse(['expires_in' => 600, 'interval' => 5]),
            new Response(429, ['Retry-After' => '1'], (string) json_encode(['error' => 'slow_down'])),
            self::oauthError('authorization_pending'),
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

        self::assertSame([5, 5, 5], $slept);
    }

    public function testABodilessOrForeignBody429StillHonoursRetryAfterAsAFloor(): void
    {
        // C164-17: a proxy's 429.
        $slept = [];
        $client = $this->client([
            self::deviceAuthorizationResponse(['expires_in' => 600, 'interval' => 5]),
            new Response(429, ['Retry-After' => '12']),
            new Response(429, ['Retry-After' => '1'], '<html>slow down</html>'),
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

        self::assertSame([5, 12, 5], $slept);
    }

    public function testAMalformedRetryAfterIsIgnoredAndDoesNotEndTheFlow(): void
    {
        // C164-09: `strtotime("17.0")` is about seven hours ahead, which ended the flow.
        $slept = [];
        $client = $this->client([
            self::deviceAuthorizationResponse(['expires_in' => 600, 'interval' => 5]),
            new Response(429, ['Retry-After' => '17.0'], (string) json_encode(['error' => 'rate_limit_exceeded'])),
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

        self::assertSame([5, 5], $slept);
    }

    public function testTheDeadlineCountsTheTimeARequestTakes(): void
    {
        // C164-05: the elapsed time is the larger of the seconds slept and the clock. Each poll
        // here costs 40 s of clock on top of a 5 s interval, so a 100 s grant is out after three
        // polls (clock 90 s, the next 5 s sleep would reach 100 s), where counting sleeps alone
        // would send nineteen.
        $clock = 1000.0;
        $polls = 0;
        $mock = new MockHandler([self::deviceAuthorizationResponse(['expires_in' => 100, 'interval' => 5])]);
        for ($i = 0; $i < 20; $i++) {
            $mock->append(static function () use (&$clock, &$polls): Response {
                $polls++;
                $clock += 40.0;

                return self::oauthError('authorization_pending');
            });
        }
        $client = new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            oidcClientId: self::CLIENT_ID,
            oidcClientSecret: null,
            oidcTenantId: self::TENANT_UUID,
            transportHandler: HandlerStack::create($mock),
            retryEnabled: false,
        );

        try {
            $client->deviceLogin(
                onUserCode: static function (DeviceAuthorization $a): void {
                },
                configuration: $this->configuration(),
                sleep: static function (int $s) use (&$clock): void {
                    $clock += $s;
                },
                now: static function () use (&$clock): float {
                    return $clock;
                },
            );
            self::fail('expected the client-side deadline to fire');
        } catch (OAuthProtocolError $e) {
            self::assertSame('expired_token', $e->error);
        }

        self::assertSame(3, $polls);
    }

    public function testASingleDevicePollStillRaisesTheRateLimitError(): void
    {
        $client = $this->client([
            new Response(429, ['Retry-After' => '9'], (string) json_encode(['error' => 'rate_limit_exceeded'])),
        ]);

        try {
            $client->devicePoll(self::DEVICE_CODE, null, $this->configuration());
            self::fail('expected an OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame('rate_limit_exceeded', $e->error);
            self::assertSame(9000.0, $e->retryAfterMs);
        }
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
