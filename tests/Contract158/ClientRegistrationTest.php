<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract158;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\OAuthProtocolError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Management\ValidationError;
use Axiam\Sdk\Oidc\ClientRegistration;
use Axiam\Sdk\Tests\Fixtures\RedactionAssertions;
use Axiam\Sdk\Tests\Fixtures\RoutedHandler;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * RFC 7592 client configuration — CONTRACT.md §28.12.6's five required tests (and the
 * Rust reference port's eight cases covering them). Every token here is generated at run time.
 */
final class ClientRegistrationTest extends TestCase
{
    use RedactionAssertions;

    private const BASE_URL = 'https://iam.example.test';
    private const CLIENT = 'dcr-client-1';
    private const TENANT_ID = '22222222-2222-4222-8222-222222222222';
    private const PATH = '/oauth2/register/' . self::CLIENT;

    private RoutedHandler $routes;

    protected function setUp(): void
    {
        $this->routes = new RoutedHandler();
    }

    private static function uri(string $base = self::BASE_URL): string
    {
        return $base . self::PATH . '?tenant_id=' . self::TENANT_ID;
    }

    private static function token(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    }

    /**
     * @param array<string,mixed> $extra
     * @return array<string,mixed>
     */
    private static function body(array $extra = []): array
    {
        return array_merge([
            'client_id' => self::CLIENT,
            'client_id_issued_at' => 1700000000,
            'client_name' => 'Agent',
            'redirect_uris' => ['https://agent.example.test/cb'],
            'grant_types' => ['authorization_code'],
            'response_types' => ['code'],
            'token_endpoint_auth_method' => 'private_key_jwt',
            'scope' => 'openid',
            'registration_client_uri' => self::uri(),
            'jwks_uri' => 'https://agent.example.test/jwks',
        ], $extra);
    }

    private function client(string $base = self::BASE_URL, bool $retry = false): AxiamClient
    {
        return new AxiamClient(
            $base,
            'acme',
            oidcTenantId: self::TENANT_ID,
            transportHandler: $this->routes,
            retryEnabled: $retry,
        );
    }

    /** A client holding a real session: a cookie-sourced access token and a CSRF token. */
    private function clientWithSession(string $sessionToken): AxiamClient
    {
        $this->routes->on('POST', '/api/v1/auth/login', new Response(200, [
            'Set-Cookie' => ['axiam_access=' . $sessionToken . '; Path=/', 'axiam_csrf=' . self::token() . '; Path=/'],
            'Content-Type' => 'application/json',
        ], (string) json_encode(['user' => ['id' => '33333333-3333-4333-8333-333333333333']])));
        $client = $this->client();
        $client->login('admin@example.test', self::token());

        return $client;
    }

    // -- 1. Origin refusal -------------------------------------------------------------

    public function testAUriAtAnotherOriginIsRefusedLocallyAndNothingIsSent(): void
    {
        $client = $this->client();
        $token = new Sensitive(self::token());
        $refused = [
            'https://elsewhere.example.test' . self::PATH,          // another host
            self::BASE_URL . ':8443' . self::PATH,                   // another port
            'http://iam.example.test' . self::PATH,                  // http vs an https base
            'ftp://iam.example.test' . self::PATH,                   // another scheme
            self::PATH,                                              // not absolute
        ];
        foreach ($refused as $uri) {
            foreach ([
                fn () => $client->readClientRegistration($uri, $token),
                fn () => $client->deleteClientRegistration($uri, $token),
                fn () => $client->updateClientRegistration($uri, $token, ClientRegistration::fromArray(self::body())),
            ] as $call) {
                try {
                    $call();
                    self::fail('expected a local ValidationError');
                } catch (ValidationError $e) {
                    self::assertStringContainsString('§28.12.2 rule 1', $e->getMessage());
                    self::assertSame('registration_client_uri', $e->fields[0]->field);
                }
            }
        }
        self::assertSame([], $this->routes->requests, 'no request was sent');
    }

    public function testTheSameOriginIsAcceptedWithTheDefaultPortSpelledOrNot(): void
    {
        $this->routes->on('GET', self::PATH, RoutedHandler::json(200, self::body()));
        $client = $this->client('https://IAM.example.test');
        $client->readClientRegistration('https://iam.example.test:443' . self::PATH . '?tenant_id=' . self::TENANT_ID, new Sensitive(self::token()));

        self::assertCount(1, $this->routes->requests);
    }

    public function testHttpIsAllowedOnlyAgainstAnHttpLoopbackBase(): void
    {
        $this->routes->on('GET', self::PATH, RoutedHandler::json(200, self::body()));
        foreach (['http://127.0.0.1:8080', 'http://localhost:8080', 'http://[::1]:8080'] as $base) {
            $this->client($base)->readClientRegistration($base . self::PATH, new Sensitive(self::token()));
        }
        self::assertCount(3, $this->routes->requests);

        $this->expectException(ValidationError::class);
        $this->client('http://iam.internal:8080')
            ->readClientRegistration('http://iam.internal:8080' . self::PATH, new Sensitive(self::token()));
    }

    // -- 2. Header only ------------------------------------------------------------------

    public function testReadAndDeleteSendTheBearerOnlyAndKeepTheQueryVerbatim(): void
    {
        $session = self::token();
        $client = $this->clientWithSession($session);
        $this->routes->on('GET', self::PATH, RoutedHandler::json(200, self::body()));
        $this->routes->on('DELETE', self::PATH, new Response(204));
        $raw = self::token();
        $token = new Sensitive($raw);

        $read = $client->readClientRegistration(self::uri(), $token);
        self::assertSame(self::CLIENT, $read->clientId);
        self::assertNull($read->registrationAccessToken);
        $client->deleteClientRegistration(self::uri(), $token);

        $sent = array_merge($this->routes->sent('GET', self::PATH), $this->routes->sent('DELETE', self::PATH));
        self::assertCount(2, $sent);
        foreach ($sent as $request) {
            self::assertTrue($request->getHeaderLine('Authorization') === 'Bearer ' . $raw, 'the registration token is the bearer');
            self::assertSame('', $request->getHeaderLine('Cookie'), 'no session cookie');
            self::assertSame('', $request->getHeaderLine('X-CSRF-Token'), 'no CSRF token');
            self::assertFalse(str_contains($request->getHeaderLine('Authorization'), $session), 'never the SDK access token');
            self::assertSame('', (string) $request->getBody(), 'no body');
            self::assertSame('tenant_id=' . self::TENANT_ID, $request->getUri()->getQuery(), 'the URI query verbatim');
        }
    }

    public function testARedirectIsNotFollowed(): void
    {
        $this->routes->on('GET', self::PATH, new Response(302, ['Location' => 'https://elsewhere.example.test/x']));
        try {
            $this->client()->readClientRegistration(self::uri(), new Sensitive(self::token()));
            self::fail('a 302 is not a registration');
        } catch (NetworkError) {
        }
        self::assertCount(1, $this->routes->requests, 'the Location was not followed');
    }

    // -- 3. Update body ------------------------------------------------------------------

    public function testUpdateDropsTheFiveServerStatedMembersAndReturnsTheRotatedToken(): void
    {
        $rotated = self::token();
        $this->routes->on('PUT', self::PATH, RoutedHandler::json(200, self::body(['registration_access_token' => $rotated])));
        $metadata = ClientRegistration::fromArray(self::body([
            'registration_access_token' => self::token(),
            'client_secret' => self::token(),
            'client_secret_expires_at' => 0,
            'backchannel_token_delivery_mode' => 'poll',
        ]));
        $metadata->clientName = 'Agent v2';

        $updated = $this->client()->updateClientRegistration(self::uri(), new Sensitive(self::token()), $metadata);

        self::assertNotNull($updated->registrationAccessToken);
        self::assertTrue($updated->registrationAccessToken->reveal() === $rotated, 'the rotated token is returned');
        $sent = $this->routes->sent('PUT', self::PATH);
        self::assertCount(1, $sent);
        self::assertStringStartsWith('application/json', $sent[0]->getHeaderLine('Content-Type'));
        $body = json_decode((string) $sent[0]->getBody(), true);
        self::assertIsArray($body);
        foreach (ClientRegistration::SERVER_STATED_MEMBERS as $gone) {
            self::assertArrayNotHasKey($gone, $body);
        }
        self::assertSame(self::CLIENT, $body['client_id']);
        self::assertSame('Agent v2', $body['client_name']);
        self::assertSame('https://agent.example.test/jwks', $body['jwks_uri']);
        self::assertSame('poll', $body['backchannel_token_delivery_mode'], 'unknown members round-trip');
    }

    /**
     * R-23 (§28.12.2 rule 4, §34.2 P12.4): the replacement is built from what the read
     * carried. A list the read lacked is not sent — never as `[]`, which RFC 7591 does not
     * read as "the default" — and a member of an unexpected shape goes back as read.
     */
    public function testAnUpdateSendsOnlyWhatTheReadCarriedAndKeepsAnUnexpectedShapeAsRead(): void
    {
        $this->routes->on('PUT', self::PATH, RoutedHandler::json(200, self::body(['registration_access_token' => self::token()])));
        $read = self::body();
        unset($read['redirect_uris'], $read['grant_types'], $read['response_types']);
        $metadata = ClientRegistration::fromArray($read);
        $this->client()->updateClientRegistration(self::uri(), new Sensitive(self::token()), $metadata);

        $sent = json_decode((string) $this->routes->sent('PUT', self::PATH)[0]->getBody(), true);
        self::assertIsArray($sent);
        foreach (['redirect_uris', 'grant_types', 'response_types'] as $absent) {
            self::assertArrayNotHasKey($absent, $sent, $absent . ' was not in the read, so it is not sent');
        }

        // An unexpected shape is kept as read: a list with a non-string item, and a string.
        $odd = ClientRegistration::fromArray(self::body([
            'grant_types' => ['authorization_code', 7],
            'response_types' => 'code',
            'redirect_uris' => [],
        ]));
        $body = $odd->updateBody();
        self::assertSame(['authorization_code', 7], $body['grant_types']);
        self::assertSame('code', $body['response_types']);
        self::assertSame([], $body['redirect_uris'], 'an empty list the read carried goes back empty');
    }

    public function testAnUpdateAnswered503IsNotRetried(): void
    {
        $this->routes->on('PUT', self::PATH, new Response(503));
        try {
            $this->client(retry: true)->updateClientRegistration(
                self::uri(),
                new Sensitive(self::token()),
                ClientRegistration::fromArray(self::body()),
            );
            self::fail('expected a NetworkError');
        } catch (NetworkError $e) {
            self::assertNotInstanceOf(ValidationError::class, $e);
        }
        self::assertCount(1, $this->routes->requests, 'exactly one request');
    }

    public function testADeleteIsNeverRetriedAndAReadIsRetriedOnlyOnTransientFailures(): void
    {
        $this->routes->on('DELETE', self::PATH, new ConnectException('reset', new Request('DELETE', self::uri())));
        $this->routes->on('GET', self::PATH, new Response(503), RoutedHandler::json(200, self::body()));
        $client = $this->client(retry: true);
        $token = new Sensitive(self::token());

        try {
            $client->deleteClientRegistration(self::uri(), $token);
            self::fail('expected a NetworkError');
        } catch (NetworkError) {
        }
        self::assertCount(1, $this->routes->sent('DELETE', self::PATH));

        $client->readClientRegistration(self::uri(), $token);
        self::assertCount(2, $this->routes->sent('GET', self::PATH), 'the read MAY be retried per §16');
    }

    public function testAReadIsNotRetriedOnABodilessFourHundred(): void
    {
        $this->routes->on('GET', self::PATH, new Response(400));
        try {
            $this->client(retry: true)->readClientRegistration(self::uri(), new Sensitive(self::token()));
            self::fail('expected a NetworkError');
        } catch (NetworkError) {
        }
        self::assertCount(1, $this->routes->requests, 'a 4xx other than 408/429 is never retried');
    }

    // -- 4. Errors -----------------------------------------------------------------------

    public function testA401InvalidTokenIsAnOAuthProtocolErrorAndRefreshesNothing(): void
    {
        $client = $this->clientWithSession(self::token());
        $this->routes->on('POST', '/api/v1/auth/refresh', new Response(500));
        $this->routes->on('GET', self::PATH, RoutedHandler::json(
            401,
            ['error' => 'invalid_token', 'error_description' => 'no'],
            ['WWW-Authenticate' => 'Bearer error="invalid_token"'],
        ));

        try {
            $client->readClientRegistration(self::uri(), new Sensitive(self::token()));
            self::fail('expected an OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame('invalid_token', $e->error);
            self::assertInstanceOf(AuthError::class, $e);
        }
        self::assertSame([], $this->routes->sent('POST', '/api/v1/auth/refresh'), '§9 is not entered');
    }

    public function testA400InvalidClientMetadataIsAnOAuthProtocolErrorAndAMissingDescriptionIsTolerated(): void
    {
        $this->routes->on('PUT', self::PATH, RoutedHandler::json(400, ['error' => 'invalid_client_metadata']));
        try {
            $this->client()->updateClientRegistration(self::uri(), new Sensitive(self::token()), ClientRegistration::fromArray(self::body()));
            self::fail('expected an OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame('invalid_client_metadata', $e->error);
            self::assertSame('', $e->errorDescription);
        }
    }

    public function testA204OnDeleteReturnsNormallyAndAnErrorOnDeleteIsMapped(): void
    {
        $this->routes->on('DELETE', self::PATH, new Response(204), RoutedHandler::json(401, ['error' => 'invalid_token']));
        $client = $this->client();
        $client->deleteClientRegistration(self::uri(), new Sensitive(self::token()));

        $this->expectException(OAuthProtocolError::class);
        $client->deleteClientRegistration(self::uri(), new Sensitive(self::token()));
    }

    public function testAMalformedSuccessBodyIsANetworkError(): void
    {
        $this->routes->on('GET', self::PATH, new Response(200, [], 'not json'), RoutedHandler::json(200, ['client_name' => 'x']), RoutedHandler::json(200, [1, 2]));
        $client = $this->client();
        foreach ([1, 2, 3] as $_) {
            try {
                $client->readClientRegistration(self::uri(), new Sensitive(self::token()));
                self::fail('expected a NetworkError');
            } catch (NetworkError $e) {
                self::assertNotInstanceOf(ValidationError::class, $e);
            }
        }
    }

    public function testAClosedClientRefusesAllThree(): void
    {
        $client = $this->client();
        $client->close();
        foreach ([
            fn () => $client->readClientRegistration(self::uri(), new Sensitive(self::token())),
            fn () => $client->updateClientRegistration(self::uri(), new Sensitive(self::token()), ClientRegistration::fromArray(self::body())),
            fn () => $client->deleteClientRegistration(self::uri(), new Sensitive(self::token())),
        ] as $call) {
            try {
                $call();
                self::fail('expected a NetworkError');
            } catch (NetworkError) {
            }
        }
        self::assertSame([], $this->routes->requests);
    }

    // -- decoding --------------------------------------------------------------------------

    public function testDecodingKeepsUnknownAndMistypedMembersAndWrapsBothSecrets(): void
    {
        $registration = ClientRegistration::fromArray([
            'client_id' => 'c1',
            'client_secret' => self::token(),
            'registration_access_token' => self::token(),
            'backchannel_token_delivery_mode' => 'poll',
            'client_id_issued_at' => 'not-a-number',
            'client_name' => 7,
            'jwks' => 'not-an-object',
            'redirect_uris' => ['https://a', 3],
        ]);

        self::assertSame('poll', $registration->extra['backchannel_token_delivery_mode']);
        self::assertSame('not-a-number', $registration->extra['client_id_issued_at']);
        self::assertSame(7, $registration->extra['client_name']);
        self::assertSame('not-an-object', $registration->extra['jwks']);
        self::assertNull($registration->redirectUris, 'a list with a non-string item is not a list of strings');
        self::assertSame(['https://a', 3], $registration->extra['redirect_uris'], '... and is kept as read (§34.2 P12.4)');
        self::assertInstanceOf(Sensitive::class, $registration->clientSecret);
        self::assertInstanceOf(Sensitive::class, $registration->registrationAccessToken);

        $body = $registration->updateBody();
        self::assertArrayNotHasKey('client_id_issued_at', $body, 'a mistyped server-stated member is dropped too');
        self::assertSame('poll', $body['backchannel_token_delivery_mode']);
        self::assertSame(7, $body['client_name'], 'a mistyped modelled member still round-trips');
        self::assertSame(['https://a', 3], $body['redirect_uris'], 'a mistyped list goes back as read');

        $jwks = ClientRegistration::fromArray(['client_id' => 'c', 'jwks' => ['keys' => []]]);
        self::assertSame(['keys' => []], $jwks->jwks);
        self::assertSame(['keys' => []], $jwks->updateBody()['jwks']);
    }

    public function testAResponseWithoutAClientIdOrNotAnObjectIsRefused(): void
    {
        foreach ([[1, 2], ['x' => 1], ['client_id' => '']] as $wire) {
            try {
                ClientRegistration::fromArray($wire);
                self::fail('expected a NetworkError');
            } catch (NetworkError) {
            }
        }
        self::assertSame('c', ClientRegistration::fromArray(['client_id' => 'c'])->clientId);
    }

    // -- 5. Redaction ------------------------------------------------------------------

    public function testNeitherTheTokenNorTheSecretReachesAnyRendering(): void
    {
        $token = self::token();
        $secret = self::token();
        $registration = ClientRegistration::fromArray(self::body([
            'registration_access_token' => $token,
            'client_secret' => $secret,
        ]));
        $rendered = self::renderings($registration);
        self::assertNoFragment($rendered, $token);
        self::assertNoFragment($rendered, $secret);
        self::assertStringContainsString('[SENSITIVE]', (string) json_encode($registration));
        self::assertNoFragment((string) json_encode($registration->updateBody()), $token);
        self::assertNoFragment((string) json_encode($registration->updateBody()), $secret);

        $this->routes->on('GET', self::PATH, RoutedHandler::json(401, ['error' => 'invalid_token']), new Response(500));
        $client = $this->client();
        foreach ([self::uri(), self::uri(), 'https://elsewhere.example.test/r'] as $uri) {
            try {
                $client->readClientRegistration($uri, new Sensitive($token));
                self::fail('expected an error');
            } catch (\Throwable $e) {
                self::assertNoFragment(self::renderings($e), $token);
            }
        }
    }
}
