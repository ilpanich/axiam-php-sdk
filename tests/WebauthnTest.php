<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Webauthn\WebauthnChallenge;
use Axiam\Sdk\Webauthn\WebauthnFailure;
use Axiam\Sdk\Webauthn\WebauthnWorkspace;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * CONTRACT.md §24 — the WebAuthn relying-party layer and the §24.6a JSON bridge.
 *
 * Two assertions are worth reading twice:
 *
 * - `testRegisterStart503IsNotRetried` asserts on the **request count**, not the exception
 *   type, because §24.4 rule 2 regresses the moment someone tidies a retry predicate — and a
 *   type assertion would still pass.
 * - `testStateTokenIsNeverParsed` hands the SDK a state token that is not a JWT at all. If
 *   anything decoded one, this is where it would fail.
 */
final class WebauthnTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';
    private const ORG_SLUG = 'globex';
    private const STATE_TOKEN = 'state-token-fixture-value-do-not-log';
    private const CHALLENGE_TOKEN = 'challenge-token-fixture-do-not-log';
    private const ACCESS_TOKEN = 'access-token-fixture-do-not-log';
    private const REFRESH_TOKEN = 'refresh-token-fixture-do-not-log';

    /**
     * Deliberately "unusual but valid": every optional field populated, so the pass-through
     * assertion has something to catch an over-eager implementation dropping. A minimal
     * fixture would prove nothing.
     */
    private const CREATION_CHALLENGE = <<<'JSON'
        {"publicKey":{
          "challenge":"Y2hhbGxlbmdlLWJ5dGVz",
          "rp":{"id":"axiam.test","name":"AXIAM Test"},
          "user":{"id":"dXNlci1oYW5kbGU","name":"alice","displayName":"Alice"},
          "pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-8},
                              {"type":"public-key","alg":-257}],
          "timeout":60000,
          "excludeCredentials":[{"id":"ZXhpc3Rpbmc","type":"public-key","transports":["usb","nfc"]}],
          "authenticatorSelection":{"residentKey":"required","requireResidentKey":true,
                                    "userVerification":"required"},
          "attestation":"direct",
          "extensions":{"credProps":true}
        }}
        JSON;

    private const MINIMAL_CREATION_CHALLENGE = <<<'JSON'
        {"publicKey":{
          "challenge":"bWluaW1hbA",
          "rp":{"name":"AXIAM Test"},
          "user":{"id":"dQ","name":"bob","displayName":"Bob"},
          "pubKeyCredParams":[{"type":"public-key","alg":-7}]
        }}
        JSON;

    private const DISCOVERABLE_CHALLENGE = <<<'JSON'
        {"publicKey":{"challenge":"ZGlzY292ZXJhYmxl","rpId":"axiam.test",
         "allowCredentials":[],"userVerification":"required"}}
        JSON;

    /** Carries an unknown key the SDK must forward rather than strip. */
    private const REGISTRATION_RESPONSE = <<<'JSON'
        {"id":"bmV3LWNyZWQ","rawId":"bmV3LWNyZWQ",
         "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0",
                     "attestationObject":"o2NmbXRkbm9uZQ",
                     "transports":["internal"],
                     "vendorSpecific":"must-survive"},
         "type":"public-key","clientExtensionResults":{"credProps":{"rk":true}}}
        JSON;

    private const AUTHENTICATION_RESPONSE = <<<'JSON'
        {"id":"bmV3LWNyZWQ","rawId":"bmV3LWNyZWQ",
         "response":{"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0",
                     "authenticatorData":"YXV0aC1kYXRh","signature":"c2ln",
                     "userHandle":"dXNlci1oYW5kbGU"},
         "type":"public-key","clientExtensionResults":{}}
        JSON;

    /** @var list<RequestInterface> */
    private array $sent = [];

    /**
     * @param array<int,Response|\Throwable> $queue
     *
     * Captures every request that reaches the transport into {@see self::$sent} — the
     * pattern the rest of this suite uses, since Guzzle's `Middleware::history()` cannot
     * be injected through AxiamClient's own internal HandlerStack construction.
     */
    private function client(array $queue, ?string $orgSlug = self::ORG_SLUG, ?string $orgId = null): AxiamClient
    {
        $this->sent = [];
        $mock = new MockHandler($queue);
        $captured = &$this->sent;
        $transportHandler = static function (RequestInterface $request, array $options) use ($mock, &$captured) {
            $captured[] = $request;

            return $mock($request, $options);
        };

        return new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            orgSlug: $orgSlug,
            orgId: $orgId,
            transportHandler: $transportHandler,
        );
    }

    /** @param array<string,mixed> $claims */
    private function unsignedJwt(array $claims): string
    {
        $segment = static fn (array $data): string => rtrim(
            strtr(base64_encode((string) json_encode($data)), '+/', '-_'),
            '=',
        );

        return $segment(['alg' => 'none', 'typ' => 'JWT']) . '.' . $segment($claims) . '.signature';
    }

    /** A login 200 that seeds the access cookie — what the SDK reads as "signed in" (§24.1). */
    private function signInResponse(): Response
    {
        return new Response(
            200,
            [
                'Set-Cookie' => 'axiam_access=' . $this->unsignedJwt([
                    'sub' => 'user-1',
                    'tenant_id' => '22222222-2222-2222-2222-222222222222',
                    'jti' => 'session-1',
                    'exp' => time() + 900,
                ]) . '; Path=/',
                'X-CSRF-Token' => 'csrf-abc',
            ],
            (string) json_encode(['user' => ['id' => 'user-1']]),
        );
    }

    private function challengeResponse(string $challenge, string $stateToken = self::STATE_TOKEN): Response
    {
        return new Response(
            200,
            ['Content-Type' => 'application/json'],
            '{"challenge":' . $challenge . ',"state_token":"' . $stateToken . '"}',
        );
    }

    private function credentialResponse(): Response
    {
        return new Response(201, ['Content-Type' => 'application/json'], (string) json_encode([
            'id' => 'cred-uuid-1',
            'credential_id' => 'bmV3LWNyZWQ',
            'name' => "Alice's laptop",
            'credential_type' => 'passkey',
            'created_at' => '2026-08-22T10:00:00Z',
        ]));
    }

    private function webauthnLoginResponse(): Response
    {
        return new Response(
            200,
            ['Content-Type' => 'application/json', 'X-CSRF-Token' => 'csrf-abc'],
            (string) json_encode([
                'access_token' => self::ACCESS_TOKEN,
                'refresh_token' => self::REFRESH_TOKEN,
                'session_id' => 'session-uuid-1',
                'expires_in' => 900,
            ]),
        );
    }

    /** @return array<string,mixed> */
    private function bodyOf(int $index): array
    {
        $decoded = json_decode($this->rawBodyOf($index), true);
        self::assertIsArray($decoded);

        return $decoded;
    }

    private function rawBodyOf(int $index): string
    {
        return (string) $this->sent[$index]->getBody();
    }

    // -----------------------------------------------------------------------
    // §24.0 — options and responses pass through untouched
    // -----------------------------------------------------------------------

    public function testOptionsPassThroughStructurallyUnchanged(): void
    {
        $client = $this->client([$this->signInResponse(), $this->challengeResponse(self::CREATION_CHALLENGE)]);
        $client->login('alice@example.com', 'pw');

        $challenge = $client->webauthnRegisterStart();

        // Structural equality, not a spot-check of three fields: the failure mode this
        // guards is an SDK that quietly drops the one option it did not recognise.
        self::assertSame(json_decode(self::CREATION_CHALLENGE, true), $challenge->challenge);
    }

    public function testSynthesizesNoFieldTheServerOmitted(): void
    {
        $client = $this->client([$this->signInResponse(), $this->challengeResponse(self::MINIMAL_CREATION_CHALLENGE)]);
        $client->login('alice@example.com', 'pw');

        $options = $client->webauthnRegisterStart()->challenge['publicKey'];

        self::assertArrayNotHasKey('authenticatorSelection', $options, 'the SDK must not invent a selection');
        self::assertArrayNotHasKey('timeout', $options, 'the SDK must not invent a timeout');
        self::assertArrayNotHasKey('attestation', $options, 'the SDK must not invent a conveyance');
    }

    public function testAuthenticatorResponseReachesTheWireByteForByte(): void
    {
        $client = $this->client([$this->signInResponse(), $this->credentialResponse()]);
        $client->login('alice@example.com', 'pw');

        $client->webauthnRegisterFinish(new Sensitive(self::STATE_TOKEN), "Alice's laptop", self::REGISTRATION_RESPONSE);

        // The literal substring, not a parsed comparison: this is the assertion that catches
        // a re-encode (§24.0), which a structural comparison would happily pass.
        $body = $this->rawBodyOf(1);
        self::assertStringContainsString(trim(self::REGISTRATION_RESPONSE), $body);
        self::assertStringContainsString('must-survive', $body);
    }

    // -----------------------------------------------------------------------
    // §24.1 — register requires a session
    // -----------------------------------------------------------------------

    public function testRegisterWithoutASessionMakesZeroWireCalls(): void
    {
        $client = $this->client([]);

        try {
            $client->webauthnRegisterStart();
            self::fail('expected AuthError');
        } catch (AuthError) {
            // expected
        }

        try {
            $client->webauthnRegisterFinish(new Sensitive(self::STATE_TOKEN), 'k', self::REGISTRATION_RESPONSE);
            self::fail('expected AuthError');
        } catch (AuthError) {
            // expected
        }

        // Asserted on the transport, not the exception type: §24.1 requires the refusal to
        // be client-side.
        self::assertCount(0, $this->sent);
    }

    public function testRegisterFinishReturnsTheCredential(): void
    {
        $client = $this->client([$this->signInResponse(), $this->credentialResponse()]);
        $client->login('alice@example.com', 'pw');

        $credential = $client->webauthnRegisterFinish(
            new Sensitive(self::STATE_TOKEN),
            "Alice's laptop",
            self::REGISTRATION_RESPONSE,
        );

        self::assertSame('bmV3LWNyZWQ', $credential->credentialId);
        self::assertSame('passkey', $credential->credentialType);
        self::assertNull($credential->lastUsedAt, 'a never-used credential has no lastUsedAt');
    }

    // -----------------------------------------------------------------------
    // §24.2 — two ceremonies, not one with a flag
    // -----------------------------------------------------------------------

    public function testAuthenticateStartSendsTheChallengeToken(): void
    {
        $client = $this->client([$this->challengeResponse(self::DISCOVERABLE_CHALLENGE)]);

        $client->webauthnAuthenticateStart(new Sensitive(self::CHALLENGE_TOKEN));

        self::assertSame(
            '/api/v1/auth/webauthn/authenticate/start',
            $this->sent[0]->getUri()->getPath(),
        );
        self::assertSame(self::CHALLENGE_TOKEN, $this->bodyOf(0)['challenge_token']);
    }

    public function testDiscoverableStartSendsAWorkspaceAndNoChallengeToken(): void
    {
        $client = $this->client([$this->challengeResponse(self::DISCOVERABLE_CHALLENGE)]);

        $client->webauthnDiscoverableStart();

        $body = $this->bodyOf(0);
        self::assertArrayNotHasKey(
            'challenge_token',
            $body,
            'merging the two ceremonies reproduces a bug the server already fixed (§24.2)',
        );
        // §24.1: unlike the /oauth2 endpoints this one accepts slugs, and the SDK fills
        // the workspace from its own configuration.
        self::assertSame(self::ORG_SLUG, $body['org_slug']);
        self::assertSame(self::TENANT, $body['tenant_slug']);
    }

    public function testExplicitWorkspaceOverridesTheClientConfiguration(): void
    {
        $client = $this->client([$this->challengeResponse(self::DISCOVERABLE_CHALLENGE)]);

        $client->webauthnDiscoverableStart(new WebauthnWorkspace(
            orgSlug: 'other-org',
            tenantId: '22222222-2222-2222-2222-222222222222',
        ));

        $body = $this->bodyOf(0);
        self::assertSame('other-org', $body['org_slug']);
        self::assertSame('22222222-2222-2222-2222-222222222222', $body['tenant_id']);
        self::assertArrayNotHasKey('tenant_slug', $body, 'a resolved tenant_id makes tenant_slug ambiguous');
    }

    public function testAClientWithNoOrganizationCannotStartADiscoverableCeremony(): void
    {
        $client = $this->client([], orgSlug: null);

        $this->expectException(AuthError::class);
        $client->webauthnDiscoverableStart();
    }

    // -----------------------------------------------------------------------
    // §24.3 — credential adoption
    // -----------------------------------------------------------------------

    public function testACompletedCeremonyReturnsTheSession(): void
    {
        $client = $this->client([$this->webauthnLoginResponse()]);

        $result = $client->webauthnDiscoverableFinish(new Sensitive(self::STATE_TOKEN), self::AUTHENTICATION_RESPONSE);

        self::assertSame(900, $result->expiresIn);
        self::assertSame('session-uuid-1', $result->sessionId);
        self::assertSame(self::ACCESS_TOKEN, $result->accessToken->reveal());
    }

    // -----------------------------------------------------------------------
    // §24.4 — the two error rows that are not the §2 defaults
    // -----------------------------------------------------------------------

    public function testRegisterStart503IsNotRetried(): void
    {
        $client = $this->client([
            $this->signInResponse(),
            new Response(503, ['Content-Type' => 'application/json'], '{"message":"FIDO metadata unavailable"}'),
        ]);
        $client->login('alice@example.com', 'pw');
        $before = count($this->sent);

        try {
            $client->webauthnRegisterStart();
            self::fail('expected a failure');
        } catch (\Throwable) {
            // expected
        }

        // §24.4 rule 2, asserted on the request count: a 503 here is a server CONFIGURATION
        // state, retrying changes nothing, and this regresses silently the moment the retry
        // predicate is tidied.
        self::assertSame(1, count($this->sent) - $before, 'the 503 must not be retried');
    }

    public function testRegisterFinish403KeepsTheAttestationPolicyMessage(): void
    {
        $client = $this->client([
            $this->signInResponse(),
            new Response(403, ['Content-Type' => 'application/json'], '{"message":"this security key is not FIDO certified"}'),
        ]);
        $client->login('alice@example.com', 'pw');

        try {
            $client->webauthnRegisterFinish(new Sensitive(self::STATE_TOKEN), 'key', self::REGISTRATION_RESPONSE);
            self::fail('expected AuthzError');
        } catch (AuthzError $e) {
            // §24.4 rule 1: the policy message is the only way the person holding the key
            // learns a different one would work.
            self::assertStringContainsString('FIDO certified', $e->getMessage());
        }
    }

    public function testAFailedAssertionIsAnAuthError(): void
    {
        $client = $this->client([new Response(401, ['Content-Type' => 'application/json'], '{"message":"assertion failed"}')]);

        $this->expectException(AuthError::class);
        $client->webauthnDiscoverableFinish(new Sensitive(self::STATE_TOKEN), self::AUTHENTICATION_RESPONSE);
    }

    // -----------------------------------------------------------------------
    // §24.5 — opaque and sensitive
    // -----------------------------------------------------------------------

    public function testStateTokenIsNeverParsed(): void
    {
        // Not a JWT, not base64, not three dot-separated parts. If anything decoded it,
        // this round trip would not survive.
        $nonsense = '-----definitely not a jwt-----';
        $client = $this->client([
            $this->challengeResponse(self::DISCOVERABLE_CHALLENGE, $nonsense),
            $this->webauthnLoginResponse(),
        ]);

        $challenge = $client->webauthnDiscoverableStart();
        self::assertSame($nonsense, $challenge->stateToken->reveal());

        $client->webauthnDiscoverableFinish($challenge->stateToken, self::AUTHENTICATION_RESPONSE);

        self::assertSame($nonsense, $this->bodyOf(1)['state_token']);
    }

    public function testNoFixtureTokenAppearsInARenderedValue(): void
    {
        $client = $this->client([
            $this->signInResponse(),
            $this->challengeResponse(self::CREATION_CHALLENGE),
            $this->webauthnLoginResponse(),
        ]);
        $client->login('alice@example.com', 'pw');

        $challenge = $client->webauthnRegisterStart();
        self::assertStringNotContainsString(self::STATE_TOKEN, print_r($challenge->stateToken, true));
        self::assertStringNotContainsString(self::STATE_TOKEN, var_export($challenge->stateToken, true));

        $login = $client->webauthnDiscoverableFinish(new Sensitive(self::STATE_TOKEN), self::AUTHENTICATION_RESPONSE);
        self::assertStringNotContainsString(self::ACCESS_TOKEN, print_r($login->accessToken, true));
        self::assertStringNotContainsString(self::REFRESH_TOKEN, print_r($login->refreshToken, true));
    }

    // -----------------------------------------------------------------------
    // §24.6a — the JSON bridge
    // -----------------------------------------------------------------------

    public function testRequestJsonRoundTripsAndDropsThePublicKeyWrapper(): void
    {
        $client = $this->client([$this->signInResponse(), $this->challengeResponse(self::CREATION_CHALLENGE)]);
        $client->login('alice@example.com', 'pw');

        $challenge = $client->webauthnRegisterStart();
        $parsed = json_decode($challenge->requestJson(), true);

        // The inner options object: the publicKey wrapper belongs to the DOM's
        // CredentialCreationOptions, and the platform JSON APIs — the very ones this
        // accessor exists for — do not want it.
        self::assertArrayNotHasKey('publicKey', $parsed);
        self::assertSame(json_decode(self::CREATION_CHALLENGE, true)['publicKey'], $parsed);
        self::assertSame('direct', $parsed['attestation']);
        self::assertSame(60000, $parsed['timeout']);
    }

    public function testAResponseThatIsNotAJsonObjectIsRefusedBeforeTheWire(): void
    {
        $client = $this->client([]);

        try {
            $client->webauthnDiscoverableFinish(new Sensitive(self::STATE_TOKEN), 'not json at all');
            self::fail('expected AuthError');
        } catch (AuthError) {
            // expected
        }

        try {
            $client->webauthnDiscoverableFinish(new Sensitive(self::STATE_TOKEN), '["an","array"]');
            self::fail('expected AuthError');
        } catch (AuthError) {
            // expected
        }

        self::assertCount(0, $this->sent, 'the SDK must not POST a body it cannot verify');
    }

    public function testTheErrorClassificationIsReachableWithoutALinkedApi(): void
    {
        // §24.6b rule 5, required of this SDK too: the browser half of a PHP relying party
        // relays a DOMException name and has the same five outcomes.
        self::assertSame(WebauthnFailure::Cancelled, WebauthnFailure::classify('NotAllowedError'));
        self::assertSame(WebauthnFailure::AlreadyRegistered, WebauthnFailure::classify('InvalidStateError'));
        self::assertSame(WebauthnFailure::Timeout, WebauthnFailure::classify('AbortError'));
        self::assertSame(WebauthnFailure::Unsupported, WebauthnFailure::classify('NotSupportedError'));
        self::assertSame(WebauthnFailure::Unsupported, WebauthnFailure::classify('SecurityError'));
        self::assertSame(WebauthnFailure::Unknown, WebauthnFailure::classify('SomethingElseError'));
        self::assertSame(WebauthnFailure::Unknown, WebauthnFailure::classify(null));

        // ASAuthorizationError.canceled spells it with one L.
        self::assertSame(WebauthnFailure::Cancelled, WebauthnFailure::classify('canceled'));
    }

    public function testAlreadyRegisteredIsDistinguishableFromCancelled(): void
    {
        self::assertNotSame(
            WebauthnFailure::classify('InvalidStateError'),
            WebauthnFailure::classify('NotAllowedError'),
        );

        // The only classification whose remedy is "use a different device".
        self::assertStringContainsString('different device', WebauthnFailure::AlreadyRegistered->message());
        // And the one that must not accuse the user: it also covers a silent timeout,
        // which the spec refuses to distinguish.
        self::assertStringContainsString('cancelled or timed out', WebauthnFailure::Cancelled->message());
    }
}
