<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Opaque\OpaqueLibrary;
use Axiam\Sdk\Tests\Fakes\FakeOpaqueNative;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * `loginOpaque` / `opaqueEnrollment` end to end (CONTRACT.md §23).
 *
 * The protocol is `libaxiam_opaque_ffi`'s and the binding is covered by
 * {@see OpaqueBindingTest}. What is tested here is the part the SDK owns: what goes on the wire
 * — and, more importantly, what does *not* — which failures are {@see AuthError} and which are
 * {@see NetworkError}, and that a failed credential check never reaches `login/finish`.
 */
final class OpaqueLoginTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';
    private const USER = 'alice';

    /**
     * The hex KE2 and RegistrationResponse the fake server answers with. Hex because that is what
     * the wire carries; the binding hands them to the library verbatim and the fake library
     * echoes them back inside its own payload, which is how these tests see that nothing was
     * rewritten in between.
     */
    private const WIRE_KE2 = '6b6532';
    private const WIRE_REGISTRATION_RESPONSE = '726573703a';

    /**
     * The three paths these tests assert ABOUT rather than merely count.
     *
     * §23.4 rule 7 is as much about the request that must not happen as the one that must, and an
     * exhausted MockHandler queue only proves that *a* second request was not made.
     */
    private const OPAQUE_LOGIN_START_PATH = '/api/v1/auth/opaque/login/start';

    /** Where `KE3` would go, and must not, once the envelope has failed to open. */
    private const LOGIN_FINISH_PATH = '/api/v1/auth/opaque/login/finish';

    /** The plaintext login path §23.4 rule 7 permits only under `mode: "optional"`. */
    private const PLAINTEXT_LOGIN_PATH = '/api/v1/auth/login';

    private FakeOpaqueNative $lib;

    /** Minted per run rather than written down; nothing here depends on the value. */
    private string $password;

    /** @var list<string> the request bodies the fake server saw, in order */
    private array $bodies = [];

    /**
     * The request PATHS the fake server saw, in order.
     *
     * §23.4 rule 7 is as much about the request that must NOT happen as the one that must, and
     * an empty MockHandler queue only proves *a* second request was not made. This proves WHICH.
     *
     * @var list<string>
     */
    private array $paths = [];

    protected function setUp(): void
    {
        $this->lib = new FakeOpaqueNative();
        OpaqueLibrary::setForTests($this->lib);
        $this->password = 'correct-' . bin2hex(random_bytes(8));
        $this->bodies = [];
        $this->paths = [];
    }

    protected function tearDown(): void
    {
        OpaqueLibrary::resetForTests();
    }

    /** @param list<Response|callable|\Throwable> $queue */
    private function client(array $queue): AxiamClient
    {
        return new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            orgSlug: 'acme',
            transportHandler: new MockHandler($queue),
        );
    }

    /** Records the path and body, and answers with `$response`. */
    private function record(Response $response): callable
    {
        return function (RequestInterface $request) use ($response): Response {
            $this->paths[] = $request->getUri()->getPath();
            $this->bodies[] = (string) $request->getBody();

            return $response;
        };
    }

    private static function json(int $status, string $body): Response
    {
        return new Response($status, ['Content-Type' => 'application/json'], $body);
    }

    private static function ksfFields(string $ksf = 'argon2id'): string
    {
        return $ksf === 'scrypt'
            ? '"ksf":"scrypt","log_n":15,"r":8,"p":1'
            : '"ksf":"' . $ksf . '","memory_kib":19456,"iterations":2,"parallelism":1';
    }

    /**
     * `$mode` is `null` by default — the field is optional on the wire and a server older than
     * contract 1.29 omits it entirely, which §23.4 rule 7 treats exactly as `required`.
     */
    private static function loginStart(
        string $ksf = 'argon2id',
        bool $withKe2 = true,
        ?string $mode = null,
    ): Response {
        $ke2 = $withKe2 ? '"ke2":"' . self::WIRE_KE2 . '",' : '';
        $modeField = $mode === null ? '' : '"mode":"' . $mode . '",';

        return self::json(
            200,
            '{"opaque_session":"handle-42",' . $ke2 . $modeField . self::ksfFields($ksf) . '}'
        );
    }

    private static function registerStart(string $ksf = 'argon2id'): Response
    {
        return self::json(200, '{"opaque_session":"reg-handle","registration_response":"'
            . self::WIRE_REGISTRATION_RESPONSE . '",' . self::ksfFields($ksf) . '}');
    }

    /**
     * A 200 `LoginSuccessResponse`.
     *
     * `user.id` is not decoration: `handleLoginResponse()` refuses a 200 without
     * it as a malformed body, which is the same shape `login()` returns and the
     * whole point of §23's same-result-type requirement.
     */
    private static function loginOk(): Response
    {
        return self::json(200, '{"user":{"id":"11111111-1111-1111-1111-111111111111"},'
            . '"session_id":"55555555-5555-5555-5555-555555555555","expires_in":900}');
    }

    /** @return array<string, mixed> */
    private function decodedBody(int $index): array
    {
        $decoded = json_decode($this->bodies[$index], true);
        self::assertIsArray($decoded);

        /** @var array<string, mixed> $decoded */
        return $decoded;
    }

    // -----------------------------------------------------------------
    // What crosses the wire
    // -----------------------------------------------------------------

    public function testLoginStartCarriesKe1AndNoPasswordField(): void
    {
        $client = $this->client([
            $this->record(self::loginStart()),
            $this->record(self::loginOk()),
        ]);

        $client->loginOpaque(self::USER, $this->password);

        $body = $this->decodedBody(0);
        // The entire point of the exchange. A body that still carried a password
        // would be SRP's failure mode with extra steps.
        self::assertArrayNotHasKey('password', $body);
        self::assertSame(self::USER, $body['username_or_email']);
        self::assertSame(self::TENANT, $body['tenant_slug']);
        self::assertSame(
            'ke1:' . $this->password,
            FakeOpaqueNative::decode((string) $body['ke1'])
        );
    }

    public function testRegisterStartNamesNoAccountAtAll(): void
    {
        $client = $this->client([$this->record(self::registerStart())]);

        $enrollment = $client->opaqueEnrollment($this->password);

        self::assertSame('reg-handle', $enrollment->opaqueSession);
        self::assertStringStartsWith(
            \sprintf('record:%s:%s:', $this->password, self::WIRE_REGISTRATION_RESPONSE),
            FakeOpaqueNative::decode($enrollment->registrationRecord)
        );

        $body = $this->decodedBody(0);
        self::assertArrayNotHasKey('password', $body);
        // No username either: a record binds to a credential identifier the server
        // chooses, which is why a later rename cannot invalidate one.
        self::assertArrayNotHasKey('username_or_email', $body);
        self::assertSame(self::TENANT, $body['tenant_slug']);
        self::assertSame(
            'req:' . $this->password,
            FakeOpaqueNative::decode((string) $body['registration_request'])
        );
    }

    public function testLoginFinishEchoesTheSessionHandleTheServerIssued(): void
    {
        $client = $this->client([
            $this->record(self::loginStart()),
            $this->record(self::loginOk()),
        ]);

        $client->loginOpaque(self::USER, $this->password);

        $body = $this->decodedBody(1);
        self::assertSame('handle-42', $body['opaque_session']);
        self::assertStringStartsWith(
            \sprintf('ke3:%s:%s:', $this->password, self::WIRE_KE2),
            FakeOpaqueNative::decode((string) $body['ke3'])
        );
    }

    public function testTheServerNamedKsfIsTheOneUsed(): void
    {
        // §23.4 rule 2: never local defaults. A credential enrolled under one cost
        // keeps working after a tenant raises its policy, so a client that guessed
        // would fail against a record that is perfectly good.
        $client = $this->client([
            $this->record(self::loginStart('scrypt')),
            $this->record(self::loginOk()),
        ]);

        $client->loginOpaque(self::USER, $this->password);

        // The fake encodes the handle it was given; scrypt handles start 0xb.
        self::assertStringEndsWith(
            ':' . dechex(0xB0000 + 15 + 8 + 1),
            FakeOpaqueNative::decode((string) $this->decodedBody(1)['ke3'])
        );
    }

    // -----------------------------------------------------------------
    // Results
    // -----------------------------------------------------------------

    public function testASuccessfulLoginReturnsWhatLoginReturns(): void
    {
        $client = $this->client([self::loginStart(), self::loginOk()]);

        self::assertTrue($client->opaqueAvailable());
        $result = $client->loginOpaque(self::USER, $this->password);

        self::assertFalse($result->mfaRequired);
        self::assertSame('11111111-1111-1111-1111-111111111111', $result->userId);
        self::assertSame(self::TENANT, $result->tenantId);
    }

    public function testTheMfaRequiredBranchSurvivesTheOpaquePath(): void
    {
        // One result handler must serve both login paths, so the second phase has
        // to arrive here exactly as it does from login().
        $client = $this->client([
            self::loginStart(),
            self::json(202, '{"challenge_token":"mfa-challenge","available_methods":["totp"]}'),
        ]);

        $result = $client->loginOpaque(self::USER, $this->password);

        self::assertTrue($result->mfaRequired);
        self::assertNotNull($result->challengeToken);
    }

    // -----------------------------------------------------------------
    // Failures -- which exception, and why it matters
    // -----------------------------------------------------------------

    public function testADisabledTenantIsANetworkErrorACallerCanFallBackFrom(): void
    {
        // A 404 is a property of the tenant, not of the credentials. As an
        // AuthError it would be shown as "invalid password" and send a user to
        // reset a working one, while stopping a fallback to login().
        //
        // The queue holds ONE response: a second request would exhaust MockHandler
        // and fail loudly, which is how this asserts nothing reaches login/finish.
        $client = $this->client([new Response(404)]);

        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/opaque_mode is disabled/');
        $client->loginOpaque(self::USER, $this->password);
    }

    public function testEnrolmentReportsADisabledTenantTheSameWay(): void
    {
        $client = $this->client([new Response(404)]);

        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/opaque_mode is disabled/');
        $client->opaqueEnrollment($this->password);
    }

    public function testA401AtLoginStartIsAnAuthError(): void
    {
        $client = $this->client([new Response(401)]);

        $this->expectException(AuthError::class);
        $client->loginOpaque(self::USER, $this->password);
    }

    public function testAWrongPasswordNeverReachesLoginFinish(): void
    {
        // §23.4 rule 7. The envelope failing to open IS the authentication check;
        // sending anything afterwards would ask the server to decide something the
        // client has already decided. One response in the queue, so a second
        // request would fail the test rather than pass silently.
        $this->lib->fail('login_finish');
        $client = $this->client([self::loginStart()]);

        $this->expectException(AuthError::class);
        $client->loginOpaque(self::USER, $this->password);
    }

    public function testAnUnsupportedKsfIsAConfigurationErrorNotABadPassword(): void
    {
        $client = $this->client([self::loginStart('bcrypt')]);

        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/bcrypt/');
        $client->loginOpaque(self::USER, $this->password);
    }

    public function testAStartResponseWithoutKe2IsAMalformedResponse(): void
    {
        $client = $this->client([self::loginStart('argon2id', withKe2: false)]);

        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/no `ke2`/');
        $client->loginOpaque(self::USER, $this->password);
    }

    public function testA5xxAtLoginFinishIsANetworkError(): void
    {
        $client = $this->client([self::loginStart(), new Response(503)]);

        $this->expectException(NetworkError::class);
        $client->loginOpaque(self::USER, $this->password);
    }

    public function testAnAbsentLibraryIsReportedBeforeAnyRequestIsSent(): void
    {
        OpaqueLibrary::setForTests(null);
        // An empty queue: any request at all would exhaust MockHandler.
        $client = $this->client([]);

        self::assertFalse($client->opaqueAvailable());

        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/libaxiam_opaque_ffi/');
        $client->loginOpaque(self::USER, $this->password);
    }

    public function testAnExchangeIsReleasedWhenTheServerNamesAKsfThisSdkRefuses(): void
    {
        // The refusal happens after start, so the exchange is abandoned rather
        // than spent -- and loginOpaque's finally must release it. Without that,
        // a misconfigured tenant leaks a Rust allocation once per login attempt.
        $client = $this->client([self::loginStart('bcrypt')]);

        try {
            $client->loginOpaque(self::USER, $this->password);
            self::fail('expected a NetworkError');
        } catch (NetworkError) {
            // expected
        }

        self::assertSame(0, $this->lib->statesAlive());
    }

    // -----------------------------------------------------------------
    // §23.4 rule 7 -- what a failed KE2 does next, and only `mode` decides
    // -----------------------------------------------------------------

    public function testOptionalRetriesOverPlaintextLoginAndReturnsItsSuccess(): void
    {
        // The migration case, and the reason the clause exists: every account has
        // no registration record the moment an operator enables OPAQUE, so under
        // `optional` a failed exchange is the ordinary case. Treating it as final
        // would lock out the whole tenant.
        $this->lib->fail('login_finish');
        $client = $this->client([
            $this->record(self::loginStart(mode: 'optional')),
            $this->record(self::loginOk()),
        ]);

        $result = $client->loginOpaque(self::USER, $this->password);

        self::assertFalse($result->mfaRequired);
        self::assertSame('11111111-1111-1111-1111-111111111111', $result->userId);

        // The retry is the SDK's OWN plaintext path, not a second hand-rolled call.
        self::assertSame(self::PLAINTEXT_LOGIN_PATH, $this->paths[1]);
        $body = $this->decodedBody(1);
        self::assertSame(self::USER, $body['username_or_email']);
        self::assertSame($this->password, $body['password']);
        self::assertSame(self::TENANT, $body['tenant_slug']);

        // KE3 is never sent, whatever happens afterwards.
        self::assertNotContains(self::LOGIN_FINISH_PATH, $this->paths);
        self::assertArrayNotHasKey('ke3', $body);
    }

    public function testOptionalSurfacesThePlaintextRetrysFailureRatherThanTheExchanges(): void
    {
        // The retry's outcome IS the call's outcome, in both directions. A 401
        // there is the ordinary authentication error a caller already handles.
        $this->lib->fail('login_finish');
        $client = $this->client([
            $this->record(self::loginStart(mode: 'optional')),
            $this->record(new Response(401)),
        ]);

        try {
            $client->loginOpaque(self::USER, $this->password);
            self::fail('expected an AuthError');
        } catch (AuthError) {
            // expected
        }

        self::assertSame(self::PLAINTEXT_LOGIN_PATH, $this->paths[1]);
        self::assertNotContains(self::LOGIN_FINISH_PATH, $this->paths);
    }

    public function testRequiredNeverPutsThePlaintextPasswordOnTheWire(): void
    {
        // `required` answers 403 opaque_required for EVERY principal in the tenant,
        // before any credential is examined -- so a retry would be refused anyway,
        // having sent the password for nothing.
        $this->lib->fail('login_finish');
        $client = $this->client([$this->record(self::loginStart(mode: 'required'))]);

        try {
            $client->loginOpaque(self::USER, $this->password);
            self::fail('expected an AuthError');
        } catch (AuthError) {
            // expected
        }

        self::assertSame([self::OPAQUE_LOGIN_START_PATH], $this->paths);
        self::assertNotContains(self::PLAINTEXT_LOGIN_PATH, $this->paths);
        self::assertNotContains(self::LOGIN_FINISH_PATH, $this->paths);
    }

    public function testAResponseWithNoModeFieldBehavesExactlyLikeRequired(): void
    {
        // A server older than contract 1.29 says nothing here. Silence is not
        // permission: this fails closed, as it did before the field existed.
        $this->lib->fail('login_finish');
        $client = $this->client([$this->record(self::loginStart())]);

        try {
            $client->loginOpaque(self::USER, $this->password);
            self::fail('expected an AuthError');
        } catch (AuthError) {
            // expected
        }

        self::assertSame([self::OPAQUE_LOGIN_START_PATH], $this->paths);
        self::assertNotContains(self::PLAINTEXT_LOGIN_PATH, $this->paths);
        self::assertNotContains(self::LOGIN_FINISH_PATH, $this->paths);
    }

    public function testAnUnrecognisedModeFailsClosed(): void
    {
        // `mode` is not downgrade protection -- a hostile server wanting the
        // plaintext would answer 404 -- but a value this SDK does not understand
        // still gets the conservative branch rather than the permissive one.
        $this->lib->fail('login_finish');
        $client = $this->client([$this->record(self::loginStart(mode: 'lenient'))]);

        try {
            $client->loginOpaque(self::USER, $this->password);
            self::fail('expected an AuthError');
        } catch (AuthError) {
            // expected
        }

        self::assertSame([self::OPAQUE_LOGIN_START_PATH], $this->paths);
        self::assertNotContains(self::PLAINTEXT_LOGIN_PATH, $this->paths);
    }

    public function testTheExchangeIsReleasedOnThePlaintextFallbackPath(): void
    {
        // The fallback leaves the try block by a different route than a spent
        // handle does; the finally still has to have run.
        $this->lib->fail('login_finish');
        $client = $this->client([
            $this->record(self::loginStart(mode: 'optional')),
            $this->record(self::loginOk()),
        ]);

        $client->loginOpaque(self::USER, $this->password);

        self::assertSame(0, $this->lib->statesAlive());
    }
}
