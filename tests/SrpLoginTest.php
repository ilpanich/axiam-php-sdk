<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Auth\LoginResult;
use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Srp\BcMathBackend;
use Axiam\Sdk\Srp\BigIntBackend;
use Axiam\Sdk\Srp\GmpBackend;
use Axiam\Sdk\Srp\Srp;
use Axiam\Sdk\Srp\SrpGroup;
use Axiam\Sdk\Srp\SrpKdfParams;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * `loginSrp` end-to-end against a fake server that performs REAL SRP arithmetic
 * (CONTRACT.md §23.7 rules 5, 7 and 8).
 *
 * A fake that echoed canned values would pass whatever the client computed. This one holds a
 * verifier, derives its own `S` from it and answers with the `M2` that follows — so a client that
 * gets `u`, `PAD()` or the identity wrong fails here rather than in production.
 *
 * `MockHandler` accepts callables that receive the outgoing request, which is what lets the verify
 * response depend on the `A` the client actually chose.
 */
final class SrpLoginTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';
    private const IDENTITY = 'alice';
    private const PASSWORD = 'correct horse battery staple';

    private function backendOrSkip(): BigIntBackend
    {
        if (GmpBackend::isAvailable()) {
            return new GmpBackend();
        }
        if (BcMathBackend::isAvailable()) {
            return new BcMathBackend();
        }
        // Not a silent pass: PHP is §23.8's one conditional SDK, and a suite that quietly tested
        // no arithmetic would look identical to one that tested it correctly.
        self::markTestSkipped('neither ext-gmp nor ext-bcmath is loaded (CONTRACT.md §23.8)');
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

    /** The two-request happy-path queue against a live fake. */
    private function exchangeQueue(FakeSrpServer $server): array
    {
        return [
            static fn (RequestInterface $r): Response => $server->challenge((string) $r->getBody()),
            static fn (RequestInterface $r): Response => $server->verify((string) $r->getBody()),
        ];
    }

    // -----------------------------------------------------------------------

    /**
     * The happy path against real arithmetic on both sides: the client's `M1` satisfies a server
     * that only ever held a verifier, and the server's `M2` satisfies the client.
     */
    public function testLoginSrpEstablishesASessionAgainstAServerThatOnlyHoldsAVerifier(): void
    {
        $server = new FakeSrpServer($this->backendOrSkip(), SrpGroup::DEFAULT_WIRE_NAME);
        $client = $this->client($this->exchangeQueue($server));

        $result = $client->loginSrp(self::IDENTITY, self::PASSWORD);

        self::assertFalse($result->mfaRequired);
        self::assertNull($result->challengeToken);
        self::assertSame('user-1', $result->userId);
    }

    /**
     * §23.1's hard requirement that both login paths return the same result type: an application
     * switching a tenant to SRP must not need a second result handler.
     */
    public function testLoginSrpReturnsTheSameMfaBranchAsLogin(): void
    {
        $server = new FakeSrpServer($this->backendOrSkip(), SrpGroup::DEFAULT_WIRE_NAME);
        $server->mfaRequired = true;
        $client = $this->client($this->exchangeQueue($server));

        $result = $client->loginSrp(self::IDENTITY, self::PASSWORD);

        self::assertTrue($result->mfaRequired, 'a 202 must surface as mfaRequired, not as an exception');
        self::assertNotNull($result->challengeToken);
        self::assertSame('mfa-challenge', $result->challengeToken->reveal());
    }

    /**
     * `A` is computed before the server has named a group, so a tenant on a narrower group must
     * work rather than fail — at the cost of one extra round trip.
     */
    public function testLoginSrpRestartsWhenTheServerNamesAnotherGroup(): void
    {
        $server = new FakeSrpServer($this->backendOrSkip(), 'rfc5054_2048');
        $client = $this->client([
            static fn (RequestInterface $r): Response => $server->challenge((string) $r->getBody()),
            static fn (RequestInterface $r): Response => $server->challenge((string) $r->getBody()),
            static fn (RequestInterface $r): Response => $server->verify((string) $r->getBody()),
        ]);

        self::assertFalse($client->loginSrp(self::IDENTITY, self::PASSWORD)->mfaRequired);
        self::assertCount(3, $server->recordedBodies, 'the exchange should have restarted exactly once');
    }

    /**
     * §23.7 rule 5. The assertion is on the ABSENCE of a session, not merely on a thrown message:
     * skipping `M2` keeps the half of SRP that authenticates the client and throws away the half
     * that authenticates the server.
     */
    public function testAWrongServerProofYieldsAuthErrorAndNoSession(): void
    {
        $server = new FakeSrpServer($this->backendOrSkip(), SrpGroup::DEFAULT_WIRE_NAME);
        $server->corruptServerProof = true;
        $client = $this->client($this->exchangeQueue($server));

        try {
            $client->loginSrp(self::IDENTITY, self::PASSWORD);
            self::fail('a rogue server must not produce a session');
        } catch (AuthError $e) {
            self::assertStringContainsString('verifier', $e->getMessage());
        }

        // The cookies the rogue server set must not survive: an endpoint that cannot prove it holds
        // the verifier is not the server it claims to be, so there is no session to log out of.
        $this->expectException(AuthError::class);
        $client->logout();
    }

    /**
     * A 404 is a property of the tenant, so a caller can fall back to `login()` without mistaking
     * it for a bad password.
     */
    public function testATenantWithSrpDisabledIsNotACredentialFailure(): void
    {
        $this->backendOrSkip();
        $client = $this->client([new Response(404, [], '')]);

        try {
            $client->loginSrp(self::IDENTITY, self::PASSWORD);
            self::fail('a disabled tenant must be reported');
        } catch (NetworkError $e) {
            self::assertStringContainsString('srp_mode', $e->getMessage());
        }
    }

    public function testAWrongPasswordIsAnAuthError(): void
    {
        $server = new FakeSrpServer($this->backendOrSkip(), SrpGroup::DEFAULT_WIRE_NAME);
        $client = $this->client([
            static fn (RequestInterface $r): Response => $server->challenge((string) $r->getBody()),
            new Response(401, [], (string) json_encode(['error' => 'authentication_failed'])),
        ]);

        $this->expectException(AuthError::class);
        $client->loginSrp(self::IDENTITY, 'wrong password');
    }

    /**
     * §23.7 rule 7 and §23.3 rule 10. A user whose password is perfectly good must never be shown
     * "invalid username or password" because the tenant moved to `srp_mode: required`.
     */
    public function testSrpRequiredIsAnAuthzErrorRatherThanAnAuthError(): void
    {
        $client = $this->client([
            new Response(403, [], (string) json_encode([
                'error' => 'srp_required',
                'message' => 'this tenant requires Secure Remote Password; use loginSrp',
            ])),
        ]);

        $this->expectException(AuthzError::class);
        $client->login(self::IDENTITY, self::PASSWORD);
    }

    /**
     * §23.7 rule 8, and the claim the whole feature rests on: the password never crosses the wire.
     */
    public function testThePasswordNeverCrossesTheWire(): void
    {
        $server = new FakeSrpServer($this->backendOrSkip(), SrpGroup::DEFAULT_WIRE_NAME);
        $client = $this->client($this->exchangeQueue($server));
        $client->loginSrp(self::IDENTITY, self::PASSWORD);

        self::assertCount(2, $server->recordedBodies);
        foreach ($server->recordedBodies as $body) {
            self::assertStringNotContainsString(self::PASSWORD, $body, 'the password crossed the wire');
        }

        $challenge = json_decode($server->recordedBodies[0], true);
        self::assertIsArray($challenge);
        self::assertArrayNotHasKey('password', $challenge, 'the challenge request carried a password field');
        self::assertArrayHasKey('client_public', $challenge);
    }

    /**
     * §23.3 rule 11 — enrolment through the client API. The server cannot compute a verifier, so
     * the SDK's output has to be reproducible from the salt it reports or it is unusable.
     */
    public function testSrpEnrollmentProducesAVerifierReproducibleFromItsOwnSalt(): void
    {
        $backend = $this->backendOrSkip();
        $client = $this->client([]);
        self::assertTrue($client->srpAvailable());

        $params = new SrpKdfParams(Srp::KDF_PBKDF2_SHA256, 1000);
        $first = $client->srpEnrollment(self::IDENTITY, self::PASSWORD, params: $params);

        self::assertSame(SrpGroup::DEFAULT_WIRE_NAME, $first->group, 'the default group');
        self::assertSame(64, \strlen($first->salt), 'the salt must be 32 bytes');
        self::assertSame(0, $first->memoryKib, 'pbkdf2 enrolment must not carry argon2 parameters');
        self::assertSame(0, $first->parallelism);

        $x = Srp::deriveX(self::IDENTITY, self::PASSWORD, Srp::hexToBytes($first->salt), $params);
        self::assertSame(
            $first->verifier,
            Srp::over($backend)->computeVerifier(SrpGroup::fromWire($first->group), $x),
            'the reported verifier is not g^x for the reported salt',
        );

        // A reused salt would make every verifier in a tenant equally attackable with one
        // precomputation.
        self::assertNotSame(
            $first->salt,
            $client->srpEnrollment(self::IDENTITY, self::PASSWORD, params: $params)->salt,
        );

        // The JSON shape is exactly what §23.5 defines: no argon2 keys on a pbkdf2 enrolment.
        self::assertSame(['group', 'kdf', 'iterations', 'salt', 'verifier'], array_keys($first->toArray()));
    }

    public function testSrpEnrollmentRefusesAKdfThisSdkCannotPerform(): void
    {
        $this->backendOrSkip();
        $client = $this->client([]);

        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/argon2id/');
        $client->srpEnrollment(self::IDENTITY, self::PASSWORD, params: new SrpKdfParams(Srp::KDF_ARGON2ID, 2));
    }
}

/**
 * The server half of one enrolled account, performing real SRP arithmetic.
 *
 * It stores a verifier and nothing else — exactly what an AXIAM server stores — so a client that
 * satisfies it has genuinely proved knowledge of the password.
 */
final class FakeSrpServer
{
    /** Every request body this fake saw, so a test can assert on what actually crossed the wire. */
    public array $recordedBodies = [];

    public bool $corruptServerProof = false;
    public bool $mfaRequired = false;

    private readonly Srp $srp;
    private readonly SrpGroup $group;
    /** PBKDF2 at a low iteration count: the KDF's cost is not what these tests measure. */
    private readonly SrpKdfParams $kdf;
    private readonly string $salt;
    private readonly string $verifier;
    private readonly string $bPriv;

    private string $bPub = '';
    private string $aPub = '';

    public function __construct(BigIntBackend $backend, private readonly string $groupWireName)
    {
        $this->srp = Srp::over($backend);
        $this->group = SrpGroup::fromWire($groupWireName);
        $this->kdf = new SrpKdfParams(Srp::KDF_PBKDF2_SHA256, 1000);
        $this->salt = str_repeat("\xa3", 32);
        $this->bPriv = str_repeat('22', 32);

        $x = Srp::deriveX('alice', 'correct horse battery staple', $this->salt, $this->kdf);
        $this->verifier = $backend->modPow(
            dechex($this->group->generator),
            $backend->mod(bin2hex($x), $this->group->modulusHex),
            $this->group->modulusHex,
        );
    }

    public function challenge(string $body): Response
    {
        $this->recordedBodies[] = $body;
        $parsed = json_decode($body, true);
        \assert(\is_array($parsed));
        $this->aPub = \is_string($parsed['client_public'] ?? null) ? $parsed['client_public'] : '';

        $backend = $this->srp->backend();
        $n = $this->group->modulusHex;
        // B = (k*v + g^b) mod N
        $this->bPub = $backend->addMod(
            $backend->mulMod(Srp::multiplier($this->group), $this->verifier, $n),
            $backend->modPow(dechex($this->group->generator), $this->bPriv, $n),
            $n,
        );

        return new Response(200, ['Content-Type' => 'application/json'], (string) json_encode([
            'srp_session' => 'opaque-session-token',
            'identity' => 'alice',
            'salt' => bin2hex($this->salt),
            'group' => $this->groupWireName,
            'kdf' => $this->kdf->kdf,
            'iterations' => $this->kdf->iterations,
            'b_pub' => Srp::pad($this->bPub, $this->group->byteLength),
        ]));
    }

    public function verify(string $body): Response
    {
        $this->recordedBodies[] = $body;
        $parsed = json_decode($body, true);
        \assert(\is_array($parsed));
        \assert(($parsed['srp_session'] ?? null) === 'opaque-session-token');

        $backend = $this->srp->backend();
        $n = $this->group->modulusHex;
        $width = $this->group->byteLength;

        // S = (A * v^u)^b mod N — the server's own derivation, from the verifier alone.
        $u = Srp::hash(
            Srp::hexToBytes(Srp::pad($this->aPub, $width)),
            Srp::hexToBytes(Srp::pad($this->bPub, $width)),
        );
        $s = $backend->modPow(
            $backend->mulMod($this->aPub, $backend->modPow($this->verifier, $u, $n), $n),
            $this->bPriv,
            $n,
        );
        $sessionKey = Srp::hash(Srp::hexToBytes(Srp::pad($s, $width)));
        $proof = Srp::hash(
            Srp::hexToBytes(Srp::pad($this->aPub, $width)),
            Srp::hexToBytes((string) ($parsed['client_proof'] ?? '')),
            Srp::hexToBytes($sessionKey),
        );
        if ($this->corruptServerProof) {
            $proof = str_repeat('0', \strlen($proof));
        }

        // Cookies are set exactly as on /auth/login (§23.5) — including on the corrupt-proof path,
        // so the test can assert the client discards them.
        $headers = [
            'Content-Type' => 'application/json',
            'Set-Cookie' => 'axiam_access=' . self::unsignedJwt() . '; Path=/',
        ];
        if ($this->mfaRequired) {
            return new Response(202, $headers, (string) json_encode([
                'challenge_token' => 'mfa-challenge',
                'available_methods' => ['totp'],
                'server_proof' => $proof,
            ]));
        }

        return new Response(200, $headers, (string) json_encode([
            'user' => ['id' => 'user-1'],
            'session_id' => '55555555-5555-5555-5555-555555555555',
            'expires_in' => 900,
            'server_proof' => $proof,
        ]));
    }

    private static function unsignedJwt(): string
    {
        $segment = static fn (array $data): string => rtrim(
            strtr(base64_encode((string) json_encode($data)), '+/', '-_'),
            '=',
        );

        return $segment(['alg' => 'none', 'typ' => 'JWT']) . '.' . $segment([
            'sub' => 'user-1',
            'tenant_id' => '22222222-2222-2222-2222-222222222222',
            'org_id' => '44444444-4444-4444-4444-444444444444',
            'jti' => '33333333-3333-3333-3333-333333333333',
            'exp' => time() + 900,
        ]) . '.signature';
    }
}
