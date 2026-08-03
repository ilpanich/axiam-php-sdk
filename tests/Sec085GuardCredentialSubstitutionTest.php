<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Laravel\AxiamMiddleware;
use Axiam\Sdk\Symfony\AxiamAuthSubscriber;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * SEC-085 regression (CONTRACT.md §10.1 rule 8): a request guard's decision must be about
 * the CALLER's credential and no other.
 *
 * Before the fix both framework bridges called {@see AxiamClient::verifyLocallyOrFallback()},
 * whose reactive-refresh fallback (D-02) verifies *this application's own* session token when
 * the supplied one fails. So a caller presenting an expired, foreign-tenant or outright
 * garbage token was admitted — authenticated as the application's own AXIAM principal, which
 * in an IAM integration is typically a service account more privileged than the user whose
 * request it replaced.
 *
 * The setup here is what makes these tests decisive rather than incidental: the client's own
 * session is primed with a genuinely verifiable Ed25519 token for `app-service-account`, and
 * its refresh genuinely succeeds, so the fallback path really is reachable and really would
 * return the app's claims. Verified by falsification — reverting the two guards to
 * `verifyLocallyOrFallback()` fails 8 of the 9 tests here, admitting each rejected caller as
 * `app-service-account`.
 */
final class Sec085GuardCredentialSubstitutionTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/Fixtures';
    private const FIXTURE_TENANT = 'acme-tenant';
    private const BASE_URL = 'https://api.test';

    private function jwksResponse(): Response
    {
        return new Response(200, [], (string) file_get_contents(self::FIXTURES . '/ed25519_jwks.json'));
    }

    private function discoveryResponse(): Response
    {
        return new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks']));
    }

    /**
     * A client whose OWN session is fully healthy AND whose refresh genuinely succeeds —
     * the setup that makes the fallback path *reachable*, which is the whole point.
     *
     * Getting this right matters more than it looks. A naive fixed `MockHandler` queue
     * makes these tests pass against the vulnerable code for the wrong reason: the session
     * token would lack `org_id`, so `Session::buildRefreshCall()` rejects before any HTTP
     * call and the fallback fails for an incidental reason rather than being blocked. This
     * handler instead routes by request path, so the number and order of calls (which
     * differ per rejected-token shape — a garbage string never reaches the JWKS fetch, an
     * expired signed one does) cannot make a test vacuous:
     *
     *   - login / refresh -> 200 + `Set-Cookie` carrying a signed token with `org_id`
     *   - discovery / JWKS -> the real fixture key, so verification actually succeeds
     *
     * Confirmed by falsification: with the guards reverted to `verifyLocallyOrFallback()`,
     * every assertion below fails with 200 and `axiam_user` = the app's own principal.
     */
    private function clientWithHealthySession(): AxiamClient
    {
        // Carries org_id, so the reactive refresh reaches the transport instead of being
        // rejected locally — without this the fallback can never succeed and the test
        // would pass vacuously.
        $appToken = self::signedFixture(['org_id' => 'org-uuid-1', 'sub' => 'app-service-account']);

        $handler = function ($request) use ($appToken) {
            $path = $request->getUri()->getPath();

            $response = match (true) {
                str_contains($path, '/auth/login'), str_contains($path, '/auth/refresh') => new Response(
                    200,
                    ['Set-Cookie' => 'axiam_access=' . $appToken . '; Path=/'],
                    (string) json_encode(['user' => ['id' => 'app-service-account']]),
                ),
                str_contains($path, 'openid-configuration'), str_contains($path, 'oauth2-authorization-server') =>
                    $this->discoveryResponse(),
                str_contains($path, '/jwks') => $this->jwksResponse(),
                default => new Response(404, [], '{}'),
            };

            return \GuzzleHttp\Promise\Create::promiseFor($response);
        };

        $client = new AxiamClient(self::BASE_URL, self::FIXTURE_TENANT, transportHandler: $handler);
        $client->login('app@example.test', 'secret');

        // Guard the guard: if this ever stops holding, the tests below would pass for the
        // wrong reason, so assert the precondition rather than assuming it.
        self::assertNotNull(
            $client->verifyLocallyOrFallback('not-a-real-jwt', self::FIXTURE_TENANT),
            'precondition: the fallback MUST be reachable and succeed here, otherwise these '
                . 'tests cannot distinguish the fix from the vulnerability',
        );

        return $client;
    }

    /**
     * Caller credentials that must never be admitted. `expired` is the headline case from
     * the finding; the others cover the remaining failure modes the fallback equally
     * papered over — all four previously returned the application's own claims.
     *
     * @return array<string,array{0:string}>
     */
    public static function rejectedCallerTokens(): array
    {
        return [
            'expired' => [self::signedFixtureWithExp(1751500001)],
            'garbage' => ['not-a-real-jwt'],
            'unsigned alg:none' => [
                self::b64('{"typ":"JWT","alg":"none"}') . '.'
                    . self::b64('{"sub":"attacker","tenant_id":"acme-tenant","exp":4102444800}') . '.',
            ],
            'foreign tenant' => [self::signedFixtureWithTenant('other-tenant')],
        ];
    }

    // --- Laravel -------------------------------------------------------------------

    /**
     * @dataProvider rejectedCallerTokens
     */
    public function testLaravelRejectsFailedCallerTokenEvenWithHealthyClientSession(string $callerToken): void
    {
        $middleware = new AxiamMiddleware($this->clientWithHealthySession(), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $callerToken);

        $response = $middleware->handle(
            $request,
            static fn (Request $r): JsonResponse => new JsonResponse(['ok' => true], 200),
        );

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(
            401,
            $response->getStatusCode(),
            'a caller token that fails verification must yield 401, never the app session',
        );
        self::assertNull(
            $request->attributes->get('axiam_user'),
            'no identity may be injected — least of all the application service account',
        );
    }

    // --- Symfony -------------------------------------------------------------------

    /**
     * @dataProvider rejectedCallerTokens
     */
    public function testSymfonyRejectsFailedCallerTokenEvenWithHealthyClientSession(string $callerToken): void
    {
        if (!class_exists(AxiamAuthSubscriber::class)) {
            self::markTestSkipped('symfony/event-dispatcher not installed');
        }

        $subscriber = new AxiamAuthSubscriber($this->clientWithHealthySession(), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $callerToken);

        $event = new RequestEvent(
            $this->createMock(HttpKernelInterface::class),
            $request,
            HttpKernelInterface::MAIN_REQUEST,
        );
        $subscriber->onKernelRequest($event);

        $response = $event->getResponse();
        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(
            401,
            $response->getStatusCode(),
            'a caller token that fails verification must yield 401, never the app session',
        );
        self::assertNull($request->attributes->get('axiam_user'));
    }

    // --- The seam itself -----------------------------------------------------------

    /**
     * Pins the distinction directly at the client surface, so the guards' correctness does
     * not rest on which helper they happen to call today: verifyLocally() decides on the
     * supplied token alone, while verifyLocallyOrFallback() — correct for the SDK's own
     * outbound calls — demonstrably substitutes the client's session.
     */
    public function testVerifyLocallyNeverSubstitutesTheClientSession(): void
    {
        $client = $this->clientWithHealthySession();
        $expired = self::signedFixtureWithExp(1751500001);

        self::assertNull(
            $client->verifyLocally($expired, self::FIXTURE_TENANT),
            'verifyLocally() must return null for a failed token, with no fallback',
        );
    }

    // --- Fixture helpers -----------------------------------------------------------

    private static function b64(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * Re-signs the fixture payload with the fixture Ed25519 key, overriding one claim, so
     * the token differs from the healthy one ONLY in the property under test — the
     * signature is genuinely valid and the rejection can only come from the claim check.
     *
     * @param array<string,mixed> $overrides
     */
    private static function signedFixture(array $overrides): string
    {
        $keypair = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_keypair.json'), true);
        \assert(\is_array($keypair));

        $header = ['typ' => 'JWT', 'alg' => 'EdDSA', 'kid' => 'axiam-test-key-2026-07-02'];
        $payload = array_merge([
            'sub' => 'user-fixture-0001',
            'tenant_id' => self::FIXTURE_TENANT,
            'iat' => 1751500000,
            'exp' => 4102444800,
        ], $overrides);

        $signingInput = self::b64((string) json_encode($header)) . '.' . self::b64((string) json_encode($payload));
        $secret = base64_decode(strtr((string) $keypair['secret_key_b64url'], '-_', '+/'), true);
        \assert(\is_string($secret));

        return $signingInput . '.' . self::b64(sodium_crypto_sign_detached($signingInput, $secret));
    }

    private static function signedFixtureWithExp(int $exp): string
    {
        return self::signedFixture(['exp' => $exp]);
    }

    private static function signedFixtureWithTenant(string $tenant): string
    {
        return self::signedFixture(['tenant_id' => $tenant]);
    }
}
