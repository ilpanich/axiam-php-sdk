<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Symfony\AxiamAuthSubscriber;
use Firebase\JWT\JWT;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Edge coverage for {@see AxiamAuthSubscriber} (D-02, CONTRACT.md §10/§3) complementing
 * {@see SymfonyAuthSubscriberTest}'s primary flows: the static event map, a non-Bearer
 * `Authorization` header, a cookie-authenticated write missing the `axiam_csrf` cookie, a
 * signature-valid token with an empty `sub`, and the two non-array `roles`/`scope` claim
 * normalizations. Tokens are re-signed with the committed Ed25519 fixture keypair (as in
 * {@see JwtVerifyTest}) so they verify against the fixture JWKS while carrying the exact
 * claim shapes under test.
 */
final class SymfonyAuthEdgeSubscriberTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/Fixtures';
    private const FIXTURE_TENANT = 'acme-tenant';
    private const BASE_URL = 'https://api.test';

    /** @return array<string,mixed> */
    private function fixtureJwks(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_jwks.json'), true);
        self::assertIsArray($decoded);

        return $decoded;
    }

    /** @param array<string,mixed> $claims */
    private function signedJwt(array $claims): string
    {
        $keypair = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_keypair.json'), true);
        self::assertIsArray($keypair);
        $secretKey = (string) base64_decode(strtr($keypair['secret_key_b64url'], '-_', '+/'), true);

        return JWT::encode(
            $claims + ['exp' => 4102444800],
            base64_encode($secretKey),
            'EdDSA',
            $keypair['kid'],
        );
    }

    /** @param list<Response> $queue */
    private function clientWith(array $queue): AxiamClient
    {
        return new AxiamClient(self::BASE_URL, self::FIXTURE_TENANT, transportHandler: new MockHandler($queue));
    }

    /** @return list<Response> */
    private function jwksQueue(): array
    {
        return [
            new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks'])),
            new Response(200, [], (string) json_encode($this->fixtureJwks())),
        ];
    }

    private function requestEvent(Request $request): RequestEvent
    {
        $kernel = new class implements HttpKernelInterface {
            public function handle(Request $request, int $type = self::MAIN_REQUEST, bool $catch = true): \Symfony\Component\HttpFoundation\Response
            {
                return new \Symfony\Component\HttpFoundation\Response();
            }
        };

        return new RequestEvent($kernel, $request, HttpKernelInterface::MAIN_REQUEST);
    }

    public function testGetSubscribedEventsMapsKernelRequest(): void
    {
        $events = AxiamAuthSubscriber::getSubscribedEvents();

        self::assertArrayHasKey(KernelEvents::REQUEST, $events);
        self::assertSame('onKernelRequest', $events[KernelEvents::REQUEST]);
    }

    public function testNonBearerAuthorizationHeaderShortCircuitsWith401(): void
    {
        $subscriber = new AxiamAuthSubscriber($this->clientWith([]), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Basic dXNlcjpwYXNz');
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertSame(401, $event->getResponse()?->getStatusCode());
    }

    public function testCookieWriteWithCsrfHeaderButNoCsrfCookieShortCircuitsWith403(): void
    {
        $subscriber = new AxiamAuthSubscriber($this->clientWith([]), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'POST');
        $request->cookies->set('axiam_access', 'some-token');
        $request->headers->set('X-CSRF-Token', 'header-value');
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertSame(403, $event->getResponse()?->getStatusCode());
    }

    public function testSignatureValidTokenWithEmptySubShortCircuitsWith401(): void
    {
        $token = $this->signedJwt(['sub' => '', 'tenant_id' => self::FIXTURE_TENANT]);
        $subscriber = new AxiamAuthSubscriber($this->clientWith($this->jwksQueue()), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertSame(401, $event->getResponse()?->getStatusCode());
    }

    /**
     * CONTRACT.md §10.1 rule 4: the token's `tenant_id` MUST be asserted against the
     * CONFIGURED tenant. `X-Tenant-ID` is attacker-controlled, so letting it select the
     * expected value would compare the token against itself — a vacuous check that lets
     * any tenant's token into an app configured for a different one.
     */
    public function testAttackerSuppliedTenantHeaderCannotOverrideTheConfiguredTenant(): void
    {
        $token = $this->signedJwt(['sub' => 'evil', 'tenant_id' => 'attacker-tenant']);
        $subscriber = new AxiamAuthSubscriber($this->clientWith($this->jwksQueue()), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);
        $request->headers->set('X-Tenant-ID', 'attacker-tenant');
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertSame(401, $event->getResponse()?->getStatusCode());
    }

    /** A matching `X-Tenant-ID` header still narrows correctly and is admitted. */
    public function testMatchingTenantHeaderStillNarrowsAndIsAdmitted(): void
    {
        $token = $this->signedJwt(['sub' => 'user-x', 'tenant_id' => self::FIXTURE_TENANT]);
        $subscriber = new AxiamAuthSubscriber($this->clientWith($this->jwksQueue()), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);
        $request->headers->set('X-Tenant-ID', self::FIXTURE_TENANT);
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertFalse($event->hasResponse());
        self::assertSame('user-x', $request->attributes->get('axiam_user')['user_id']);
    }

    /**
     * CONTRACT.md §10.1 rule 2, end to end through the guard: a signature-valid,
     * correct-tenant token carrying NO `exp` claim is a permanent credential and must be
     * rejected. Asserted at the GUARD level (not only at the verifier) so the guard
     * genuinely routing through the full §10.1 set is itself under test.
     */
    public function testTokenWithNoExpClaimIsRejectedByTheGuard(): void
    {
        // NOTE: bypasses signedJwt(), which always adds an exp.
        $keypair = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_keypair.json'), true);
        self::assertIsArray($keypair);
        $secretKey = (string) base64_decode(strtr($keypair['secret_key_b64url'], '-_', '+/'), true);
        $token = JWT::encode(
            ['sub' => 'user-x', 'tenant_id' => self::FIXTURE_TENANT],
            base64_encode($secretKey),
            'EdDSA',
            $keypair['kid'],
        );
        $subscriber = new AxiamAuthSubscriber($this->clientWith($this->jwksQueue()), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertSame(401, $event->getResponse()?->getStatusCode());
    }

    public function testScopeStringClaimIsNormalizedToRolesList(): void
    {
        $token = $this->signedJwt([
            'sub' => 'user-x',
            'tenant_id' => self::FIXTURE_TENANT,
            'scope' => 'read write delete',
        ]);
        $subscriber = new AxiamAuthSubscriber($this->clientWith($this->jwksQueue()), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertFalse($event->hasResponse());
        self::assertSame(
            ['read', 'write', 'delete'],
            $request->attributes->get('axiam_user')['roles'],
        );
    }

    public function testNonStringRolesClaimNormalizesToEmptyList(): void
    {
        $token = $this->signedJwt([
            'sub' => 'user-x',
            'tenant_id' => self::FIXTURE_TENANT,
            'roles' => 123,
        ]);
        $subscriber = new AxiamAuthSubscriber($this->clientWith($this->jwksQueue()), self::FIXTURE_TENANT);

        $request = Request::create('/documents/1', 'GET');
        $request->headers->set('Authorization', 'Bearer ' . $token);
        $event = $this->requestEvent($request);
        $subscriber->onKernelRequest($event);

        self::assertFalse($event->hasResponse());
        self::assertSame([], $request->attributes->get('axiam_user')['roles']);
    }
}
