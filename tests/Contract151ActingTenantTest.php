<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\DecisionMemo;
use Axiam\Sdk\Core\NetworkError;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * CONTRACT.md §5.2 rule 1 (contract 1.51) — the acting-tenant helper
 * (`actingTenant()`/`clearActingTenant()`, and the construction-time `actingTenant`
 * parameter).
 *
 * `X-Axiam-Tenant` is sent when set and absent when not (the I4 twin), on EVERY
 * `/api/v1` request this client makes — not only management calls
 * (CONTRACT.md §5.2.2 rule 4 forbids clearing or rewriting the header per call site,
 * so an SDK that only wires it into `management()` has not implemented the rule). A
 * non-UUID value is refused client-side with zero wire calls. Gated on a held login
 * result's `organizationLevel`/`reachableTenantIds` when one is held, and open when
 * none is. The §17 decision memo key includes the acting tenant. A session that
 * completes without a `LoginUserInfo` (SSO here) resets the gate to unknown.
 */
final class Contract151ActingTenantTest extends TestCase
{
    private const BASE_URL = 'https://axiam-151.test';
    private const ORG_ID = '11111111-1111-4111-8111-111111111111';
    private const CLIENT_TENANT_SLUG = 'acme';
    private const TARGET_TENANT = '33333333-3333-4333-8333-333333333333';
    private const OTHER_TENANT = '99999999-9999-4999-8999-999999999999';

    /** @var list<RequestInterface> */
    private array $requests = [];

    protected function setUp(): void
    {
        $this->requests = [];
    }

    /** @param list<Response> $queue */
    private function client(array $queue, ?string $actingTenant = null): AxiamClient
    {
        $handler = new MockHandler($queue);
        $recorder = function (RequestInterface $request, array $options) use ($handler) {
            $this->requests[] = $request;

            return $handler($request, $options);
        };

        return new AxiamClient(
            self::BASE_URL,
            self::CLIENT_TENANT_SLUG,
            orgId: self::ORG_ID,
            transportHandler: $recorder,
            retryEnabled: false,
            actingTenant: $actingTenant,
        );
    }

    /** An unsigned but well-shaped JWT — enough for the SDK's own unverified claim reads. */
    private static function unsignedJwt(array $claims): string
    {
        $segment = static fn (array $data): string => rtrim(
            strtr(base64_encode((string) json_encode($data)), '+/', '-_'),
            '=',
        );

        return $segment(['alg' => 'none', 'typ' => 'JWT']) . '.' . $segment($claims) . '.signature';
    }

    /** @param array<string,mixed> $user */
    private static function loginSuccess(array $user = []): Response
    {
        $token = self::unsignedJwt([
            'jti' => 'sid-1',
            'tenant_id' => self::ORG_ID,
            'org_id' => self::ORG_ID,
        ]);

        return new Response(
            200,
            ['Set-Cookie' => 'axiam_access=' . $token . '; Path=/', 'Content-Type' => 'application/json'],
            (string) json_encode([
                'user' => array_merge(['id' => self::ORG_ID, 'username' => 'alice'], $user),
                'session_id' => '22222222-2222-4222-8222-222222222222',
                'expires_in' => 900,
            ]),
        );
    }

    private static function checkAccessOk(): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], '{"allowed":true}');
    }

    /** Every request's `X-Axiam-Tenant` header value, or `null` when absent, in order. */
    private function actingTenantHeaders(): array
    {
        return array_map(
            static fn (RequestInterface $r): ?string => $r->hasHeader('X-Axiam-Tenant')
                ? $r->getHeaderLine('X-Axiam-Tenant')
                : null,
            $this->requests,
        );
    }

    // -----------------------------------------------------------------
    // Sent when set, absent when not (the I4 twin)
    // -----------------------------------------------------------------

    public function testHeaderIsSentOnCheckAccessWhenSetAtConstruction(): void
    {
        $client = $this->client([self::checkAccessOk()], self::TARGET_TENANT);

        $client->checkAccess('read', 'doc-1');

        self::assertSame([self::TARGET_TENANT], $this->actingTenantHeaders());
    }

    public function testHeaderIsAbsentOnCheckAccessWhenNeverSet(): void
    {
        $client = $this->client([self::checkAccessOk()]);

        $client->checkAccess('read', 'doc-1');

        self::assertSame([null], $this->actingTenantHeaders());
    }

    public function testOnClientFormSendsTheHeaderFromItsNextCallOnwards(): void
    {
        $client = $this->client([self::checkAccessOk(), self::checkAccessOk()]);

        $client->checkAccess('read', 'doc-1'); // before: no header
        $client->actingTenant(self::TARGET_TENANT);
        $client->checkAccess('read', 'doc-1'); // after: header present

        self::assertSame([null, self::TARGET_TENANT], $this->actingTenantHeaders());
    }

    public function testClearActingTenantStopsSendingTheHeader(): void
    {
        $client = $this->client([self::checkAccessOk(), self::checkAccessOk()]);

        $client->actingTenant(self::TARGET_TENANT);
        $client->clearActingTenant();
        $client->checkAccess('read', 'doc-1');

        self::assertNull($client->actingTenantId());
        self::assertSame([null], $this->actingTenantHeaders());
    }

    /**
     * §5.2.2 rule 4: an SDK MUST NOT clear or rewrite the header per call site. Proved
     * on management, checkAccess AND refresh/logout — not only the one call type a
     * narrower implementation might have wired it into.
     */
    public function testHeaderReachesManagementCheckAccessRefreshAndLogout(): void
    {
        $client = $this->client([
            self::loginSuccess(),
            new Response(200, ['Content-Type' => 'application/json'], '{"items":[],"total":0,"offset":0,"limit":50}'), // permissions.list
            self::checkAccessOk(),
            new Response(200, [], (string) json_encode(['exp' => time() + 900])), // refresh — body shape is unverified-decode only
            new Response(204),
        ], self::TARGET_TENANT);

        $client->login('alice@example.test', 'pw');
        $client->permissions()->listItems();
        $client->checkAccess('read', 'doc-1');
        $client->refresh();
        $client->logout();

        // requests[0] = login (a login() body has no tenant to act on yet? -- the header
        // is sent regardless, since login has no held scope to gate on).
        $headers = $this->actingTenantHeaders();
        self::assertSame(self::TARGET_TENANT, $headers[0], 'login');
        self::assertSame(self::TARGET_TENANT, $headers[1], 'management (permissions.list)');
        self::assertSame(self::TARGET_TENANT, $headers[2], 'checkAccess');
        self::assertSame(self::TARGET_TENANT, $headers[3], 'refresh');
        self::assertSame(self::TARGET_TENANT, $headers[4], 'logout');
    }

    // -----------------------------------------------------------------
    // A non-UUID value is refused client-side, zero wire calls
    // -----------------------------------------------------------------

    public function testConstructionRefusesANonUuidActingTenant(): void
    {
        $this->expectException(NetworkError::class);
        $this->client([], 'not-a-uuid');
    }

    public function testOnClientFormRefusesANonUuidActingTenantWithZeroWireCalls(): void
    {
        $client = $this->client([]);

        try {
            $client->actingTenant('not-a-uuid');
            self::fail('expected NetworkError');
        } catch (NetworkError) {
        }

        self::assertSame([], $this->requests, 'no wire call for a client-side refusal');
    }

    // -----------------------------------------------------------------
    // Gating: organizationLevel / reachableTenantIds, when a login result is held
    // -----------------------------------------------------------------

    public function testActingTenantIsRefusedAfterAnOrdinaryNonOrganizationLevelLogin(): void
    {
        $client = $this->client([self::loginSuccess(['organization_level' => false])]);
        $client->login('alice@example.test', 'pw');

        $before = \count($this->requests);
        try {
            $client->actingTenant(self::TARGET_TENANT);
            self::fail('expected AuthzError');
        } catch (AuthzError) {
        }

        self::assertSame($before, \count($this->requests), 'refused client-side, no wire call');
    }

    public function testActingTenantSucceedsForAnOrganizationLevelLoginWithNoReachableTenantIds(): void
    {
        $client = $this->client([self::loginSuccess(['organization_level' => true]), self::checkAccessOk()]);
        $client->login('alice@example.test', 'pw');

        $client->actingTenant(self::TARGET_TENANT);
        $client->checkAccess('read', 'doc-1');

        self::assertSame(self::TARGET_TENANT, $this->requests[\count($this->requests) - 1]->getHeaderLine('X-Axiam-Tenant'));
    }

    public function testActingTenantIsRefusedOutsideReachableTenantIds(): void
    {
        $client = $this->client([self::loginSuccess([
            'organization_level' => true,
            'reachable_tenant_ids' => [self::TARGET_TENANT],
        ])]);
        $client->login('alice@example.test', 'pw');

        $before = \count($this->requests);
        try {
            $client->actingTenant(self::OTHER_TENANT);
            self::fail('expected AuthzError (§5.2.3 rule 4)');
        } catch (AuthzError) {
        }

        self::assertSame($before, \count($this->requests));
    }

    public function testActingTenantSucceedsInsideReachableTenantIds(): void
    {
        $client = $this->client([
            self::loginSuccess(['organization_level' => true, 'reachable_tenant_ids' => [self::TARGET_TENANT]]),
            self::checkAccessOk(),
        ]);
        $client->login('alice@example.test', 'pw');

        $client->actingTenant(self::TARGET_TENANT);
        $client->checkAccess('read', 'doc-1');

        self::assertSame(self::TARGET_TENANT, $this->requests[\count($this->requests) - 1]->getHeaderLine('X-Axiam-Tenant'));
    }

    /** A client holding no login result has nothing to gate on — the server's 403 answers. */
    public function testActingTenantIsUngatedBeforeAnyLogin(): void
    {
        $client = $this->client([self::checkAccessOk()]);

        $client->actingTenant(self::TARGET_TENANT);
        $client->checkAccess('read', 'doc-1');

        self::assertSame(self::TARGET_TENANT, $this->requests[0]->getHeaderLine('X-Axiam-Tenant'));
    }

    // -----------------------------------------------------------------
    // §17 memo key includes the acting tenant (C-12 item 2)
    // -----------------------------------------------------------------

    public function testDecisionMemoKeyDiffersByActingTenant(): void
    {
        $sameArgs = fn (?string $tenant): string => DecisionMemo::key('subj', 'res', 'read', null, $tenant);

        self::assertNotSame($sameArgs(self::TARGET_TENANT), $sameArgs(self::OTHER_TENANT));
        self::assertNotSame($sameArgs(null), $sameArgs(self::TARGET_TENANT), 'no acting tenant is its own distinct key');
    }

    /**
     * End-to-end: two handles differing only in acting tenant must each reach the
     * wire — a memo keyed without the tenant would let tenant A's cached "allowed"
     * answer tenant B's identical check.
     */
    public function testMemoDoesNotLeakAnAllowAcrossActingTenants(): void
    {
        $handler = new MockHandler([self::checkAccessOk(), self::checkAccessOk()]);
        $stack = HandlerStack::create($handler);
        $history = [];
        $stack->push(Middleware::history($history));

        $client = new AxiamClient(
            self::BASE_URL,
            self::CLIENT_TENANT_SLUG,
            orgId: self::ORG_ID,
            transportHandler: $stack,
            retryEnabled: false,
            decisionMemoTtlMs: 5000.0,
        );

        $client->actingTenant(self::TARGET_TENANT);
        $client->checkAccess('read', 'doc-1');
        $client->actingTenant(self::OTHER_TENANT);
        $client->checkAccess('read', 'doc-1'); // same action/resource, DIFFERENT tenant

        self::assertCount(2, $history, 'both must reach the wire; the second must not be served from the memo');
    }

    // -----------------------------------------------------------------
    // C-12 lesson: a session with no LoginUserInfo resets the gate to unknown
    // -----------------------------------------------------------------

    public function testSsoCompletionResetsTheGateAfterARefusingLogin(): void
    {
        $client = new AxiamClient(
            self::BASE_URL,
            self::CLIENT_TENANT_SLUG,
            orgSlug: 'acme',
            oidcClientId: 'my-app',
            transportHandler: new MockHandler([
                self::loginSuccess(['organization_level' => false]),
                new Response(
                    200,
                    ['Set-Cookie' => 'axiam_access=sso-tok; Path=/'],
                    (string) json_encode([
                        'user_id' => 'user-1',
                        'session_id' => 'sess-1',
                        'expires_in' => 900,
                        'redirect_uri' => 'https://app.test/',
                    ]),
                ),
            ]),
            retryEnabled: false,
        );

        $client->login('alice@example.test', 'pw');
        try {
            $client->actingTenant(self::TARGET_TENANT);
            self::fail('expected AuthzError: not organization-level');
        } catch (AuthzError) {
        }

        // SSO completes a session WITHOUT a LoginUserInfo -- the previous refusal's
        // scope must not survive it.
        $client->ssoComplete('state', 'code');

        // No exception: the gate is open again (this client holds no login result).
        $client->actingTenant(self::TARGET_TENANT);
        self::assertSame(self::TARGET_TENANT, $client->actingTenantId());
        self::assertNotNull($client->actingTenantId());
    }

    /** The twin: a FAILED SSO completion leaves the gate exactly as it was. */
    public function testARefusedSsoCompletionLeavesTheGateAsItWas(): void
    {
        $client = new AxiamClient(
            self::BASE_URL,
            self::CLIENT_TENANT_SLUG,
            orgSlug: 'acme',
            oidcClientId: 'my-app',
            transportHandler: new MockHandler([
                self::loginSuccess(['organization_level' => false]),
                new Response(401, [], (string) json_encode(['error' => 'invalid_grant'])),
            ]),
            retryEnabled: false,
        );

        $client->login('alice@example.test', 'pw');
        try {
            $client->ssoComplete('state', 'bad-code');
            self::fail('expected an error from the malformed/401 completion');
        } catch (\Throwable $e) {
            self::assertNotInstanceOf(\PHPUnit\Framework\AssertionFailedError::class, $e);
        }

        // The gate is STILL refused: the failed completion must not have reset it.
        try {
            $client->actingTenant(self::TARGET_TENANT);
            self::fail('expected AuthzError: the refusing login result must still be held');
        } catch (AuthzError $e) {
            self::assertStringContainsString('not organization-level', $e->getMessage());
        }
    }
}
