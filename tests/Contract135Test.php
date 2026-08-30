<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Management\Models\AssignRoleToGroupRequest;
use Axiam\Sdk\Management\Models\AssignRoleToServiceAccountRequest;
use Axiam\Sdk\Management\Models\AssignRoleToUserRequest;
use Axiam\Sdk\Management\Models\UpdateWebhookRequest;
use Axiam\Sdk\Opaque\OpaqueLibrary;
use Axiam\Sdk\Tests\Fakes\FakeOpaqueNative;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * Contract 1.34 §5.2.2 and contract 1.35 §5.2.3 — the acting tenant vs the principal
 * tenant, and tenant-scoped role assignments.
 *
 * Two of these rules are the kind an SDK breaks silently rather than loudly, which is
 * why they are pinned here rather than left to the generated surface test:
 *
 * - **§5.2.2 rule 2.** A registration record for the caller's *own* password is sealed
 *   against the tenant the account lives in, not the one the client is pointed at. Get
 *   it wrong and the server answers "the OPAQUE session was issued for a different
 *   tenant" — but only for an organization-level principal that has switched tenant, so
 *   it passes every test written against an ordinary account.
 * - **§5.2.3 rule 1.** `tenant_scope: []` is refused with `400`. A null check alone does
 *   not prevent it: an empty array is the natural thing to build for "no tenants named",
 *   and it is not null.
 */
final class Contract135Test extends TestCase
{
    private const BASE_URL = 'https://axiam-135.test';
    private const ORG_ID = '11111111-1111-4111-8111-111111111111';
    private const ACTING_TENANT_SLUG = 'acme';
    private const ACTING_TENANT = '33333333-3333-4333-8333-333333333333';
    private const PRINCIPAL_TENANT = '55555555-5555-4555-8555-555555555555';

    /** The hex RegistrationResponse the fake server answers `register/start` with. */
    private const WIRE_REGISTRATION_RESPONSE = '726573703a';

    private FakeOpaqueNative $lib;

    /** @var list<RequestInterface> */
    private array $requests = [];

    protected function setUp(): void
    {
        $this->lib = new FakeOpaqueNative();
        OpaqueLibrary::setForTests($this->lib);
        $this->requests = [];
    }

    protected function tearDown(): void
    {
        OpaqueLibrary::resetForTests();
    }

    /**
     * A throwaway credential, minted per call.
     *
     * Deliberately not a literal: a password spelled out in source is a finding for every
     * secret scanner that looks at this repository, and it stays one wherever the file
     * gets copied. Nothing here depends on the value — the login stub answers 200
     * regardless, so what is under test is which tenant the body names, never whether a
     * credential matched.
     */
    private function fixturePassword(): string
    {
        return 'fixture-' . bin2hex(random_bytes(8));
    }

    /** A client with `$queue` behind it, recording every request that reaches the transport. */
    private function client(array $queue): AxiamClient
    {
        $handler = new MockHandler($queue);
        $recorder = function (RequestInterface $request, array $options) use ($handler) {
            $this->requests[] = $request;

            return $handler($request, $options);
        };

        return new AxiamClient(
            self::BASE_URL,
            self::ACTING_TENANT_SLUG,
            orgId: self::ORG_ID,
            transportHandler: $recorder,
            retryEnabled: false,
        );
    }

    /**
     * A `LoginSuccessResponse` whose user object carries `$user` on top of the minimum.
     *
     * @param array<string,mixed> $user
     */
    private static function loginSuccess(array $user): Response
    {
        return new Response(
            200,
            ['Set-Cookie' => 'axiam_access=t0ken; Path=/', 'Content-Type' => 'application/json'],
            (string) json_encode([
                'user' => array_merge([
                    'id' => self::ORG_ID,
                    'username' => 'alice',
                    'email' => 'alice@example.com',
                ], $user),
                'session_id' => '22222222-2222-4222-8222-222222222222',
                'expires_in' => 900,
            ]),
        );
    }

    /** The `register/start` answer both enrolment paths get. */
    private static function registerStart(): Response
    {
        return new Response(
            200,
            ['Content-Type' => 'application/json'],
            '{"opaque_session":"reg-handle","registration_response":"'
                . self::WIRE_REGISTRATION_RESPONSE
                . '","ksf":"argon2id","memory_kib":19456,"iterations":2,"parallelism":1}',
        );
    }

    /**
     * A client signed in against a login response carrying `$user`, with `$then` queued
     * behind it.
     *
     * @param array<string,mixed> $user Extra fields on the login response's user object.
     * @param list<Response>      $then Responses queued after the login.
     */
    private function signedIn(array $user, array $then = []): AxiamClient
    {
        $client = $this->client(array_merge([self::loginSuccess($user)], $then));
        $client->login('alice@example.com', $this->fixturePassword());

        return $client;
    }

    /**
     * The decoded body of the last request that reached the transport.
     *
     * @return array<string,mixed>
     */
    private function lastBody(): array
    {
        $request = $this->requests[array_key_last($this->requests)];
        $decoded = json_decode((string) $request->getBody(), true);
        self::assertIsArray($decoded);

        return $decoded;
    }

    // -----------------------------------------------------------------
    // §5.2.2 — acting tenant vs principal tenant
    // -----------------------------------------------------------------

    /**
     * Rule 1: absent means *equal*, not unknown. A server older than contract 1.34 omits
     * `principal_tenant_id` and cannot switch the acting tenant either, so reading
     * `tenant_id` there is not a guess — it is the only value the field could have had.
     */
    public function testAbsentPrincipalTenantReadsAsTheActingTenant(): void
    {
        $client = $this->client([self::loginSuccess(['tenant_id' => self::ACTING_TENANT])]);

        $result = $client->login('alice@example.com', $this->fixturePassword());

        self::assertSame(self::ACTING_TENANT, $result->actingTenantId);
        self::assertSame(
            self::ACTING_TENANT,
            $result->principalTenantId,
            'an omitted principal tenant is the acting tenant, not null',
        );
        self::assertNull($result->principalTenantSlug);
    }

    /**
     * The whole point of the field: for an organization-level principal that has selected
     * another tenant, the two differ and the SDK must not collapse them.
     */
    public function testDivergentPrincipalTenantIsReportedSeparately(): void
    {
        $client = $this->client([self::loginSuccess([
            'tenant_id' => self::ACTING_TENANT,
            'principal_tenant_id' => self::PRINCIPAL_TENANT,
            'principal_tenant_slug' => 'organization',
            'org_id' => self::ORG_ID,
            'organization_level' => true,
        ])]);

        $result = $client->login('alice@example.com', $this->fixturePassword());

        self::assertSame(self::ACTING_TENANT, $result->actingTenantId);
        self::assertSame(self::PRINCIPAL_TENANT, $result->principalTenantId);
        self::assertSame('organization', $result->principalTenantSlug);
        // Rule 3: read the organization from the session rather than resolving a slug
        // through the `super-admin`-only `GET /api/v1/organizations`.
        self::assertSame(self::ORG_ID, $result->orgId);
        self::assertTrue($result->organizationLevel);
    }

    /**
     * §5.2.3: a narrowed principal still reports `organizationLevel = true`, which is
     * exactly why gating on that flag alone offers tenants the server refuses.
     */
    public function testReachableTenantIdsNarrowsAnOrganizationLevelPrincipal(): void
    {
        $reachable = '66666666-6666-4666-8666-666666666666';
        $client = $this->client([self::loginSuccess([
            'tenant_id' => self::ACTING_TENANT,
            'organization_level' => true,
            'reachable_tenant_ids' => [$reachable],
        ])]);

        $result = $client->login('alice@example.com', $this->fixturePassword());

        self::assertTrue($result->organizationLevel);
        self::assertSame([$reachable], $result->reachableTenantIds);
    }

    /**
     * `null`, never `[]`: an empty list would read as "reaches nothing", which is the
     * opposite of what an omitted field means here.
     */
    public function testAbsentReachIsUnrestrictedNotEmpty(): void
    {
        $client = $this->client([self::loginSuccess(['tenant_id' => self::ACTING_TENANT])]);

        $result = $client->login('alice@example.com', $this->fixturePassword());

        self::assertNull($result->reachableTenantIds);
        // Rule 1's fallback still applies with the rest of the scope absent.
        self::assertSame(self::ACTING_TENANT, $result->principalTenantId);
    }

    // -----------------------------------------------------------------
    // §5.2.2 rule 2 — which tenant a registration record is sealed against
    // -----------------------------------------------------------------

    /**
     * The correctness fix itself. `opaqueEnrollmentForSelf` seals against the tenant the
     * account lives in, and drops the slug naming the acting tenant — a slug left beside
     * the id would out-vote it server-side, which is the exact confusion the override
     * exists to avoid.
     */
    public function testEnrollmentForSelfSealsAgainstThePrincipalTenant(): void
    {
        $client = $this->signedIn(
            [
                'tenant_id' => self::ACTING_TENANT,
                'principal_tenant_id' => self::PRINCIPAL_TENANT,
                'principal_tenant_slug' => 'organization',
                'organization_level' => true,
            ],
            [self::registerStart()],
        );

        $enrollment = $client->opaqueEnrollmentForSelf($this->fixturePassword());

        $body = $this->lastBody();
        self::assertSame(self::PRINCIPAL_TENANT, $body['tenant_id'] ?? null);
        self::assertArrayNotHasKey(
            'tenant_slug',
            $body,
            'a slug naming the acting tenant would out-vote the principal tenant id',
        );
        self::assertSame('reg-handle', $enrollment->opaqueSession);
    }

    /**
     * The other call site, unchanged: creating a record for *another* account seals it
     * against the tenant being acted on, which is what the client is already pointed at.
     */
    public function testPlainEnrollmentStillSealsAgainstTheActingTenant(): void
    {
        $client = $this->signedIn(
            [
                'tenant_id' => self::ACTING_TENANT,
                'principal_tenant_id' => self::PRINCIPAL_TENANT,
                'organization_level' => true,
            ],
            [self::registerStart()],
        );

        $client->opaqueEnrollment($this->fixturePassword());

        $body = $this->lastBody();
        self::assertSame(self::ACTING_TENANT_SLUG, $body['tenant_slug'] ?? null);
        self::assertArrayNotHasKey('tenant_id', $body);
    }

    /**
     * Before a login there is no principal tenant to seal against, and guessing the
     * acting one is exactly the bug this method exists to prevent.
     */
    public function testOpaqueEnrollmentForSelfRefusesBeforeALogin(): void
    {
        $client = $this->client([]);

        $this->expectException(NetworkError::class);
        $this->expectExceptionMessageMatches('/principal tenant/');
        $client->opaqueEnrollmentForSelf($this->fixturePassword());
    }

    // -----------------------------------------------------------------
    // §5.2.3 rules 1 and 2 — tenant_scope on an assignment
    // -----------------------------------------------------------------

    /**
     * Rule 1. `[]` is refused with 400, and an empty array is what building the field
     * from a filtered collection produces for "no tenants named", so both spellings of
     * absent must travel the same way: by not appearing.
     */
    public function testAnEmptyTenantScopeNeverReachesTheWire(): void
    {
        $userId = '77777777-7777-4777-8777-777777777777';

        $omitted = (new AssignRoleToUserRequest($userId))->jsonSerialize();
        $empty = (new AssignRoleToUserRequest($userId, null, []))->jsonSerialize();

        self::assertArrayNotHasKey('tenant_scope', $omitted);
        self::assertArrayNotHasKey(
            'tenant_scope',
            $empty,
            'the server refuses an empty tenant_scope with 400',
        );
    }

    /**
     * Rule 2. Dropping a scope the caller *did* name would turn a refusal they need to
     * see into a success that silently applied no restriction.
     */
    public function testANamedTenantScopeIsSent(): void
    {
        $scoped = '88888888-8888-4888-8888-888888888888';
        $id = '99999999-9999-4999-8999-999999999999';

        foreach ([
            'users' => (new AssignRoleToUserRequest($id, null, [$scoped]))->jsonSerialize(),
            'groups' => (new AssignRoleToGroupRequest($id, null, [$scoped]))->jsonSerialize(),
            'service accounts' => (new AssignRoleToServiceAccountRequest($id, null, [$scoped]))->jsonSerialize(),
        ] as $which => $body) {
            self::assertSame([$scoped], $body['tenant_scope'] ?? null, $which);
        }
    }

    /**
     * The allowlist is one field wide on purpose: elsewhere `[]` is meaningful — a
     * replacement body clearing a list — and dropping it would make "remove every entry"
     * inexpressible.
     */
    public function testOtherEmptyListsAreStillSent(): void
    {
        $body = (new UpdateWebhookRequest(events: []))->jsonSerialize();

        self::assertSame([], $body['events'] ?? null, 'clearing a webhook event list must stay expressible');
    }
}
