<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Management;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\RequestStartEvent;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Core\TelemetryEvent;
use Axiam\Sdk\Management\ConflictError;
use Axiam\Sdk\Management\ManagementTransport;
use Axiam\Sdk\Management\Models;
use Axiam\Sdk\Management\NotFoundError;
use Axiam\Sdk\Management\PageRequest;
use Axiam\Sdk\Management\ValidationError;
use GuzzleHttp\Psr7\Response;

/**
 * The CONTRACT.md §27.9 required-test list, hand-written.
 *
 * The generated suites next door assert that all 146 operations reach the right route
 * with nothing dropped. These assert the RULES — the behaviours §27.4 specifies that are
 * true of the surface as a whole and that no per-operation test would catch.
 */
final class ManagementSemanticsTest extends ManagementTestCase
{
    // -- rule 1: no session, no wire call ---------------------------------

    /** An unauthenticated management call never reaches the server (§27.4 rule 1). */
    public function testWithoutASessionNothingIsSent(): void
    {
        $client = new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            orgId: self::ORG_ID,
            oidcTenantId: self::TENANT_ID,
            transportHandler: $this->handler = new \GuzzleHttp\Handler\MockHandler([]),
        );

        $this->expectException(AuthError::class);
        $client->management()->users()->get(self::ORG_ID);
    }

    /** The refusal names the operation, so it is diagnosable without a stack trace. */
    public function testTheSessionRefusalNamesTheOperation(): void
    {
        $client = new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            transportHandler: new \GuzzleHttp\Handler\MockHandler([]),
        );

        try {
            $client->management()->roles()->listItems();
            self::fail('expected an AuthError');
        } catch (AuthError $e) {
            self::assertStringContainsString('roles.list', $e->getMessage());
            self::assertStringContainsString('§27.4 rule 1', $e->getMessage());
        }
    }

    // -- rule 3: implicit ids, with a per-handle override ------------------

    /** `{org_id}` comes from the client when the call does not name one (§27.4 rule 3). */
    public function testOrgIdIsImplicitFromTheClient(): void
    {
        $client = $this->signedInClient(200, ['items' => [], 'total' => 0]);
        $client->management()->caCertificates()->listItems();

        self::assertStringContainsString(self::ORG_ID, $this->lastRequest()->getUri()->getPath());
    }

    /** `->inOrg()` re-scopes the routes it substitutes into (§27.4 rule 3). */
    public function testInOrgOverridesTheImplicitOrgId(): void
    {
        $other = '22222222-2222-4222-8222-222222222222';
        $client = $this->signedInClient(200, ['items' => [], 'total' => 0]);
        $client->management()->caCertificates()->inOrg($other)->listItems();

        self::assertStringContainsString($other, $this->lastRequest()->getUri()->getPath());
    }

    /**
     * `->inOrg()` returns a COPY; the handle it was called on is untouched.
     *
     * The failure this pins is not hypothetical on a management surface: a shared handle
     * silently repointed by an unrelated code path writes to the wrong tenant.
     */
    public function testInOrgDoesNotMutateTheHandleItWasCalledOn(): void
    {
        $other = '22222222-2222-4222-8222-222222222222';
        $client = $this->signedInWith(
            self::json(200, ['items' => [], 'total' => 0]),
            self::json(200, ['items' => [], 'total' => 0]),
        );

        $handle = $client->management()->caCertificates();
        $handle->inOrg($other)->listItems();
        self::assertStringContainsString($other, $this->lastRequest()->getUri()->getPath());

        $handle->listItems();
        self::assertStringContainsString(self::ORG_ID, $this->lastRequest()->getUri()->getPath());
    }

    /** A route needing an id the client never supplied refuses rather than sending `//`. */
    public function testAMissingScopeIdRefusesInsteadOfSendingAnEmptySegment(): void
    {
        $client = new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            transportHandler: new \GuzzleHttp\Handler\MockHandler([
                new Response(200, ['Set-Cookie' => 'axiam_access=t0ken; Path=/'], '{"user":{"id":"u"}}'),
            ]),
        );
        $client->login('admin@axiam.test', 'pw');

        $this->expectException(AxiamException::class);
        $this->expectExceptionMessageMatches('/organization id/');
        $client->management()->caCertificates()->listItems();
    }

    // -- rule 4: paging ----------------------------------------------------

    /** `Page::$total` is the server's count, NOT the number of items on the page. */
    public function testPageTotalIsNotTheItemCount(): void
    {
        $client = $this->signedInClient(200, [
            'items' => [self::role('one'), self::role('two')],
            'total' => 97,
        ]);

        $page = $client->management()->roles()->listItems();

        self::assertSame(97, $page->total);
        self::assertCount(2, $page);
        self::assertNotSame($page->total, $page->count());
    }

    /** Auto-paging stops on an EMPTY page, not on a short one (§27.4 rule 4). */
    public function testAutoPagingStopsOnAnEmptyPageNotAShortOne(): void
    {
        $client = $this->signedInWith(
            self::page([self::role('a'), self::role('b')], 5),
            self::page([self::role('c')], 5),   // SHORT — must not stop the walk
            self::page([], 5),                   // empty — stops here
        );

        $roles = $client->management()->roles();
        $seen = iterator_to_array(ManagementTransport::walk(
            static fn (PageRequest $p): \Axiam\Sdk\Management\Page => $roles->listItems($p),
        ), false);

        self::assertCount(3, $seen, 'a short page must not end the walk');
    }

    /** Auto-paging advances by the page SIZE, so a short page does not re-read items. */
    public function testAutoPagingAdvancesByTheRequestedLimit(): void
    {
        $client = $this->signedInWith(
            self::page([self::role('a')], 9),
            self::page([], 9),
        );

        $roles = $client->management()->roles();
        iterator_to_array(ManagementTransport::walk(
            static fn (PageRequest $p): \Axiam\Sdk\Management\Page => $roles->listItems($p),
            new PageRequest(0, 50),
        ), false);

        parse_str($this->lastRequest()->getUri()->getQuery(), $query);
        self::assertSame('50', $query['offset'] ?? null);
    }

    /** A bare-array endpoint returns a plain list, never a Page (§27.4 rule 4). */
    public function testABareArrayIsNotModelledAsAPage(): void
    {
        $client = $this->signedInClient(200, [self::resource('child')]);

        $children = $client->management()->resources()->listChildren(self::ORG_ID);

        self::assertIsArray($children);
        self::assertNotInstanceOf(\Axiam\Sdk\Management\Page::class, $children);
    }

    // -- rule 5: sparse vs replacement -------------------------------------

    /** A sparse body omits what you did not name — it does not null it (§27.4 rule 5). */
    public function testASparseUpdateSendsOnlyTheNamedField(): void
    {
        $client = $this->signedInClient(200, self::role('renamed'));
        $client->management()->roles()->update(self::ORG_ID, new Models\UpdateRole(name: 'renamed'));

        self::assertSame(['name' => 'renamed'], $this->lastBody());
    }

    /** A replacement body cannot be built with a field missing — that is a TypeError. */
    public function testAReplacementBodyRequiresEveryField(): void
    {
        $reflection = new \ReflectionClass(Models\CreateRoleRequest::class);
        $constructor = $reflection->getConstructor();
        self::assertNotNull($constructor);

        foreach ($constructor->getParameters() as $parameter) {
            self::assertFalse(
                $parameter->isOptional(),
                sprintf('%s is optional on a replacement body', $parameter->getName()),
            );
        }
    }

    // -- rule 6: deletes are not idempotent --------------------------------

    /** A second delete raises NotFoundError rather than succeeding quietly (§27.4 rule 6). */
    public function testASecondDeleteRaisesNotFound(): void
    {
        $client = $this->signedInWith(new Response(204), new Response(404));
        $roles = $client->management()->roles();

        $roles->delete(self::ORG_ID);

        $this->expectException(NotFoundError::class);
        $roles->delete(self::ORG_ID);
    }

    // -- rule 7: the classification table ----------------------------------

    /** 404 becomes NotFoundError (§27.4 rule 7). */
    public function testNotFoundIsClassified(): void
    {
        $client = $this->signedInWith(new Response(404));
        $this->expectException(NotFoundError::class);
        $client->management()->roles()->get(self::ORG_ID);
    }

    /** 409 becomes ConflictError (§27.4 rule 7). */
    public function testConflictIsClassified(): void
    {
        $client = $this->signedInWith(new Response(409));
        $this->expectException(ConflictError::class);
        $client->management()->roles()->get(self::ORG_ID);
    }

    /** 400 and 422 both become ValidationError (§27.4 rule 7). */
    public function testValidationIsClassifiedForBoth400And422(): void
    {
        foreach ([400, 422] as $status) {
            $client = $this->signedInWith(new Response($status));
            try {
                $client->management()->roles()->get(self::ORG_ID);
                self::fail("expected a ValidationError for HTTP {$status}");
            } catch (ValidationError $e) {
                self::assertStringContainsString((string) $status, $e->getMessage());
            }
        }
    }

    /** A validation body's per-field complaints reach the caller. */
    public function testValidationCarriesItsFieldErrors(): void
    {
        $client = $this->signedInWith(self::json(422, [
            'fields' => [['field' => 'name', 'message' => 'must not be blank']],
        ]));

        try {
            $client->management()->roles()->get(self::ORG_ID);
            self::fail('expected a ValidationError');
        } catch (ValidationError $e) {
            self::assertCount(1, $e->fields);
            self::assertSame('name', $e->fields[0]->field);
            self::assertSame('must not be blank', $e->fields[0]->message);
        }
    }

    /** A malformed validation body still classifies by STATUS, just with no fields. */
    public function testAMalformedValidationBodyStillClassifies(): void
    {
        $client = $this->signedInWith(new Response(400, [], '<html>gateway</html>'));

        try {
            $client->management()->roles()->get(self::ORG_ID);
            self::fail('expected a ValidationError');
        } catch (ValidationError $e) {
            self::assertSame([], $e->fields);
        }
    }

    /**
     * Each §27 sub-type keeps the parent §2 already gave its status (§27.4 rule 7).
     *
     * This is the counter-intuitive half of rule 7 and the one a port gets wrong: 404 and
     * 409 belong under `AuthzError`, NOT under `NetworkError`. A sibling SDK shipped
     * `ConflictError extends NetworkError` and this exact assertion is what caught it.
     * The consequence is concrete — a `catch (AuthzError $e)` written before §27 existed
     * must still catch both, and §16 must not retry either.
     */
    public function testEveryClassificationKeepsTheParentSection2GaveIt(): void
    {
        self::assertTrue(is_subclass_of(NotFoundError::class, AuthzError::class));
        self::assertTrue(is_subclass_of(ConflictError::class, AuthzError::class));
        self::assertTrue(is_subclass_of(ValidationError::class, NetworkError::class));

        self::assertFalse(is_subclass_of(NotFoundError::class, NetworkError::class));
        self::assertFalse(is_subclass_of(ConflictError::class, NetworkError::class));
        self::assertFalse(is_subclass_of(ValidationError::class, AuthzError::class));
    }

    // -- rule 8: only GET is retried ---------------------------------------

    /** A failed GET is retried (§27.4 rule 8 / §16). */
    public function testAFailedGetIsRetried(): void
    {
        $client = $this->signedInWith(new Response(503), self::json(200, self::role('ok')));

        $role = $client->management()->roles()->get(self::ORG_ID);

        self::assertSame('ok', $role->name);
        self::assertSame(3, $this->requestCount(), 'login + two GET attempts');
    }

    /** A failed POST is NOT retried — it may already have been applied (§27.4 rule 8). */
    public function testAFailedWriteIsNotRetried(): void
    {
        $client = $this->signedInWith(new Response(503), self::json(200, self::role('never')));

        try {
            $client->management()->roles()->create(new Models\CreateRoleRequest('d', false, 'n'));
            self::fail('expected a NetworkError');
        } catch (NetworkError $e) {
            self::assertSame(2, $this->requestCount(), 'login + exactly one POST attempt');
        }
    }

    /** A rejected body is not retried, even though ValidationError is a NetworkError. */
    public function testARejectedBodyIsNotRetriedThreeTimes(): void
    {
        $client = $this->signedInWith(new Response(422));

        try {
            $client->management()->roles()->create(new Models\CreateRoleRequest('d', false, 'n'));
            self::fail('expected a ValidationError');
        } catch (ValidationError) {
            self::assertSame(2, $this->requestCount());
        }
    }

    // -- rule 10: nothing is cached ----------------------------------------

    /** The same read twice is two wire calls; §27 caches nothing (§27.4 rule 10). */
    public function testTheSameReadTwiceIsTwoWireCalls(): void
    {
        $client = $this->signedInWith(
            self::json(200, self::role('a')),
            self::json(200, self::role('b')),
        );

        $roles = $client->management()->roles();
        self::assertSame('a', $roles->get(self::ORG_ID)->name);
        self::assertSame('b', $roles->get(self::ORG_ID)->name);
        self::assertSame(3, $this->requestCount());
    }

    // -- rule 11: telemetry carries the path TEMPLATE ----------------------

    /**
     * §19 events name the path TEMPLATE, never the substituted path (§27.4 rule 11).
     *
     * A metrics label carrying a user id is an unbounded-cardinality series, and on this
     * surface it is also a slow identifier leak into whatever consumes the telemetry.
     */
    public function testTelemetryUsesThePathTemplate(): void
    {
        $seen = [];
        $client = new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            orgId: self::ORG_ID,
            oidcTenantId: self::TENANT_ID,
            transportHandler: $this->handler = new \GuzzleHttp\Handler\MockHandler([
                new Response(200, ['Set-Cookie' => 'axiam_access=t0ken; Path=/'], '{"user":{"id":"u"}}'),
                self::json(200, self::role('a')),
            ]),
            telemetryHook: static function (TelemetryEvent $event) use (&$seen): void {
                if ($event instanceof RequestStartEvent) {
                    $seen[] = $event->pathTemplate;
                }
            },
        );
        $client->login('admin@axiam.test', 'pw');
        $client->management()->roles()->get(self::ORG_ID);

        self::assertContains('/api/v1/roles/{role_id}', $seen);
        foreach ($seen as $template) {
            self::assertStringNotContainsString(self::ORG_ID, $template);
        }
    }

    // -- §27.5: one-time secrets -------------------------------------------

    /** A `Sensitive` in a request body reaches the wire in the clear (§27.5). */
    public function testASecretReachesTheWireUnredacted(): void
    {
        $client = $this->signedInWith(self::json(200, self::webhook()));

        $client->management()->webhooks()->update(
            self::ORG_ID,
            new Models\UpdateWebhookRequest(secret: new Sensitive('hunter2')),
        );

        self::assertStringContainsString('hunter2', (string) $this->lastRequest()->getBody());
        self::assertStringNotContainsString('[SENSITIVE]', (string) $this->lastRequest()->getBody());
    }

    /** ...but the SAME body rendered anywhere else stays redacted (§27.5). */
    public function testTheSameSecretIsRedactedInAnOrdinaryRendering(): void
    {
        $body = new Models\UpdateWebhookRequest(secret: new Sensitive('hunter2'));

        $encoded = (string) json_encode($body);

        self::assertStringContainsString('[SENSITIVE]', $encoded);
        self::assertStringNotContainsString('hunter2', $encoded);
    }

    // -- fixtures ----------------------------------------------------------

    /**
     * A minimal `Role` object as the server would send it.
     *
     * @return array<string,mixed>
     */
    private static function role(string $name): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'description' => 'd',
            'id' => self::ORG_ID,
            'is_global' => false,
            'name' => $name,
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    /**
     * A minimal `WebhookResponse` object as the server would send it.
     *
     * @return array<string,mixed>
     */
    private static function webhook(): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'enabled' => true,
            'events' => ['user.created'],
            'id' => self::ORG_ID,
            'retry_policy' => [
                'backoff_multiplier' => 1.5,
                'initial_delay_secs' => 1,
                'max_retries' => 3,
            ],
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
            'url' => 'https://example.test/hook',
        ];
    }

    /**
     * A minimal `Resource` object as the server would send it.
     *
     * @return array<string,mixed>
     */
    private static function resource(string $name): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'id' => self::ORG_ID,
            'metadata' => [],
            'name' => $name,
            'resource_type' => 'folder',
            'tenant_id' => self::TENANT_ID,
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }
}
