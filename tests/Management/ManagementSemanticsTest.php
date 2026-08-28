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
 * The generated suites next door assert that all 147 operations reach the right route
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

    // -- rule 4: search ----------------------------------------------------

    /**
     * A term on the page request reaches the QUERY STRING (§27.4 rule 4).
     *
     * Asserted on the request URI rather than on the argument, because a term the SDK
     * accepts and never sends is exactly the failure this test exists for: every
     * caller-side assertion still passes while the server returns the unfiltered set.
     */
    public function testASearchTermIsSentAsAQueryParameter(): void
    {
        $client = $this->signedInClient(200, ['items' => [self::role('ada')], 'total' => 1]);

        $client->management()->roles()->listItems(new PageRequest(search: 'ada'));

        parse_str($this->lastRequest()->getUri()->getQuery(), $query);
        self::assertSame('ada', $query['search'] ?? null);
    }

    /**
     * The server does the filtering, and `total` counts MATCHES (§27.4 rule 4).
     *
     * The page carries what the server sent, unfiltered by the SDK. Filtering client-side
     * after the fetch would give a pager whose page count belongs to a different result
     * set than the page it is showing.
     */
    public function testSearchDoesNotFilterClientSide(): void
    {
        $client = $this->signedInClient(200, [
            // A server that matched loosely still gets its answer through untouched.
            'items' => [self::role('ada'), self::role('adalovelace')],
            'total' => 2,
        ]);

        $page = $client->management()->roles()->listItems(new PageRequest(search: 'ada'));

        self::assertCount(2, $page);
        self::assertSame(2, $page->total);
    }

    /** With no term, no `search` key is sent at all — assert the exact key set. */
    public function testNoSearchTermSendsNoSearchKey(): void
    {
        $client = $this->signedInClient(200, ['items' => [], 'total' => 0]);

        $client->management()->roles()->listItems(new PageRequest(0, 25));

        parse_str($this->lastRequest()->getUri()->getQuery(), $query);
        self::assertSame(['offset' => '0', 'limit' => '25'], $query);
    }

    /**
     * An empty or whitespace-only term is the SAME request as none (§27.4 rule 4).
     *
     * A search box that fires on every keystroke sends one the moment it is cleared, and
     * "rows containing the empty string" is a different question from "all rows".
     *
     * @dataProvider blankTerms
     */
    public function testABlankSearchTermIsTreatedAsNone(string $term): void
    {
        $client = $this->signedInClient(200, ['items' => [], 'total' => 0]);

        $client->management()->roles()->listItems(new PageRequest(0, 25, $term));

        parse_str($this->lastRequest()->getUri()->getQuery(), $query);
        self::assertSame(['offset' => '0', 'limit' => '25'], $query);
    }

    /** @return iterable<string,array{string}> */
    public static function blankTerms(): iterable
    {
        yield 'empty' => [''];
        yield 'spaces' => ['   '];
        yield 'tab and newline' => ["\t\n"];
    }

    /** A term is trimmed but never truncated — the server's length cap stays the server's. */
    public function testASearchTermIsTrimmedButNotShortened(): void
    {
        $long = str_repeat('a', 300);
        $client = $this->signedInClient(200, ['items' => [], 'total' => 0]);

        $client->management()->roles()->listItems(new PageRequest(search: "  {$long}  "));

        parse_str($this->lastRequest()->getUri()->getQuery(), $query);
        self::assertSame($long, $query['search'] ?? null);
    }

    /**
     * The auto-paging form carries the term on EVERY request of the walk (§27.4 rule 4).
     *
     * Asserted on each recorded request rather than on the count: a walk that filtered
     * only its first request returns the matches followed by the unfiltered tail, which
     * reads as a server bug from the caller's side.
     */
    public function testAutoPagingCarriesTheSearchTermOnEveryRequest(): void
    {
        $client = $this->signedInWith(
            self::page([self::role('ada')], 3),
            self::page([self::role('adele')], 3),
            self::page([], 3),
        );

        $roles = $client->management()->roles();
        iterator_to_array(ManagementTransport::walk(
            static fn (PageRequest $p): \Axiam\Sdk\Management\Page => $roles->listItems($p),
            new PageRequest(0, 1, 'ad'),
        ), false);

        // Slice off the login POST; every management request that follows must carry it.
        $walked = \array_slice($this->requests, 1);
        self::assertCount(3, $walked);
        foreach ($walked as $i => $request) {
            parse_str($request->getUri()->getQuery(), $query);
            self::assertSame('ad', $query['search'] ?? null, "request {$i} dropped the term");
        }
    }

    /**
     * `search` rides on the page request, not as a third argument on twenty methods.
     *
     * §27.4 rule 4 requires this shape, and it is what makes the walk above work at all:
     * a per-method argument has nowhere to live between one request and the next.
     */
    public function testSearchIsNotAGeneratedMethodArgument(): void
    {
        $parameters = (new \ReflectionMethod(
            \Axiam\Sdk\Management\RolesApi::class,
            'listItems',
        ))->getParameters();

        self::assertSame(['page'], array_map(
            static fn (\ReflectionParameter $p): string => $p->getName(),
            $parameters,
        ));
    }

    /** A walk that starts from a term keeps it through `next()`, offset by offset. */
    public function testTheNextRequestKeepsTheTerm(): void
    {
        $request = new PageRequest(0, 25, ' ada ');

        $next = $request->next();

        self::assertSame(25, $next->offset);
        self::assertSame(' ada ', $next->search, 'the raw term is carried verbatim');
        self::assertSame('ada', $next->toQuery()['search'] ?? null, 'and normalised on the wire');
    }

    /** `matching()` returns a COPY, so a shared request cannot be repointed. */
    public function testMatchingReturnsACopy(): void
    {
        $request = new PageRequest(10, 25, 'ada');

        $other = $request->matching('grace');

        self::assertSame('ada', $request->search);
        self::assertSame('grace', $other->search);
        self::assertSame(10, $other->offset);
        self::assertSame(25, $other->limit);
    }

    // -- §27.11: model additions -------------------------------------------

    /**
     * An unrecognised enum value decodes to `Unknown` rather than failing the response
     * it arrived in (§27.11 rule 1).
     *
     * The whole point is the blast radius: the page below carries two tenants, and only
     * one of them has a `kind` this SDK has never seen. A closed enum would throw while
     * decoding it and take the other tenant — which the caller did ask for — down with it.
     */
    public function testAnUnknownEnumValueDecodesInsteadOfFailingThePage(): void
    {
        $client = $this->signedInClient(200, [
            'items' => [
                self::tenant('ordinary', 'standard'),
                self::tenant('from-the-future', 'sandbox'),
            ],
            'total' => 2,
        ]);

        $page = $client->management()->tenants()->listItems();

        self::assertCount(2, $page, 'one unknown value must not take down the page');
        self::assertSame(Models\TenantKind::Standard, $page->items[0]->kind);
        self::assertSame(Models\TenantKind::Unknown, $page->items[1]->kind);
    }

    /**
     * `Unknown` is a case of its own, and never one of the known ones.
     *
     * Reading a new `"suspended"` as whichever case was declared first would turn a new
     * server state into a wrong one, and on this surface these values gate access.
     */
    public function testUnknownIsNeverMistakenForAKnownCase(): void
    {
        $unknown = Models\TenantKind::fromWire('sandbox');

        self::assertSame(Models\TenantKind::Unknown, $unknown);
        self::assertNotSame(Models\TenantKind::Standard, $unknown);
        self::assertNotSame(Models\TenantKind::Organization, $unknown);
        self::assertSame('', $unknown->value, 'no server value is the empty string');
    }

    /** `kind` is read-only — it is on neither create nor update body (§27.11 rule 2). */
    public function testTenantKindIsNotWritable(): void
    {
        foreach ([Models\CreateTenantRequest::class, Models\UpdateTenant::class] as $model) {
            $names = array_map(
                static fn (\ReflectionParameter $p): string => $p->getName(),
                (new \ReflectionClass($model))->getConstructor()?->getParameters() ?? [],
            );
            self::assertNotContains('kind', $names, "{$model} must not accept kind");
        }
    }

    /** An absent `kind` decodes as null rather than failing — the field is optional. */
    public function testAnAbsentTenantKindDecodes(): void
    {
        $row = self::tenant('legacy', null);
        $client = $this->signedInClient(200, ['items' => [$row], 'total' => 1]);

        $page = $client->management()->tenants()->listItems();

        self::assertNull($page->items[0]->kind);
    }

    /**
     * `trusted_anchors` is nullable and is NOT coalesced to zero (§27.11 rule 3).
     *
     * "the listener trusts no CAs" and "there was no listener to ask" are different
     * operational states, and only one of them is a problem.
     */
    public function testTrustedAnchorsKeepsNullDistinctFromZero(): void
    {
        $absent = Models\MtlsTrustAnchorResponse::fromArray([
            'ca_certificate_id' => self::ORG_ID,
            'message' => 'stored; applies at next start',
            'mtls_trust_anchor' => true,
            'restart_required' => true,
        ]);
        $none = Models\MtlsTrustAnchorResponse::fromArray([
            'ca_certificate_id' => self::ORG_ID,
            'message' => 'reloaded',
            'mtls_trust_anchor' => false,
            'restart_required' => false,
            'trusted_anchors' => 0,
        ]);

        self::assertNull($absent->trustedAnchors);
        self::assertSame(0, $none->trustedAnchors);
        self::assertArrayNotHasKey('trusted_anchors', $absent->jsonSerialize());
    }

    /**
     * `bound_service_account_id` is populated by `certificates.list` and null on `get`,
     * with no second request to fill it in (§27.11 rule 4).
     */
    public function testTheCertificateProjectionIsListOnlyAndCostsNoExtraRequest(): void
    {
        $bound = '22222222-2222-4222-8222-222222222222';
        $client = $this->signedInWith(
            self::page([self::certificate($bound)], 1),
            self::json(200, self::certificate(null)),
        );

        $certificates = $client->management()->certificates();
        $listed = $certificates->listItems();
        $fetched = $certificates->get(self::ORG_ID);

        self::assertSame($bound, $listed->items[0]->boundServiceAccountId);
        self::assertNull($fetched->boundServiceAccountId, 'get does not carry the projection');
        self::assertCount(2, \array_slice($this->requests, 1), 'and does not go and fetch it');
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

    /**
     * A minimal `Tenant` object as the server would send it.
     *
     * @return array<string,mixed>
     */
    private static function tenant(string $slug, ?string $kind): array
    {
        $row = [
            'created_at' => '2026-08-26T00:00:00Z',
            'id' => self::TENANT_ID,
            'metadata' => [],
            'name' => $slug,
            'organization_id' => self::ORG_ID,
            'slug' => $slug,
            'status' => 'active',
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
        if ($kind !== null) {
            $row['kind'] = $kind;
        }

        return $row;
    }

    /**
     * A minimal `Certificate` object, with or without the list-only projection.
     *
     * @return array<string,mixed>
     */
    private static function certificate(?string $boundServiceAccountId): array
    {
        $row = [
            'cert_type' => 'device',
            'created_at' => '2026-08-26T00:00:00Z',
            'fingerprint' => 'aa:bb',
            'id' => self::ORG_ID,
            'issuer_ca_id' => self::ORG_ID,
            'key_algorithm' => 'ed25519',
            'metadata' => [],
            'not_after' => '2027-08-26T00:00:00Z',
            'not_before' => '2026-08-26T00:00:00Z',
            'public_cert_pem' => '-----BEGIN CERTIFICATE-----',
            'status' => 'active',
            'subject' => 'CN=device-001',
            'tenant_id' => self::TENANT_ID,
        ];
        if ($boundServiceAccountId !== null) {
            $row['bound_service_account_id'] = $boundServiceAccountId;
        }

        return $row;
    }
}
