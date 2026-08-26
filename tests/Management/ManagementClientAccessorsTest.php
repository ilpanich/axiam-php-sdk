<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Management;

use Axiam\Sdk\Management\ManagementApi;
use GuzzleHttp\Psr7\Response;

/**
 * CONTRACT.md §27.2/§27.3 — the namespace handles sit on the client.
 *
 * §27.3's PHP row is `$client->serviceAccounts()->rotateSecret($id)`, and §27.2 rule 4
 * makes the single `management()` accessor the ADDITIONAL one. Both forms therefore
 * exist, and rule 4 requires that "where an SDK offers both, the two MUST return
 * equivalent handles".
 *
 * Equivalent means the same REQUEST, not merely the same class — a direct accessor that
 * built a handle with a default scope instead of the client's would return the right type
 * and read the wrong tenant. So the assertions below compare what each form actually put
 * on the wire.
 */
final class ManagementClientAccessorsTest extends ManagementTestCase
{
    /** Every namespace the aggregate exposes is also directly on the client. */
    public function testEveryNamespaceIsReachableBothWays(): void
    {
        $client = $this->signedInClientNoResponse();

        $onAggregate = array_filter(
            get_class_methods(ManagementApi::class),
            static fn (string $name): bool => $name !== '__construct' && $name !== 'manifest',
        );

        self::assertNotEmpty($onAggregate);
        foreach ($onAggregate as $name) {
            self::assertTrue(
                method_exists($client, $name),
                "§27.3 puts `{$name}` on the client, not only behind management()",
            );
        }
        // 24 namespaces. Pinned so a partial regeneration that dropped one fails here
        // rather than quietly shipping 23.
        self::assertCount(24, $onAggregate);
    }

    /** Both forms reach the same route with the client's own scope. */
    public function testTheTwoFormsIssueTheSameRequest(): void
    {
        $page = ['items' => [], 'total' => 0];
        $client = $this->signedInWith(
            new Response(200, ['Content-Type' => 'application/json'], (string) json_encode($page)),
            new Response(200, ['Content-Type' => 'application/json'], (string) json_encode($page)),
        );

        $client->roles()->listItems();
        $direct = $this->lastRequest();

        $client->management()->roles()->listItems();
        $viaAggregate = $this->lastRequest();

        self::assertSame($direct->getMethod(), $viaAggregate->getMethod());
        self::assertSame(
            $direct->getUri()->getPath(),
            $viaAggregate->getUri()->getPath(),
        );
        self::assertSame(
            $direct->getUri()->getQuery(),
            $viaAggregate->getUri()->getQuery(),
        );
    }

    /**
     * A direct accessor carries the client's implicit `{org_id}`, not a bare default.
     *
     * This is the failure the equivalence rule exists to prevent: a forwarding accessor
     * that constructed its own handle would compile, return the right type, and address
     * the wrong organization.
     */
    public function testADirectAccessorCarriesTheClientsOwnScope(): void
    {
        $client = $this->signedInClient(200, ['items' => [], 'total' => 0]);

        $client->caCertificates()->listItems();

        self::assertStringContainsString(
            self::ORG_ID,
            $this->lastRequest()->getUri()->getPath(),
        );
    }

    /** Acquiring a handle either way performs no I/O (§27.2 rule 1). */
    public function testAcquiringAHandlePerformsNoIO(): void
    {
        $client = $this->signedInClientNoResponse();
        $before = \count($this->requests);

        $client->roles();
        $client->serviceAccounts();
        $client->management()->certificates();

        self::assertCount($before, $this->requests);
    }
}
