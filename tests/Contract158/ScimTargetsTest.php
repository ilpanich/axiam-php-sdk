<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract158;

use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AxiamException;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Management\ConflictError;
use Axiam\Sdk\Management\ManagementTransport;
use Axiam\Sdk\Management\Models;
use Axiam\Sdk\Management\NotFoundError;
use Axiam\Sdk\Management\Page;
use Axiam\Sdk\Management\PageRequest;
use Axiam\Sdk\Management\ReadModifyWrite;
use Axiam\Sdk\Management\ValidationError;
use Axiam\Sdk\Tests\Fixtures\RoutedHandler;
use GuzzleHttp\Psr7\Response;

/**
 * The `scim_targets` namespace — CONTRACT.md §31.8's six required tests. The credential is
 * generated at run time.
 */
final class ScimTargetsTest extends ManagementRouteTestCase
{
    private const TARGETS = '/api/v1/scim-targets';

    private static function credential(): string
    {
        return self::runtimeSecret('scim-');
    }

    /**
     * @param array<string,mixed> $extra
     * @return array<string,mixed>
     */
    private static function target(array $extra = []): array
    {
        return array_merge([
            'id' => self::uuid(), 'tenant_id' => self::TENANT_ID, 'name' => 'Downstream',
            'base_url' => 'https://idp.example/scim/v2', 'enabled' => true,
            'auth' => ['type' => 'bearer'], 'scope' => ['type' => 'all_users'],
            'push_groups' => false, 'user_name_from' => 'username', 'deprovision' => 'deactivate',
            'created_at' => '2026-10-05T00:00:00Z', 'updated_at' => '2026-10-05T00:00:00Z',
            'state' => ['last_success_at' => null, 'last_failure_at' => null, 'last_failure_reason' => null,
                'consecutive_failures' => 0, 'dead_lettered_total' => 0, 'last_reconciled_at' => null],
        ], $extra);
    }

    private static function input(?string $credential = null): Models\ScimTargetInput
    {
        return new Models\ScimTargetInput(
            auth: new Models\ScimTargetAuthBearer(),
            baseUrl: 'https://idp.example/scim/v2',
            name: 'Downstream',
            scope: new Models\ScimTargetScopeAllUsers(),
            credential: $credential !== null ? new Sensitive($credential) : null,
        );
    }

    // -- 1. Redaction --------------------------------------------------------------------

    public function testTheCredentialIsOnTheWireAndInNoRendering(): void
    {
        $client = $this->client();
        $credential = self::credential();
        $body = self::input($credential);
        self::assertNoFragment(self::renderings($body), $credential);

        $this->routes->on('POST', self::TARGETS, RoutedHandler::json(400, ['error' => 'validation_error', 'message' => 'base_url: refused']));
        try {
            $client->scimTargets()->create($body);
            self::fail('expected a ValidationError');
        } catch (ValidationError $e) {
            self::assertNoFragment(self::renderings($e), $credential);
        }
        $sent = $this->bodies('POST', self::TARGETS)[0];
        self::assertIsArray($sent);
        self::assertSecretEquals($credential, $sent['credential'] ?? null, 'credential');
    }

    // -- 2. No credential on the response ----------------------------------------------

    public function testACredentialInAResponseIsDropped(): void
    {
        $client = $this->client();
        $leaked = self::credential();
        $id = self::uuid();
        $this->routes->on('GET', self::TARGETS . '/' . $id, RoutedHandler::json(200, self::target(['credential' => $leaked, 'credential_set' => true])));

        $target = $client->scimTargets()->get($id);
        self::assertNoFragment(self::renderings($target), $leaked);
        self::assertFalse(property_exists($target, 'credential'), 'no accessor for a credential');
        self::assertSame('Downstream', $target->name);

        // ... nor through an unknown auth variant, which keeps its discriminator alone.
        $odd = Models\ScimTargetAuth::fromArray(['type' => 'mtls', 'credential' => $leaked]);
        self::assertInstanceOf(Models\ScimTargetAuthUnknown::class, $odd);
        self::assertSame(['tag' => 'mtls'], get_object_vars($odd));
        self::assertNoFragment(self::renderings($odd), $leaked);
    }

    /**
     * R-20 (§34.2 P12.1, §31.2): an unknown `auth` or `scope` arm keeps its discriminator and
     * nothing else — not the server's object minus a list of names — so a secret under a name
     * nobody listed is not surfaced either.
     */
    public function testAnUnknownArmKeepsItsDiscriminatorAndNothingElse(): void
    {
        $client = $this->client();
        $cert = self::runtimeSecret('cert-');
        $selector = self::runtimeSecret('sel-');
        $id = self::uuid();
        $this->routes->on('GET', self::TARGETS . '/' . $id, RoutedHandler::json(200, self::target([
            'auth' => ['type' => 'mtls', 'cert' => $cert, 'credential' => $cert],
            'scope' => ['type' => 'by_filter', 'filter' => $selector],
        ])));

        $target = $client->scimTargets()->get($id);
        self::assertInstanceOf(Models\ScimTargetAuthUnknown::class, $target->auth);
        self::assertInstanceOf(Models\ScimTargetScopeUnknown::class, $target->scope);
        self::assertSame(['tag' => 'mtls'], get_object_vars($target->auth), 'the discriminator and nothing else');
        self::assertSame(['tag' => 'by_filter'], get_object_vars($target->scope), 'the discriminator and nothing else');
        self::assertNoFragment(self::renderings($target->auth) . self::renderings($target->scope), $cert);
        self::assertNoFragment(self::renderings($target->scope), $selector);
        self::assertNoFragment(self::renderings($target), $cert);
    }

    /**
     * R-21 (§34.2 P12.2, §7 rule 1): rendering a response that carries an unknown arm for a
     * log line never fails; the refusal to send that value is the request path's, local, and
     * before anything is sent.
     */
    public function testAnUnknownArmRendersForALogLineAndIsRefusedOnlyOnTheWayOut(): void
    {
        $client = $this->client();
        $id = self::uuid();
        $this->routes->on('GET', self::TARGETS . '/' . $id, RoutedHandler::json(200, self::target([
            'auth' => ['type' => 'mtls', 'certificate_id' => self::uuid()],
            'scope' => ['type' => 'by_filter'],
        ])));
        $target = $client->scimTargets()->get($id);

        $logged = json_encode($target, JSON_THROW_ON_ERROR);
        self::assertStringContainsString('"auth":{"type":"mtls"}', $logged);
        self::assertStringContainsString('"scope":{"type":"by_filter"}', $logged);
        $body = ReadModifyWrite::scimTarget($target);
        self::assertStringContainsString('"type":"mtls"', json_encode($body, JSON_THROW_ON_ERROR), 'the input renders for a log line too');

        $this->routes->on('PUT', self::TARGETS . '/' . $id, RoutedHandler::json(200, self::target()));
        try {
            $client->scimTargets()->update($id, $body);
            self::fail('an unknown auth type must not be sent');
        } catch (AxiamException $e) {
            self::assertStringContainsString('mtls', $e->getMessage());
        }
        self::assertSame([], $this->bodies('PUT', self::TARGETS . '/' . $id), 'refused locally: nothing was sent');
    }

    // -- 3. Replacement and the omitted credential ----------------------------------------

    public function testUpdateWithoutACredentialSendsNoKeyAndTheVariantsKeepTheirShape(): void
    {
        $client = $this->client();
        $id = self::uuid();
        $this->routes->on('PUT', self::TARGETS . '/' . $id, RoutedHandler::json(200, self::target()));
        $credential = self::credential();

        $client->scimTargets()->update($id, self::input());
        $client->scimTargets()->update($id, self::input($credential));
        $sent = $this->bodies('PUT', self::TARGETS . '/' . $id);
        self::assertIsArray($sent[0]);
        self::assertArrayNotHasKey('credential', $sent[0], 'no credential key');
        self::assertIsArray($sent[1]);
        self::assertSecretEquals($credential, $sent[1]['credential'] ?? null, 'credential');

        self::assertSame(['type' => 'bearer'], (new Models\ScimTargetAuthBearer())->toArray());
        self::assertEquals(
            ['type' => 'oauth2_client_credentials', 'client_id' => 'axiam', 'scope' => 'scim', 'token_url' => 'https://idp.example/token'],
            (new Models\ScimTargetAuthOauth2ClientCredentials('axiam', 'https://idp.example/token', 'scim'))->toArray(),
        );
        self::assertSame(['type' => 'all_users'], (new Models\ScimTargetScopeAllUsers())->toArray());
        $group = self::uuid();
        self::assertEquals(['type' => 'groups', 'group_ids' => [$group]], (new Models\ScimTargetScopeGroups([$group]))->toArray());

        $this->expectException(\ArgumentCountError::class);
        /** @phpstan-ignore-next-line deliberately missing arguments */
        new Models\ScimTargetInput(auth: new Models\ScimTargetAuthBearer(), baseUrl: 'https://x');
    }

    // -- 4. Open decoding and pagination ------------------------------------------------

    public function testUnknownValuesDecodeAndThePagerCarriesSearch(): void
    {
        $client = $this->client();
        $odd = self::target([
            'auth' => ['type' => 'mtls', 'certificate_id' => self::uuid()],
            'deprovision' => 'archive', 'user_name_from' => 'employee_number', 'state' => null,
        ]);
        $failing = self::target(['state' => [
            'last_success_at' => null, 'last_failure_at' => '2026-10-05T01:00:00Z',
            'last_failure_reason' => 'a reason this SDK has never seen',
            'consecutive_failures' => 3, 'dead_lettered_total' => 1, 'last_reconciled_at' => null,
        ]]);
        $this->routes->on('GET', self::TARGETS, static function ($request) use ($odd, $failing): Response {
            parse_str($request->getUri()->getQuery(), $query);
            $offset = (int) ($query['offset'] ?? 0);
            $items = [0 => [$odd], 1 => [$failing]][$offset] ?? [];

            return RoutedHandler::json(200, ['items' => $items, 'total' => 2, 'offset' => $offset, 'limit' => 1]);
        });

        $targets = $client->scimTargets();
        $page = $targets->listItems(new PageRequest(0, 1, 'downstream'));
        self::assertSame(2, $page->total);
        self::assertInstanceOf(Models\ScimTargetAuthUnknown::class, $page->items[0]->auth);
        self::assertSame('mtls', $page->items[0]->auth->tag);
        self::assertSame(Models\DeprovisionPolicy::Unknown, $page->items[0]->deprovision);
        self::assertSame(Models\UserNameSource::Unknown, $page->items[0]->userNameFrom);
        self::assertNull($page->items[0]->state);

        $all = iterator_to_array(ManagementTransport::walk(
            static fn (PageRequest $p): Page => $targets->listItems($p),
            new PageRequest(0, 1, 'downstream'),
        ), false);
        self::assertCount(2, $all);
        self::assertSame('a reason this SDK has never seen', $all[1]->state?->lastFailureReason);
        foreach ($this->queries('GET', self::TARGETS) as $query) {
            self::assertStringContainsString('search=downstream', $query);
        }

        // An unknown variant decodes but is never sent.
        try {
            ReadModifyWrite::scimTarget($all[0])->toArray();
            self::fail('an unknown auth type must not render');
        } catch (AxiamException) {
        }
    }

    // -- 5. No retry ---------------------------------------------------------------------

    public function testNoWriteIsRetriedOn503(): void
    {
        $client = $this->client(retry: true);
        $id = self::uuid();
        $routes = [
            ['POST', self::TARGETS],
            ['PUT', self::TARGETS . '/' . $id],
            ['DELETE', self::TARGETS . '/' . $id],
            ['POST', self::TARGETS . '/' . $id . '/reconcile'],
        ];
        foreach ($routes as [$method, $path]) {
            $this->routes->on($method, $path, new Response(503));
        }
        $t = $client->scimTargets();
        foreach ([
            fn () => $t->create(self::input(self::credential())),
            fn () => $t->update($id, self::input()),
            fn () => $t->delete($id),
            fn () => $t->reconcile($id),
        ] as $call) {
            try {
                $call();
                self::fail('expected a NetworkError');
            } catch (NetworkError $e) {
                self::assertNotInstanceOf(ValidationError::class, $e);
            }
        }
        foreach ($routes as [$method, $path]) {
            self::assertCount(1, $this->routes->sent($method, $path), $method . ' ' . $path);
        }
    }

    // -- 6. Errors and reconcile -------------------------------------------------------

    public function testStatusesMapAndReconcileIsABodilessTwoHundredTwo(): void
    {
        $client = $this->client();
        $id = self::uuid();
        $other = self::uuid();
        $this->routes->on('POST', self::TARGETS, RoutedHandler::json(400, ['error' => 'validation_error', 'message' => 'credential: required on create']));
        $this->routes->on('PUT', self::TARGETS . '/' . $id, RoutedHandler::json(409, ['error' => 'conflict', 'message' => 'the SCIM target changed since it was read']));
        $this->routes->on('POST', self::TARGETS . '/' . $other . '/reconcile', RoutedHandler::json(409, ['error' => 'conflict', 'message' => 'a run holds the claim']));
        $this->routes->on('GET', self::TARGETS . '/' . $id, RoutedHandler::json(404, ['error' => 'not_found', 'message' => 'no']));
        $this->routes->on('DELETE', self::TARGETS . '/' . $id, RoutedHandler::json(401, ['error' => 'unauthorized', 'message' => 'human only']));
        $this->routes->on('POST', '/api/v1/auth/refresh', RoutedHandler::json(401, ['error' => 'unauthorized']));
        $this->routes->on('POST', self::TARGETS . '/' . $id . '/reconcile', RoutedHandler::json(202, ['target_id' => $id, 'status' => 'started']));

        $t = $client->scimTargets();
        $expect = function (callable $call, string $type): \Throwable {
            try {
                $call();
            } catch (\Throwable $e) {
                self::assertInstanceOf($type, $e);

                return $e;
            }
            self::fail('expected ' . $type);
        };
        self::assertStringContainsString('credential', $expect(fn () => $t->create(self::input()), ValidationError::class)->getMessage());
        $expect(fn () => $t->update($id, self::input()), ConflictError::class);
        $expect(fn () => $t->reconcile($other), ConflictError::class);
        $expect(fn () => $t->get($id), NotFoundError::class);
        $expect(fn () => $t->delete($id), AuthError::class);

        $accepted = $t->reconcile($id);
        self::assertSame($id, $accepted->targetId);
        self::assertSame('started', $accepted->status);
        $sent = $this->routes->sent('POST', self::TARGETS . '/' . $id . '/reconcile');
        self::assertSame('', (string) $sent[0]->getBody(), 'reconcile sends no body');
    }

    public function testAReadConvertsIntoTheReplacementBodyWithoutACredential(): void
    {
        $target = Models\ScimTargetResponse::fromArray(self::target());
        $body = ReadModifyWrite::scimTarget($target);
        self::assertNull($body->credential, 'absent keeps the stored credential');
        self::assertSame($target->baseUrl, $body->baseUrl);
        self::assertTrue($body->enabled);

        $credential = self::credential();
        $moved = ReadModifyWrite::scimTarget($target, ['base_url' => 'https://idp2.example/scim/v2', 'credential' => $credential]);
        self::assertSame('https://idp2.example/scim/v2', $moved->baseUrl);
        self::assertNotNull($moved->credential);
        self::assertSecretEquals($credential, $moved->credential->reveal(), 'credential');
    }
}
