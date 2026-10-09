<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract158;

use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Management\ConflictError;
use Axiam\Sdk\Management\JsonNull;
use Axiam\Sdk\Management\Models;
use Axiam\Sdk\Management\NotFoundError;
use Axiam\Sdk\Management\ReadModifyWrite;
use Axiam\Sdk\Management\ValidationError;
use Axiam\Sdk\Tests\Fixtures\RoutedHandler;
use GuzzleHttp\Psr7\Response;

/**
 * The `directory` namespace — CONTRACT.md §30.8's six required tests, plus the sync status
 * and the read-modify-write helper. The bind secret is generated at run time.
 */
final class DirectoryTest extends ManagementRouteTestCase
{
    private const DIRECTORY = '/api/v1/tenants/' . self::TENANT_ID . '/directory';

    private static function secret(): string
    {
        return self::runtimeSecret('bind-');
    }

    /** @return array<string,mixed> */
    private static function config(): array
    {
        return [
            'id' => self::uuid(), 'tenant_id' => self::TENANT_ID, 'enabled' => true, 'kind' => 'active_directory',
            'url' => 'ldaps://dc.corp.example', 'start_tls' => false, 'bind_dn' => 'cn=svc,dc=corp',
            'base_dn' => 'dc=corp', 'user_filter' => '(sAMAccountName={username})',
            'user_attribute_map' => ['username' => 'sAMAccountName', 'email' => 'mail',
                'display_name' => 'displayName', 'external_id' => 'objectGUID'],
            'group_base_dn' => null, 'group_filter' => null, 'group_member_attribute' => 'member',
            'group_nesting_depth' => 5, 'group_mappings' => [], 'sync_interval_secs' => 3600,
            'jit_provisioning' => false, 'trust_anchors_pem' => [],
            'created_at' => '2026-10-04T00:00:00Z', 'updated_at' => '2026-10-04T00:00:00Z',
        ];
    }

    private static function setBody(?string $secret = null): Models\SetDirectoryConfig
    {
        return new Models\SetDirectoryConfig(
            baseDn: 'dc=corp',
            bindDn: 'cn=svc,dc=corp',
            enabled: true,
            kind: Models\DirectoryKind::ActiveDirectory,
            startTls: false,
            url: 'ldaps://dc.corp.example',
            userFilter: '(sAMAccountName={username})',
            bindSecret: $secret !== null ? new Sensitive($secret) : null,
        );
    }

    // -- 1. Redaction ------------------------------------------------------------------

    public function testTheBindSecretReachesTheWireAndNoRendering(): void
    {
        $client = $this->client();
        $secret = self::secret();
        $set = self::setBody($secret);
        $update = new Models\UpdateDirectoryConfig(bindSecret: new Sensitive($secret));
        foreach ([$set, $update] as $body) {
            self::assertNoFragment(self::renderings($body), $secret);
        }

        $this->routes->on('PUT', self::DIRECTORY, RoutedHandler::json(400, [
            'error' => 'validation_error', 'message' => 'url: plaintext LDAP is refused',
        ]));
        try {
            $client->directory()->set($set);
            self::fail('expected a ValidationError');
        } catch (ValidationError $e) {
            self::assertNoFragment(self::renderings($e), $secret);
        }
        $sent = $this->bodies('PUT', self::DIRECTORY);
        self::assertIsArray($sent[0]);
        self::assertSecretEquals($secret, $sent[0]['bind_secret'] ?? null, 'bind_secret');
    }

    // -- 2. No secret on the response ------------------------------------------------

    public function testABindSecretInAResponseIsDropped(): void
    {
        $client = $this->client();
        $leaked = self::secret();
        $this->routes->on('GET', self::DIRECTORY, RoutedHandler::json(200, self::config() + ['bind_secret' => $leaked]));

        $config = $client->directory()->get();

        self::assertNoFragment(self::renderings($config), $leaked);
        self::assertFalse(property_exists($config, 'bindSecret'), 'DirectoryConfig declares no secret member');
        self::assertArrayNotHasKey('bind_secret', $config->toArray());
        self::assertSame('ldaps://dc.corp.example', $config->url);
    }

    // -- 3. Sparse update --------------------------------------------------------------

    public function testUpdateSendsExactlyTheMembersItWasGiven(): void
    {
        $client = $this->client();
        $this->routes->on('PATCH', self::DIRECTORY, RoutedHandler::json(200, self::config()));
        $secret = self::secret();

        $client->directory()->update(new Models\UpdateDirectoryConfig(enabled: false));
        $client->directory()->update(new Models\UpdateDirectoryConfig(
            bindSecret: new Sensitive($secret),
            url: 'ldaps://dc2.corp.example',
        ));
        $client->directory()->update(new Models\UpdateDirectoryConfig(groupFilter: JsonNull::Null));
        $client->directory()->update(new Models\UpdateDirectoryConfig(groupBaseDn: 'ou=groups,dc=corp'));

        $sent = $this->routes->sent('PATCH', self::DIRECTORY);
        self::assertSame('{"enabled":false}', (string) $sent[0]->getBody());
        $second = json_decode((string) $sent[1]->getBody(), true);
        self::assertIsArray($second);
        $keys = array_keys($second);
        sort($keys);
        self::assertSame(['bind_secret', 'url'], $keys);
        self::assertSecretEquals($secret, $second['bind_secret'], 'bind_secret');
        self::assertSame('{"group_filter":null}', (string) $sent[2]->getBody(), 'an explicit null clears');
        self::assertSame('{"group_base_dn":"ou=groups,dc=corp"}', (string) $sent[3]->getBody());
    }

    public function testTheExplicitNullDecodesApartFromAbsent(): void
    {
        $cleared = Models\UpdateDirectoryConfig::fromArray(['group_filter' => null]);
        self::assertSame(JsonNull::Null, $cleared->groupFilter);
        self::assertNull($cleared->groupBaseDn, 'absent stays absent');
        self::assertSame(['group_filter' => null], $cleared->toArray());
        self::assertSame('x', Models\UpdateDirectoryConfig::fromArray(['group_base_dn' => 'x'])->groupBaseDn);
    }

    // -- 4. Replacement ----------------------------------------------------------------

    public function testSetSendsEveryRequiredMemberAndDecodes201And200(): void
    {
        $client = $this->client();
        $this->routes->on('PUT', self::DIRECTORY, RoutedHandler::json(201, self::config()), RoutedHandler::json(200, self::config()));

        foreach ([1, 2] as $_) {
            self::assertTrue($client->directory()->set(self::setBody())->enabled);
        }
        foreach ($this->bodies('PUT', self::DIRECTORY) as $sent) {
            self::assertIsArray($sent);
            foreach (['enabled', 'kind', 'url', 'start_tls', 'bind_dn', 'base_dn', 'user_filter'] as $required) {
                self::assertArrayHasKey($required, $sent);
            }
            self::assertArrayNotHasKey('bind_secret', $sent, 'absent keeps the stored secret');
        }

        // The replacement type cannot be built without its required members.
        $this->expectException(\ArgumentCountError::class);
        /** @phpstan-ignore-next-line deliberately missing arguments */
        new Models\SetDirectoryConfig(baseDn: 'dc=corp');
    }

    // -- 5. No retry --------------------------------------------------------------------

    public function testNoWriteIsRetriedOn503(): void
    {
        $client = $this->client(retry: true);
        foreach (['PUT', 'PATCH', 'DELETE'] as $method) {
            $this->routes->on($method, self::DIRECTORY, new Response(503));
        }
        $this->routes->on('POST', self::DIRECTORY . '/links', new Response(503));

        $d = $client->directory();
        foreach ([
            fn () => $d->set(self::setBody(self::secret())),
            fn () => $d->update(new Models\UpdateDirectoryConfig()),
            fn () => $d->delete(),
            fn () => $d->linkAccount(new Models\LinkDirectoryAccount(self::uuid())),
        ] as $call) {
            try {
                $call();
                self::fail('expected a NetworkError');
            } catch (NetworkError $e) {
                self::assertNotInstanceOf(ValidationError::class, $e);
            }
        }
        foreach (['PUT', 'PATCH', 'DELETE'] as $method) {
            self::assertCount(1, $this->routes->sent($method, self::DIRECTORY), $method . ': exactly one request');
        }
        self::assertCount(1, $this->routes->sent('POST', self::DIRECTORY . '/links'));
    }

    // -- 6. Errors and link_account ---------------------------------------------------

    public function testErrorsMapPerSection2AndLinkAccountSendsOnlyTheUserId(): void
    {
        $client = $this->client();
        $this->routes->on('PUT', self::DIRECTORY, RoutedHandler::json(400, [
            'error' => 'validation_error',
            'message' => 'url: changing the connection requires entering the bind secret again',
        ]));
        $this->routes->on('PATCH', self::DIRECTORY, RoutedHandler::json(409, ['error' => 'conflict', 'message' => 'opaque_mode']));
        $this->routes->on('GET', self::DIRECTORY, RoutedHandler::json(404, ['error' => 'not_found', 'message' => 'none']));

        try {
            $client->directory()->set(self::setBody());
            self::fail('expected a ValidationError');
        } catch (ValidationError $e) {
            self::assertStringContainsString('bind secret again', $e->getMessage());
            self::assertSame('url: changing the connection requires entering the bind secret again', $e->serverMessage);
        }
        try {
            $client->directory()->update(new Models\UpdateDirectoryConfig(enabled: true));
            self::fail('expected a ConflictError');
        } catch (ConflictError) {
        }
        try {
            $client->directory()->get();
            self::fail('expected a NotFoundError');
        } catch (NotFoundError) {
        }

        $user = self::uuid();
        $this->routes->on('POST', self::DIRECTORY . '/links', RoutedHandler::json(200, [
            'user_id' => $user, 'directory_external_id' => '3f2a-objectguid',
            'webauthn_credentials_deleted' => 2, 'certificates_revoked' => 1, 'was_already_linked' => false,
        ]));
        $result = $client->directory()->linkAccount(new Models\LinkDirectoryAccount($user));

        self::assertSame((string) json_encode(['user_id' => $user]), (string) $this->routes->sent('POST', self::DIRECTORY . '/links')[0]->getBody());
        self::assertSame($user, $result->userId);
        self::assertSame('3f2a-objectguid', $result->directoryExternalId);
        self::assertSame(2, $result->webauthnCredentialsDeleted);
        self::assertSame(1, $result->certificatesRevoked);
        self::assertFalse($result->wasAlreadyLinked);
    }

    public function testSyncStatusDecodesAnUnknownResultAndTheFirstRunNulls(): void
    {
        $client = $this->client();
        $this->routes->on('GET', self::DIRECTORY . '/sync-status', RoutedHandler::json(200, [
            'last_result' => 'something_new', 'last_attempt_at' => null, 'last_full_run_at' => null,
            'full_required' => true, 'has_watermark' => false,
        ]));
        $status = $client->directory()->getSyncStatus();

        self::assertTrue($status->fullRequired);
        self::assertFalse($status->hasWatermark);
        self::assertNull($status->lastAttemptAt);
    }

    public function testAReadConvertsIntoTheReplacementBodyWithoutASecret(): void
    {
        $config = Models\DirectoryConfig::fromArray(self::config());
        $body = ReadModifyWrite::directoryConfig($config);
        self::assertNull($body->bindSecret, 'absent keeps the stored secret');
        self::assertSame($config->url, $body->url);
        self::assertSame(5, $body->groupNestingDepth);
        self::assertSame(3600, $body->syncIntervalSecs);

        $secret = self::secret();
        $moved = ReadModifyWrite::directoryConfig($config, ['url' => 'ldaps://dc2.corp.example', 'bind_secret' => new Sensitive($secret)]);
        self::assertSame('ldaps://dc2.corp.example', $moved->url);
        self::assertNotNull($moved->bindSecret);
        self::assertSecretEquals($secret, $moved->bindSecret->reveal(), 'a Sensitive change is carried, not its rendering');
        self::assertSame('cn=svc,dc=corp', $moved->bindDn, 'every other member carried over');
    }
}
