<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract158;

use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Management\ConflictError;
use Axiam\Sdk\Management\JsonNull;
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
 * The `saml` namespace — CONTRACT.md §29.8's eight required tests.
 */
final class SamlTest extends ManagementRouteTestCase
{
    private const SAML = '/api/v1/tenants/' . self::TENANT_ID . '/saml';

    /**
     * @param array<string,mixed> $extra
     * @return array<string,mixed>
     */
    private static function sp(array $extra = []): array
    {
        return array_merge([
            'id' => self::uuid(), 'tenant_id' => self::TENANT_ID, 'enabled' => true,
            'display_name' => 'Payroll', 'entity_id' => 'https://payroll.example/sp',
            'acs_urls' => [['url' => 'https://payroll.example/acs', 'binding' => 'http_post', 'index' => 0, 'is_default' => true]],
            'slo_url' => null, 'slo_binding' => null, 'name_id_format' => 'persistent',
            'sign_responses' => true, 'encrypt_assertions' => false,
            'sp_signing_cert_pem' => null, 'sp_encryption_cert_pem' => null,
            'want_authn_requests_signed' => false, 'allow_idp_initiated' => false,
            'attribute_mappings' => [], 'allowed_groups' => [],
            'created_at' => '2026-10-04T00:00:00Z', 'updated_at' => '2026-10-04T00:00:00Z',
        ], $extra);
    }

    /**
     * @param array<string,mixed> $extra
     * @return array<string,mixed>
     */
    private static function credential(string $status, array $extra = []): array
    {
        return array_merge([
            'id' => self::uuid(), 'tenant_id' => self::TENANT_ID, 'issuer_ca_id' => self::uuid(),
            'certificate_pem' => "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            'serial' => '0a1b', 'fingerprint' => str_repeat('ab', 32),
            'not_before' => '2026-10-04T00:00:00Z', 'not_after' => '2027-10-04T00:00:00Z',
            'status' => $status, 'created_at' => '2026-10-04T00:00:00Z', 'retired_at' => null,
        ], $extra);
    }

    private static function input(): Models\SamlServiceProviderInput
    {
        return new Models\SamlServiceProviderInput(
            acsUrls: [new Models\AcsEndpoint(Models\SamlBinding::HttpPost, 0, 'https://payroll.example/acs', true)],
            displayName: 'Payroll',
            entityId: 'https://payroll.example/sp',
        );
    }

    // -- 1. Replacement ------------------------------------------------------------------

    public function testUpdateServiceProviderPutsTheWholeRegistration(): void
    {
        $client = $this->client();
        $id = self::uuid();
        $this->routes->on('PUT', self::SAML . '/service-providers/' . $id, RoutedHandler::json(200, self::sp()));

        $current = Models\SamlServiceProvider::fromArray(self::sp());
        $body = ReadModifyWrite::samlServiceProvider($current, ['display_name' => 'Payroll (EU)']);
        $sp = $client->saml()->updateServiceProvider($id, $body);
        self::assertSame('https://payroll.example/sp', $sp->entityId);

        $sent = $this->bodies('PUT', self::SAML . '/service-providers/' . $id)[0];
        self::assertIsArray($sent);
        foreach (['acs_urls', 'allow_idp_initiated', 'allowed_groups', 'attribute_mappings', 'display_name',
            'enabled', 'encrypt_assertions', 'entity_id', 'name_id_format', 'sign_responses',
            'want_authn_requests_signed'] as $member) {
            self::assertArrayHasKey($member, $sent);
        }
        self::assertSame('Payroll (EU)', $sent['display_name']);
        self::assertSame(ReadModifyWrite::samlServiceProvider($current)->displayName, 'Payroll');

        // The input type cannot be built without display_name, entity_id and acs_urls.
        $this->expectException(\ArgumentCountError::class);
        /** @phpstan-ignore-next-line deliberately missing arguments */
        new Models\SamlServiceProviderInput(acsUrls: []);
    }

    // -- 2. No signing switch, open decoding -------------------------------------------

    public function testSignAssertionsDoesNotExistAndUnknownValuesDecode(): void
    {
        $client = $this->client();
        $id = self::uuid();
        $wire = self::sp(['sign_assertions' => false, 'some_future_member' => 1]);
        $wire['acs_urls'][0]['binding'] = 'http_artifact';
        $this->routes->on('GET', self::SAML . '/service-providers/' . $id, RoutedHandler::json(200, $wire));
        $this->routes->on('PUT', self::SAML . '/service-providers/' . $id, RoutedHandler::json(200, self::sp()));

        $sp = $client->saml()->getServiceProvider($id);
        self::assertSame(Models\SamlBinding::Unknown, $sp->acsUrls[0]->binding);
        self::assertFalse(property_exists($sp, 'signAssertions'));
        self::assertFalse(property_exists(Models\SamlServiceProviderInput::class, 'signAssertions'));

        // An unknown value is decoded, but is not sent: replace the ACS before writing back.
        $client->saml()->updateServiceProvider($id, ReadModifyWrite::samlServiceProvider($sp, [
            'acs_urls' => [['url' => 'https://payroll.example/acs', 'binding' => 'http_post', 'index' => 0]],
        ]));
        $sent = $this->bodies('PUT', self::SAML . '/service-providers/' . $id)[0];
        self::assertIsArray($sent);
        self::assertArrayNotHasKey('sign_assertions', $sent);
        self::assertArrayNotHasKey('some_future_member', $sent);
        self::assertSame('http_post', $sent['acs_urls'][0]['binding']);
    }

    // -- 3. Draft round trip -------------------------------------------------------------

    public function testParseSpMetadataSendsExactlyOneMemberAndTheDraftCreates(): void
    {
        $client = $this->client();
        $draft = [
            'service_provider' => [
                'display_name' => 'Imported', 'entity_id' => 'https://imported.example/sp',
                'acs_urls' => [['url' => 'https://imported.example/acs', 'binding' => 'http_post', 'index' => 1, 'is_default' => false]],
                'want_authn_requests_signed' => true,
                'sp_signing_cert_pem' => "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            ],
            'signing_certificate_fingerprint' => str_repeat('cd', 32),
            'encryption_certificate_fingerprint' => null,
            'warnings' => ["the metadata's signature was not evaluated"],
        ];
        $this->routes->on('POST', self::SAML . '/parse-sp-metadata', RoutedHandler::json(200, $draft));
        $this->routes->on('POST', self::SAML . '/service-providers', RoutedHandler::json(201, self::sp()));

        $fromUrl = $client->saml()->parseSpMetadata(Models\ParseSamlSpMetadata::fromUrl('https://imported.example/metadata'));
        $client->saml()->parseSpMetadata(Models\ParseSamlSpMetadata::fromXml('<EntityDescriptor/>'));
        foreach ([
            new Models\ParseSamlSpMetadata(metadataUrl: 'https://a', metadataXml: '<x/>'),
            new Models\ParseSamlSpMetadata(),
        ] as $bothOrNeither) {
            try {
                $client->saml()->parseSpMetadata($bothOrNeither);
                self::fail('expected a local ValidationError');
            } catch (ValidationError $e) {
                self::assertStringContainsString('§29.2', $e->getMessage());
                self::assertNull($e->serverMessage, 'local, not the server');
            }
        }
        self::assertSame(
            ['{"metadata_url":"https://imported.example/metadata"}', '{"metadata_xml":"<EntityDescriptor/>"}'],
            array_map(static fn ($r): string => (string) $r->getBody(), $this->routes->sent('POST', self::SAML . '/parse-sp-metadata')),
            'the refused calls sent nothing',
        );
        self::assertSame(["the metadata's signature was not evaluated"], $fromUrl->warnings);
        self::assertNull($fromUrl->encryptionCertificateFingerprint);

        $client->saml()->createServiceProvider($fromUrl->serviceProvider);
        self::assertEquals($draft['service_provider'], $this->bodies('POST', self::SAML . '/service-providers')[0]);
    }

    // -- 4. Credentials carry no key ----------------------------------------------------

    public function testACredentialHasNoKeyMemberAndPromotionMayRetireNothing(): void
    {
        $client = $this->client();
        $keyBody = self::runtimeSecret('MC4C');
        $leaked = "-----BEGIN PRIVATE KEY-----\n" . $keyBody . "\n-----END PRIVATE KEY-----\n";
        $id = self::uuid();
        $this->routes->on('POST', self::SAML . '/idp-credentials/' . $id . '/retire', RoutedHandler::json(200, self::credential('retired', ['private_key_pem' => $leaked])));
        $this->routes->on('POST', self::SAML . '/idp-credentials/' . $id . '/promote', RoutedHandler::json(200, ['active' => self::credential('active'), 'retired' => null]));

        $credential = $client->saml()->retireIdpCredential($id);
        $rendered = self::renderings($credential);
        self::assertFalse(str_contains($rendered, 'PRIVATE KEY'), 'the key does not appear in any rendering');
        self::assertNoFragment($rendered, $keyBody);
        self::assertFalse(str_contains($rendered, 'private_key_pem'), 'no key member in any rendering');
        self::assertFalse(property_exists($credential, 'privateKeyPem'), 'no accessor for a key');

        $promotion = $client->saml()->promoteIdpCredential($id);
        self::assertNull($promotion->retired);
        self::assertSame(Models\SamlIdpCredentialStatus::Active, $promotion->active->status);
    }

    // -- 5. Pagination ------------------------------------------------------------------

    public function testServiceProvidersPageWithSearchAndCredentialsAreAPlainList(): void
    {
        $client = $this->client();
        $this->routes->on('GET', self::SAML . '/service-providers', self::pager(self::sp(), 2));
        $this->routes->on('GET', self::SAML . '/idp-credentials', RoutedHandler::json(200, [self::credential('next'), self::credential('active')]));

        $saml = $client->saml();
        $page = $saml->listServiceProviders(new PageRequest(0, 1, 'payroll'));
        self::assertInstanceOf(Page::class, $page);
        self::assertSame(2, $page->total);
        $all = iterator_to_array(ManagementTransport::walk(
            static fn (PageRequest $p): Page => $saml->listServiceProviders($p),
            new PageRequest(0, 1, 'payroll'),
        ), false);
        self::assertCount(2, $all);
        foreach ($this->queries('GET', self::SAML . '/service-providers') as $query) {
            self::assertStringContainsString('search=payroll', $query);
        }

        $credentials = $saml->listIdpCredentials();
        self::assertTrue(array_is_list($credentials), 'a plain list, not a page');
        self::assertCount(2, $credentials);
        self::assertInstanceOf(Models\SamlIdpCredential::class, $credentials[0]);
    }

    // -- 6. No retry ---------------------------------------------------------------------

    public function testNoneOfTheSevenWritesIsRetriedOn503(): void
    {
        $client = $this->client(retry: true);
        $id = self::uuid();
        $routes = [
            ['POST', self::SAML . '/service-providers'],
            ['PUT', self::SAML . '/service-providers/' . $id],
            ['DELETE', self::SAML . '/service-providers/' . $id],
            ['POST', self::SAML . '/parse-sp-metadata'],
            ['POST', self::SAML . '/idp-credentials'],
            ['POST', self::SAML . '/idp-credentials/' . $id . '/promote'],
            ['POST', self::SAML . '/idp-credentials/' . $id . '/retire'],
        ];
        foreach ($routes as [$method, $path]) {
            $this->routes->on($method, $path, new Response(503));
        }
        $s = $client->saml();
        foreach ([
            fn () => $s->createServiceProvider(self::input()),
            fn () => $s->updateServiceProvider($id, self::input()),
            fn () => $s->deleteServiceProvider($id),
            fn () => $s->parseSpMetadata(Models\ParseSamlSpMetadata::fromUrl('https://m.example')),
            fn () => $s->issueIdpCredential(new Models\IssueSamlIdpCredential(self::uuid(), Models\SamlIdpSlot::Next)),
            fn () => $s->promoteIdpCredential($id),
            fn () => $s->retireIdpCredential($id),
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

    // -- 7. Errors -----------------------------------------------------------------------

    public function testStatusesMapPerSection2(): void
    {
        $client = $this->client();
        $id = self::uuid();
        $this->routes->on('POST', self::SAML . '/service-providers', RoutedHandler::json(409, ['error' => 'conflict', 'message' => 'entity_id']));
        $this->routes->on('PUT', self::SAML . '/service-providers/' . $id, RoutedHandler::json(400, ['error' => 'validation_error', 'message' => 'entity_id is immutable: register a new service provider']));
        $this->routes->on('GET', self::SAML . '/service-providers/' . $id, RoutedHandler::json(404, ['error' => 'not_found', 'message' => 'no']));
        $this->routes->on('POST', self::SAML . '/idp-credentials/' . $id . '/promote', RoutedHandler::json(409, ['error' => 'conflict', 'message' => 'not next']));
        $this->routes->on('POST', self::SAML . '/parse-sp-metadata', RoutedHandler::json(503, ['error' => 'service_unavailable', 'message' => 'saml']));

        $s = $client->saml();
        $expect = function (callable $call, string $type): \Throwable {
            try {
                $call();
            } catch (\Throwable $e) {
                self::assertInstanceOf($type, $e);

                return $e;
            }
            self::fail('expected ' . $type);
        };
        $expect(fn () => $s->createServiceProvider(self::input()), ConflictError::class);
        $e = $expect(fn () => $s->updateServiceProvider($id, self::input()), ValidationError::class);
        self::assertStringContainsString('immutable', $e->getMessage());
        $expect(fn () => $s->getServiceProvider($id), NotFoundError::class);
        $expect(fn () => $s->promoteIdpCredential($id), ConflictError::class);
        $e = $expect(fn () => $s->parseSpMetadata(Models\ParseSamlSpMetadata::fromUrl('https://m.example')), NetworkError::class);
        self::assertNotInstanceOf(ValidationError::class, $e);
    }

    // -- 8. Readiness is read, not cached ---------------------------------------------

    public function testGetIdpIsNeverCachedAndKeepsNullApartFromAbsent(): void
    {
        $client = $this->client();
        $active = self::uuid();
        $this->routes->on('GET', self::SAML . '/idp', RoutedHandler::json(200, [
            'tenant_id' => self::TENANT_ID, 'saml_available' => true, 'saml_idp_enabled' => false,
            'metadata_served' => true, 'entity_id' => 'https://iam.example/saml/v2/t',
            'metadata_url' => 'https://iam.example/saml/v2/t/metadata',
            'sso_url' => 'https://iam.example/saml/v2/t/sso', 'slo_url' => 'https://iam.example/saml/v2/t/slo',
            'active_credential_id' => $active, 'next_credential_id' => null,
        ]));

        // The configured tenant, in the path: getIdp() takes no tenant argument.
        $info = $client->saml()->getIdp();
        $client->saml()->getIdp();
        self::assertCount(2, $this->routes->sent('GET', self::SAML . '/idp'), 'two calls, two requests');
        self::assertSame($active, $info->activeCredentialId);
        self::assertSame(JsonNull::Null, $info->nextCredentialId, 'null, not absent');
        self::assertTrue($info->samlAvailable && $info->metadataServed && !$info->samlIdpEnabled);
        self::assertSame(['active_credential_id' => $active, 'next_credential_id' => null], array_intersect_key(
            $info->toArray(),
            ['active_credential_id' => 1, 'next_credential_id' => 1],
        ));

        $without = Models\SamlIdpInfo::fromArray([
            'tenant_id' => self::TENANT_ID, 'saml_available' => true, 'saml_idp_enabled' => false,
            'metadata_served' => false, 'entity_id' => 'e', 'metadata_url' => 'm', 'sso_url' => 's', 'slo_url' => 'l',
        ]);
        self::assertNull($without->nextCredentialId, 'absent stays absent');
        self::assertArrayNotHasKey('next_credential_id', $without->toArray());
    }
}
