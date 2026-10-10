<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract160;

use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Management\JsonNull;
use Axiam\Sdk\Management\Models;
use Axiam\Sdk\Management\ValidationError;
use Axiam\Sdk\Tests\Contract158\ManagementRouteTestCase;
use Axiam\Sdk\Tests\Fixtures\RoutedHandler;

/**
 * CONTRACT.md §27.15 (contract 1.60): `window_minutes` on the `notification_rules` models
 * (note 1's required test), the `federation` configuration's `allow_sha1_signatures` and
 * `idp_metadata_signing_cert_pem` (notes 6 and 7), and `update_config`'s explicit-null rule
 * with §27.4 rule 5's exact key-set test (note 8). Everything runs on the SDK's real request
 * path; the client secret and the certificate body are generated at run time.
 */
final class FederationAndNotificationRulesTest extends ManagementRouteTestCase
{
    private const RULES = '/api/v1/notification-rules';
    private const CONFIGS = '/api/v1/federation-configs';

    /** The ten members of `UpdateFederationConfigRequest` an explicit `null` clears. */
    private const CLEARABLE = [
        'metadataUrl' => 'metadata_url',
        'idpSigningCertPem' => 'idp_signing_cert_pem',
        'idpMetadataSigningCertPem' => 'idp_metadata_signing_cert_pem',
        'providerSlug' => 'provider_slug',
        'authorizationEndpoint' => 'authorization_endpoint',
        'tokenEndpoint' => 'token_endpoint',
        'userinfoEndpoint' => 'userinfo_endpoint',
        'appleTeamId' => 'apple_team_id',
        'appleKeyId' => 'apple_key_id',
        'buttonIcon' => 'button_icon',
    ];

    /**
     * @param array<string,mixed> $extra
     * @return array<string,mixed>
     */
    private static function rule(array $extra = []): array
    {
        return array_merge([
            'id' => self::uuid(), 'tenant_id' => self::TENANT_ID, 'name' => 'Lockouts',
            'description' => 'Mail the admins', 'enabled' => true, 'events' => ['login_failure'],
            'recipient_emails' => ['admin@example.test'], 'window_minutes' => 15,
            'created_at' => '2026-10-05T00:00:00Z', 'updated_at' => '2026-10-05T00:00:00Z',
        ], $extra);
    }

    /**
     * A SAML configuration as a 1.60 server returns it, or — with `$drop` — as an older one.
     *
     * @param array<string,mixed> $extra
     * @param list<string> $drop
     * @return array<string,mixed>
     */
    private static function config(array $extra = [], array $drop = []): array
    {
        $config = array_merge([
            'id' => self::uuid(), 'tenant_id' => self::TENANT_ID, 'provider' => 'Okta',
            'protocol' => 'Saml', 'provider_kind' => 'generic_saml', 'client_id' => 'axiam-sp',
            'enabled' => true, 'allow_tenant_inheritance' => false, 'allow_sha1_signatures' => false,
            'allowed_algorithms' => [], 'allowed_issuer_tenants' => [], 'attribute_map' => [],
            'effective_scopes' => [], 'scopes' => [], 'has_bundled_mark' => false,
            'mints_client_secret' => false, 'pkce_required' => false,
            'idp_metadata_signing_cert_pem' => null,
            'token_exchange' => ['enabled' => false, 'accepted_audiences' => [], 'max_lifetime_secs' => 300,
                'max_token_age_secs' => 300, 'scope_map' => [], 'subject_mapping' => 'link'],
            'created_at' => '2026-10-05T00:00:00Z', 'updated_at' => '2026-10-05T00:00:00Z',
        ], $extra);

        return array_diff_key($config, array_flip($drop));
    }

    /** A PEM-shaped certificate whose body is generated at run time. */
    private static function pem(): string
    {
        return "-----BEGIN CERTIFICATE-----\n" . base64_encode(random_bytes(48)) . "\n-----END CERTIFICATE-----\n";
    }

    private static function createSaml(?bool $sha1 = null, ?string $metadataCert = null): Models\CreateFederationConfigRequest
    {
        return new Models\CreateFederationConfigRequest(
            clientId: 'axiam-sp',
            clientSecret: new Sensitive(self::runtimeSecret('fed-')),
            protocol: 'Saml',
            provider: 'Okta',
            allowSha1Signatures: $sha1,
            idpMetadataSigningCertPem: $metadataCert,
        );
    }

    // -- §27.15 note 1: window_minutes --------------------------------------------------

    /**
     * The one required test of note 1: `create` with `window_minutes` sends it as given,
     * `create` without it sends no such key, and a response carrying it decodes it.
     */
    public function testWindowMinutesIsSentAsGivenOmittedWhenUnsetAndDecoded(): void
    {
        $client = $this->client();
        $this->routes->on('POST', self::RULES, RoutedHandler::json(201, self::rule(['window_minutes' => 60])));
        $rules = $client->notificationRules();

        $created = $rules->create(new Models\CreateNotificationRuleRequest(
            'Mail the admins', [Models\NotificationEventType::LoginFailure], 'Lockouts', ['admin@example.test'], windowMinutes: 60,
        ));
        $rules->create(new Models\CreateNotificationRuleRequest(
            'Mail the admins', [Models\NotificationEventType::LoginFailure], 'Lockouts', ['admin@example.test'],
        ));

        $sent = $this->bodies('POST', self::RULES);
        self::assertIsArray($sent[0]);
        self::assertSame(60, $sent[0]['window_minutes'] ?? null, 'sent as given');
        self::assertIsArray($sent[1]);
        self::assertArrayNotHasKey('window_minutes', $sent[1], 'unset: no key');
        self::assertSame(60, $created->windowMinutes, 'decoded from the response');
    }

    /**
     * Never clamped: a value outside 1 … 1440 goes on the wire unchanged and the server's
     * `400` surfaces as `ValidationError`; `update` sends it when set and only then.
     */
    public function testWindowMinutesIsNeverClampedAndUpdateIsSparse(): void
    {
        $client = $this->client();
        $id = self::uuid();
        $this->routes->on('POST', self::RULES, RoutedHandler::json(400, ['error' => 'validation_error', 'message' => 'window_minutes must be between 1 and 1440']));
        $this->routes->on('PUT', self::RULES . '/' . $id, RoutedHandler::json(200, self::rule(['id' => $id, 'window_minutes' => 1440])));

        foreach ([0, 1441] as $outOfRange) {
            try {
                $client->notificationRules()->create(new Models\CreateNotificationRuleRequest(
                    'd', [Models\NotificationEventType::LoginFailure], 'n', ['admin@example.test'], windowMinutes: $outOfRange,
                ));
                self::fail('the server refuses it, the SDK does not rewrite it');
            } catch (ValidationError $e) {
                self::assertStringContainsString('window_minutes', $e->getMessage());
            }
        }
        $sent = $this->bodies('POST', self::RULES);
        self::assertIsArray($sent[0]);
        self::assertIsArray($sent[1]);
        self::assertSame([0, 1441], [$sent[0]['window_minutes'], $sent[1]['window_minutes']], 'not clamped');

        $updated = $client->notificationRules()->update($id, new Models\UpdateNotificationRuleRequest(windowMinutes: 1440));
        $client->notificationRules()->update($id, new Models\UpdateNotificationRuleRequest(name: 'Renamed'));
        $puts = $this->routes->sent('PUT', self::RULES . '/' . $id);
        self::assertSame('{"window_minutes":1440}', (string) $puts[0]->getBody());
        self::assertSame('{"name":"Renamed"}', (string) $puts[1]->getBody(), 'absent stays absent');
        self::assertSame(1440, $updated->windowMinutes);
    }

    // -- §27.15 notes 6 and 7: the two new federation members -----------------------------

    public function testAllowSha1SignaturesAndTheMetadataCertAreSentOnlyWhenSet(): void
    {
        $client = $this->client();
        $pem = self::pem();
        $this->routes->on('POST', self::CONFIGS, RoutedHandler::json(201, self::config([
            'allow_sha1_signatures' => true, 'idp_metadata_signing_cert_pem' => $pem,
        ])));

        $created = $client->federation()->createConfig(self::createSaml(true, $pem));
        $client->federation()->createConfig(self::createSaml());
        $client->federation()->createConfig(self::createSaml(false));

        $sent = $this->bodies('POST', self::CONFIGS);
        self::assertIsArray($sent[0]);
        self::assertTrue($sent[0]['allow_sha1_signatures'] ?? null);
        self::assertSame($pem, $sent[0]['idp_metadata_signing_cert_pem'] ?? null, 'the PEM as given');
        self::assertIsArray($sent[1]);
        self::assertArrayNotHasKey('allow_sha1_signatures', $sent[1], 'unset: no key');
        self::assertArrayNotHasKey('idp_metadata_signing_cert_pem', $sent[1], 'unset: no key');
        self::assertIsArray($sent[2]);
        self::assertFalse($sent[2]['allow_sha1_signatures'] ?? null, 'an explicit false is sent');

        self::assertTrue($created->allowSha1Signatures);
        self::assertSame($pem, $created->idpMetadataSigningCertPem);

        $update = new Models\UpdateFederationConfigRequest(allowSha1Signatures: true);
        self::assertSame(['allow_sha1_signatures' => true], $update->toArray());
    }

    /**
     * A 1.60 response decodes both members; one from a server before 1.0.0, which sends
     * neither, decodes `allow_sha1_signatures` as `false` and the certificate as `null`.
     */
    public function testAResponseWithoutTheNewMembersDecodes(): void
    {
        $current = Models\FederationConfigResponse::fromArray(self::config());
        self::assertFalse($current->allowSha1Signatures);
        self::assertNull($current->idpMetadataSigningCertPem, 'null when unset');

        $older = Models\FederationConfigResponse::fromArray(
            self::config([], ['allow_sha1_signatures', 'idp_metadata_signing_cert_pem']),
        );
        self::assertFalse($older->allowSha1Signatures, 'absent decodes as false');
        self::assertNull($older->idpMetadataSigningCertPem);
    }

    // -- §27.15 note 8: an explicit null clears, an omitted member is left -----------------

    /**
     * §27.4 rule 5's exact key-set test for one cleared member: clearing the metadata
     * signing certificate sends exactly `{"idp_metadata_signing_cert_pem": null}` and nothing
     * else; leaving every member unset sends `{}`.
     */
    public function testClearingOneMemberSendsExactlyThatKeyAsNull(): void
    {
        $client = $this->client();
        $id = self::uuid();
        $this->routes->on('PUT', self::CONFIGS . '/' . $id, RoutedHandler::json(200, self::config(['id' => $id])));

        $client->federation()->updateConfig($id, new Models\UpdateFederationConfigRequest(idpMetadataSigningCertPem: JsonNull::Null));
        $client->federation()->updateConfig($id, new Models\UpdateFederationConfigRequest());
        $client->federation()->updateConfig($id, new Models\UpdateFederationConfigRequest(metadataUrl: 'https://idp.example/metadata'));

        $sent = $this->routes->sent('PUT', self::CONFIGS . '/' . $id);
        self::assertSame('{"idp_metadata_signing_cert_pem":null}', (string) $sent[0]->getBody(), 'exactly the cleared key');
        $cleared = json_decode((string) $sent[0]->getBody(), true);
        self::assertIsArray($cleared);
        self::assertSame(['idp_metadata_signing_cert_pem'], array_keys($cleared));
        self::assertNull($cleared['idp_metadata_signing_cert_pem']);
        self::assertSame('{}', (string) $sent[1]->getBody(), 'omitted leaves everything unchanged');
        self::assertSame('{"metadata_url":"https://idp.example/metadata"}', (string) $sent[2]->getBody());
    }

    /** Each of the ten is three-state; the members that cannot be cleared stay two-state. */
    public function testEveryClearableMemberDistinguishesUnsetFromNull(): void
    {
        foreach (self::CLEARABLE as $property => $wire) {
            $cleared = new Models\UpdateFederationConfigRequest(...[$property => JsonNull::Null]);
            self::assertSame([$wire => null], $cleared->toArray(), "{$wire}: null clears");
            self::assertSame('{"' . $wire . '":null}', json_encode($cleared), "{$wire}: on the wire");

            $set = new Models\UpdateFederationConfigRequest(...[$property => 'v']);
            self::assertSame([$wire => 'v'], $set->toArray(), "{$wire}: a value is sent");

            $decoded = Models\UpdateFederationConfigRequest::fromArray([$wire => null]);
            self::assertSame(JsonNull::Null, $decoded->{$property}, "{$wire}: a decoded null is not absent");
            self::assertSame([$wire => null], $decoded->toArray());
        }

        self::assertSame([], (new Models\UpdateFederationConfigRequest())->toArray(), 'unset: nothing sent');
        self::assertSame([], Models\UpdateFederationConfigRequest::fromArray([])->toArray());

        // `provider`, `client_id`, the booleans and the rest cannot be cleared: PHP null is absent.
        $twoState = Models\UpdateFederationConfigRequest::fromArray(['provider' => null, 'enabled' => null, 'client_id' => null]);
        self::assertSame([], $twoState->toArray());
    }
}
