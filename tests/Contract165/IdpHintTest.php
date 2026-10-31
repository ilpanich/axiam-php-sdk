<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract165;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Oidc\OidcConfiguration;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * CONTRACT.md §12.1 "`idp_hint` — choosing the provider" and §26.2 rule 8 (contract 1.65): the
 * optional provider hint of `oidcBegin` and `oidcPar`, spelled `axiam_idp_hint` and nothing else.
 */
final class IdpHintTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT_UUID = '22222222-2222-2222-2222-222222222222';
    private const REDIRECT_URI = 'https://app.example.com/callback';
    private const REQUEST_URI = 'urn:ietf:params:oauth:request_uri:abc123';

    /** @var list<RequestInterface> */
    private array $sent = [];

    private function configuration(): OidcConfiguration
    {
        return new OidcConfiguration(
            issuer: self::BASE_URL,
            authorization_endpoint: self::BASE_URL . '/oauth2/authorize',
            token_endpoint: self::BASE_URL . '/oauth2/token',
            userinfo_endpoint: self::BASE_URL . '/oauth2/userinfo',
            jwks_uri: self::BASE_URL . '/oauth2/jwks',
            revocation_endpoint: self::BASE_URL . '/oauth2/revoke',
            introspection_endpoint: self::BASE_URL . '/oauth2/introspect',
            response_types_supported: ['code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['EdDSA'],
            scopes_supported: ['openid'],
            token_endpoint_auth_methods_supported: ['client_secret_post'],
            claims_supported: ['sub'],
            grant_types_supported: ['authorization_code'],
            pushed_authorization_request_endpoint: self::BASE_URL . '/oauth2/par',
        );
    }

    /** @param array<int,Response> $queue */
    private function client(array $queue = []): AxiamClient
    {
        $this->sent = [];
        $mock = new MockHandler($queue);
        $captured = &$this->sent;

        return new AxiamClient(
            self::BASE_URL,
            self::TENANT_UUID,
            oidcClientId: 'my-app',
            oidcTenantId: self::TENANT_UUID,
            transportHandler: static function (RequestInterface $request, array $options) use ($mock, &$captured) {
                $captured[] = $request;

                return $mock($request, $options);
            },
        );
    }

    /**
     * The query as the PARAMETER LIST, so a duplicated name is visible (parse_str would hide it).
     *
     * @return list<array{0:string,1:string}>
     */
    private static function pairs(string $queryOrBody): array
    {
        $pairs = [];
        foreach (explode('&', $queryOrBody) as $part) {
            if ($part === '') {
                continue;
            }
            [$name, $value] = array_pad(explode('=', $part, 2), 2, '');
            $pairs[] = [rawurldecode(str_replace('+', '%20', $name)), rawurldecode(str_replace('+', '%20', $value))];
        }

        return $pairs;
    }

    /** @return list<string> every value of `$name`, in order */
    private static function valuesOf(array $pairs, string $name): array
    {
        return array_values(array_map(
            static fn (array $pair): string => $pair[1],
            array_filter($pairs, static fn (array $pair): bool => $pair[0] === $name),
        ));
    }

    private static function queryOf(string $url): string
    {
        return (string) parse_url($url, PHP_URL_QUERY);
    }

    private const EIGHT = [
        'client_id', 'code_challenge', 'code_challenge_method', 'nonce',
        'redirect_uri', 'response_type', 'scope', 'state',
    ];

    // ===================================================================================
    // §12.1 — oidc_begin
    // ===================================================================================

    public function testIdpHintEmittedOnce(): void
    {
        foreach (['corp-okta', '9b2f1c0e-7d4a-4c1b-8e55-0a1b2c3d4e5f', 'Google'] as $hint) {
            $request = $this->client()->oidcBegin($this->configuration(), self::REDIRECT_URI, idpHint: $hint);

            $pairs = self::pairs(self::queryOf($request->url));
            self::assertSame([$hint], self::valuesOf($pairs, 'axiam_idp_hint'), 'exactly once, not case-folded: ' . $hint);
            $names = array_map(static fn (array $pair): string => $pair[0], $pairs);
            sort($names);
            $expected = [...self::EIGHT, 'axiam_idp_hint'];
            sort($expected);
            self::assertSame($expected, $names, 'beside the other eight, unchanged, and nothing else');
            self::assertSame($request->state, self::valuesOf($pairs, 'state')[0]);
        }

        // Characters that need percent-encoding round-trip through the parsed query intact.
        $hint = 'Corp Okta/été & co=1+2#x';
        $request = $this->client()->oidcBegin($this->configuration(), self::REDIRECT_URI, idpHint: $hint);
        self::assertSame([$hint], self::valuesOf(self::pairs(self::queryOf($request->url)), 'axiam_idp_hint'));
        self::assertSame($hint, $request->idpHint, 'the request remembers the hint for oidcPar');
    }

    public function testIdpHintOmittedWhenUnset(): void
    {
        $request = $this->client()->oidcBegin($this->configuration(), self::REDIRECT_URI);

        $names = array_map(static fn (array $pair): string => $pair[0], self::pairs(self::queryOf($request->url)));
        sort($names);
        self::assertSame(self::EIGHT, $names, 'exactly the eight parameters of rule 5');
        self::assertStringNotContainsString('idp_hint', $request->url, 'neither axiam_idp_hint nor kc_idp_hint');
        self::assertNull($request->idpHint);
    }

    public function testIdpHintNotDuplicated(): void
    {
        // Set: the option is the single source; a caller-supplied copy is dropped.
        $request = $this->client()->oidcBegin(
            $this->configuration(),
            self::REDIRECT_URI,
            extraParams: ['axiam_idp_hint' => 'other', 'prompt' => 'login'],
            idpHint: 'corp-okta',
        );
        $pairs = self::pairs(self::queryOf($request->url));
        self::assertSame(['corp-okta'], self::valuesOf($pairs, 'axiam_idp_hint'));
        self::assertSame(['login'], self::valuesOf($pairs, 'prompt'), 'other extras are untouched');

        // Unset: a caller-supplied copy passes through as the extras always did, still once.
        $request = $this->client()->oidcBegin(
            $this->configuration(),
            self::REDIRECT_URI,
            extraParams: ['axiam_idp_hint' => 'other'],
        );
        self::assertSame(['other'], self::valuesOf(self::pairs(self::queryOf($request->url)), 'axiam_idp_hint'));

        // No kc_ alias, ever.
        self::assertSame([], self::valuesOf(self::pairs(self::queryOf($request->url)), 'kc_idp_hint'));
    }

    public function testIdpHintBounds(): void
    {
        $client = $this->client();

        foreach (['', str_repeat('a', 257), str_repeat('é', 129)] as $bad) {
            try {
                $client->oidcBegin($this->configuration(), self::REDIRECT_URI, idpHint: $bad);
                self::fail('expected a refusal for a hint of ' . strlen($bad) . ' bytes');
            } catch (\InvalidArgumentException $e) {
                self::assertStringContainsString('idpHint', $e->getMessage());
            }
        }

        foreach ([str_repeat('a', 256), str_repeat('é', 128)] as $ok) {
            self::assertSame(256, strlen($ok));
            $request = $client->oidcBegin($this->configuration(), self::REDIRECT_URI, idpHint: $ok);
            self::assertSame([$ok], self::valuesOf(self::pairs(self::queryOf($request->url)), 'axiam_idp_hint'), 'accepted unchanged');
        }

        // Nothing but emptiness and length is checked: not trimmed, not parsed, not looked up.
        $request = $client->oidcBegin($this->configuration(), self::REDIRECT_URI, idpHint: '  not-a-provider  ');
        self::assertSame(['  not-a-provider  '], self::valuesOf(self::pairs(self::queryOf($request->url)), 'axiam_idp_hint'));
        self::assertCount(0, $this->sent, 'and no sso_providers lookup');
    }

    // ===================================================================================
    // §26.2 rule 8 — oidc_par
    // ===================================================================================

    private static function parResponse(): Response
    {
        return new Response(201, ['Content-Type' => 'application/json'], (string) json_encode([
            'request_uri' => self::REQUEST_URI,
            'expires_in' => 90,
        ]));
    }

    public function testParIdpHintInPushedBody(): void
    {
        $client = $this->client([self::parResponse(), self::parResponse(), self::parResponse(), self::parResponse()]);
        $config = $this->configuration();

        // Given to oidcPar directly.
        $pushed = $client->oidcPar($client->oidcBegin($config, self::REDIRECT_URI), self::REDIRECT_URI, $config, idpHint: 'corp-okta');
        $body = self::pairs((string) $this->sent[0]->getBody());
        self::assertSame(['corp-okta'], self::valuesOf($body, 'axiam_idp_hint'), 'exactly once, in the pushed form');

        // Carried over from the oidcBegin that built the request.
        $begun = $client->oidcBegin($config, self::REDIRECT_URI, idpHint: 'Google');
        $pushedFromBegin = $client->oidcPar($begun, self::REDIRECT_URI, $config);
        self::assertSame(['Google'], self::valuesOf(self::pairs((string) $this->sent[1]->getBody()), 'axiam_idp_hint'));

        // An explicit argument wins over the carried one, still once.
        $client->oidcPar($begun, self::REDIRECT_URI, $config, idpHint: 'github');
        self::assertSame(['github'], self::valuesOf(self::pairs((string) $this->sent[2]->getBody()), 'axiam_idp_hint'));

        // Without one the field is absent.
        $unhinted = $client->oidcPar($client->oidcBegin($config, self::REDIRECT_URI), self::REDIRECT_URI, $config);
        self::assertSame([], self::valuesOf(self::pairs((string) $this->sent[3]->getBody()), 'axiam_idp_hint'));
        self::assertStringNotContainsString('idp_hint', (string) $this->sent[3]->getBody());

        // In every case the redirect URL carries exactly client_id and request_uri — a hint
        // cannot leak into it.
        foreach ([$pushed, $pushedFromBegin, $unhinted] as $result) {
            $names = array_map(static fn (array $pair): string => $pair[0], self::pairs(self::queryOf($result->url)));
            sort($names);
            self::assertSame(['client_id', 'request_uri'], $names);
            self::assertStringNotContainsString('idp_hint', $result->url);
        }
    }

    public function testParRefusesAnEmptyOrOversizedHintWithNoRequest(): void
    {
        $client = $this->client([self::parResponse()]);
        $config = $this->configuration();
        $begun = $client->oidcBegin($config, self::REDIRECT_URI);

        foreach (['', str_repeat('a', 257)] as $bad) {
            try {
                $client->oidcPar($begun, self::REDIRECT_URI, $config, idpHint: $bad);
                self::fail('expected a refusal');
            } catch (\InvalidArgumentException) {
                // expected
            }
        }
        self::assertCount(0, $this->sent);
    }
}
