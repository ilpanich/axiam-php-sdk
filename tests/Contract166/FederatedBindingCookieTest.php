<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract166;

use Axiam\Sdk\AxiamClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * CONTRACT.md §12.1 rule 12b (contract 1.66, #837): a federated sign-in is completed through the
 * cookie jar that started it. The port's CONFIRMATION that the existing §4 jar delivers it — the
 * `axiam_fed_bind` cookie an `ssoStart` response sets is presented on the following `ssoComplete`
 * from the same client, and absent from a second client's. No SDK behaviour changed.
 */
final class FederatedBindingCookieTest extends TestCase
{
    /** Plain-http mock: the server's `cookie_secure` is off, so no `__Host-` prefix and no `Secure`. */
    private const BASE_URL = 'http://api.test';
    private const TENANT_SLUG = 'acme-tenant';
    /** 32 bytes, base64url without padding — the shape the server issues. */
    private const BINDING = 'Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx';

    /**
     * @param array<int,Response> $queue
     * @param array<int,array<string,mixed>> $history
     */
    private function client(array $queue, array &$history): AxiamClient
    {
        $stack = HandlerStack::create(new MockHandler($queue));
        $stack->push(Middleware::history($history));

        return new AxiamClient(
            self::BASE_URL,
            self::TENANT_SLUG,
            orgSlug: 'acme',
            oidcClientId: 'my-app',
            transportHandler: $stack,
        );
    }

    private static function completeResponse(): Response
    {
        return new Response(
            200,
            ['Set-Cookie' => 'axiam_access=sso-session-token; Path=/'],
            (string) json_encode([
                'user_id' => 'user-1',
                'session_id' => 'session-1',
                'expires_in' => 900,
                'redirect_uri' => 'https://app.test/dashboard',
            ]),
        );
    }

    public function testSsoCompletePresentsTheBindingCookieOfItsOwnStartAndNoOtherClientDoes(): void
    {
        self::assertSame(43, \strlen(self::BINDING));

        $history = [];
        $client = $this->client([
            new Response(
                200,
                ['Set-Cookie' => 'axiam_fed_bind=' . self::BINDING . '; Path=/; HttpOnly; SameSite=Strict'],
                (string) json_encode([
                    'authorize_url' => 'https://upstream-idp.example/authorize',
                    'state' => 'federation-state-value',
                    'expires_in_secs' => 600,
                ]),
            ),
            self::completeResponse(),
        ], $history);

        $start = $client->ssoStart(
            federationConfigId: 'fed-config-1',
            redirectUri: 'https://app.test/sso/callback',
        );
        $client->ssoComplete($start->state, 'upstream-auth-code');

        self::assertCount(2, $history);
        self::assertStringEndsWith('/api/v1/auth/federation/oidc/callback', $history[1]['request']->getUri()->getPath());
        self::assertStringContainsString(
            'axiam_fed_bind=' . self::BINDING,
            $history[1]['request']->getHeaderLine('Cookie'),
            'the completion carries the binding the start set (§12.1 rule 12b, §4)',
        );

        $otherHistory = [];
        $other = $this->client([self::completeResponse()], $otherHistory);
        $other->ssoComplete($start->state, 'upstream-auth-code');

        self::assertCount(1, $otherHistory);
        self::assertStringNotContainsString(
            'axiam_fed_bind',
            $otherHistory[0]['request']->getHeaderLine('Cookie'),
            'a second client has its own jar and never presents the first client\'s binding',
        );
    }
}
