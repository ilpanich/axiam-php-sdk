<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\OAuthProtocolError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Oidc\OidcConfiguration;
use Axiam\Sdk\Oidc\RequestedPermission;
use Axiam\Sdk\Oidc\UmaChallenge;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * UMA 2.0 — CONTRACT.md §20.7 required assertions.
 *
 * Like §15, most of §20 is a list of things an SDK must not helpfully do, so most of
 * these tests assert an absence. The centrepiece is §20.2 rule 6: **a permission ticket
 * is never retried.**
 *
 * That rule is the one documented exception to §16, and the only way to assert it is to
 * count requests. A ticket is consumed *before* the exchange is evaluated, so a failed
 * exchange has already spent it — and under concurrency a retry is precisely the
 * concurrent redemption a server whose storage engine this SDK cannot attest may admit
 * twice (ilpanich/axiam#302). "Exactly one request" is a security assertion here, not a
 * performance one.
 */
final class OidcUmaTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';
    private const CLIENT_ID = 'orders-resource-server';
    private const CLIENT_SECRET = 'resource-server-secret';
    private const TENANT_UUID = '22222222-2222-2222-2222-222222222222';
    private const PAT = 'pat-token-value';
    private const TICKET = 'ticket-value';
    private const CLAIM_TOKEN = 'claim-token-value';
    private const RPT = 'rpt-token-value';
    private const RESOURCE_ID = '99999999-8888-7777-6666-555555555555';

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
            scopes_supported: ['openid', 'uma_protection'],
            token_endpoint_auth_methods_supported: ['client_secret_post'],
            claims_supported: ['sub'],
            grant_types_supported: ['urn:ietf:params:oauth:grant-type:uma-ticket'],
        );
    }

    /**
     * @param array<int,Response|\Throwable> $queue
     * @param array<int,mixed>|null $history
     */
    private function client(array $queue, bool $withSecret = true, ?array &$history = null): AxiamClient
    {
        $mock = new MockHandler($queue);
        $stack = HandlerStack::create($mock);
        if ($history !== null) {
            $stack->push(Middleware::history($history));
        }

        return new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            oidcClientId: self::CLIENT_ID,
            oidcClientSecret: $withSecret ? self::CLIENT_SECRET : null,
            oidcTenantId: self::TENANT_UUID,
            transportHandler: $stack,
        );
    }

    /** @param list<string> $scopes */
    private static function resourceSetResponse(array $scopes = ['view'], int $status = 200): Response
    {
        return new Response($status, [], (string) json_encode([
            '_id' => self::RESOURCE_ID,
            'name' => 'invoice-7',
            'type' => 'document',
            'resource_scopes' => $scopes,
        ]));
    }

    private static function rptResponse(?string $refreshToken = null): Response
    {
        $body = ['access_token' => self::RPT, 'token_type' => 'Bearer', 'expires_in' => 300];
        if ($refreshToken !== null) {
            $body['refresh_token'] = $refreshToken;
        }

        return new Response(200, [], (string) json_encode($body));
    }

    private static function oauthError(string $code, int $status): Response
    {
        return new Response($status, [], (string) json_encode([
            'error' => $code,
            'error_description' => $code . ' description',
        ]));
    }

    // ===================================================================================
    // §20.1 the Protection API
    // ===================================================================================

    public function testRegistrationRoundTripsAndTheIdIsUsableAsATicketResourceId(): void
    {
        $history = [];
        $client = $this->client([
            self::resourceSetResponse(status: 201),
            new Response(201, [], (string) json_encode(['ticket' => self::TICKET])),
        ], history: $history);

        $registered = $client->umaRegisterResource(self::PAT, 'invoice-7', 'document', ['view']);

        self::assertSame(self::RESOURCE_ID, $registered->id);
        self::assertSame(['view'], $registered->resourceScopes);

        // §20.1: `_id` IS the AXIAM resource id, not a parallel identifier — it goes
        // straight back out as a requested permission with no translation step.
        $ticket = $client->umaRequestTicket(self::PAT, [
            new RequestedPermission((string) $registered->id, ['view']),
        ]);

        self::assertSame(self::TICKET, $ticket->reveal());
        self::assertSame(
            [['resource_id' => self::RESOURCE_ID, 'resource_scopes' => ['view']]],
            json_decode((string) $history[1]['request']->getBody(), true),
        );
    }

    public function testAnOmittedTypeIsLeftOutRatherThanSentEmpty(): void
    {
        $history = [];
        $client = $this->client([self::resourceSetResponse(status: 201)], history: $history);

        $client->umaRegisterResource(self::PAT, 'invoice-7', resourceScopes: ['view']);

        // §12.1: an absent optional field is omitted, never sent empty — here so the
        // server applies its own `uma_resource` default rather than storing "".
        $body = json_decode((string) $history[0]['request']->getBody(), true);
        self::assertIsArray($body);
        self::assertArrayNotHasKey('type', $body);
    }

    public function testAnUpdateSendsExactlyTheScopesGivenWithNoReadFirst(): void
    {
        $history = [];
        // A single queued response: a read-modify-write would need two, and would fail
        // here with MockHandler's "queue is empty" rather than pass quietly.
        $client = $this->client([self::resourceSetResponse(['view'])], history: $history);

        $updated = $client->umaUpdateResource(self::PAT, self::RESOURCE_ID, 'invoice-7', 'document', ['view']);

        self::assertCount(1, $history, '§20.2 rule 8: an update must not read the current scopes first');
        self::assertSame('PUT', $history[0]['request']->getMethod());

        $body = json_decode((string) $history[0]['request']->getBody(), true);
        self::assertIsArray($body);
        // The caller dropped `edit`; merging it back in would make removing a scope
        // impossible through this SDK.
        self::assertSame(['view'], $body['resource_scopes']);
        self::assertSame(['view'], $updated->resourceScopes);
    }

    public function testAnUndeclaredScopeSurfacesThe400Unchanged(): void
    {
        $history = [];
        $client = $this->client([
            new Response(400, [], (string) json_encode(['message' => 'scope not declared on resource'])),
        ], history: $history);

        $this->expectException(NetworkError::class);
        try {
            $client->umaRequestTicket(self::PAT, [new RequestedPermission(self::RESOURCE_ID, ['delete'])]);
        } finally {
            self::assertCount(1, $history);
        }
    }

    public function testATokenThatIsNotAPatSurfacesTheServers403(): void
    {
        $history = [];
        $client = $this->client([
            new Response(403, [], (string) json_encode([
                'error' => 'authorization_denied',
                'message' => "the protection API requires the 'uma_protection' scope",
            ])),
        ], history: $history);

        // §20.2 rule 1: a user access token is not a PAT. The SDK does not pre-judge the
        // token's subject kind — it lets the server's refusal through as an AuthzError,
        // the §2 mapping for a 403, rather than an OAuth2 protocol error (those rows
        // belong to the token endpoint, §20.4).
        $this->expectException(AuthzError::class);
        try {
            $client->umaRequestTicket('a-user-token', [new RequestedPermission(self::RESOURCE_ID, ['view'])]);
        } finally {
            self::assertCount(1, $history);
        }
    }

    public function testTheProtectionApiCarriesThePatAndNotTheSessionToken(): void
    {
        $history = [];
        $client = $this->client([
            new Response(200, [], (string) json_encode([
                'access_token' => 'session-access', 'token_type' => 'Bearer', 'expires_in' => 3600,
            ])),
            new Response(200, [], (string) json_encode([self::RESOURCE_ID])),
        ], history: $history);

        // Adopt an ordinary session credential first, so the PAT has something to beat.
        $client->loginClientCredentials(configuration: $this->configuration(), adoptAsCredential: true);
        $ids = $client->umaListResources(new Sensitive(self::PAT));

        self::assertSame([self::RESOURCE_ID], $ids);
        // §20.2 rule 1: a minted ticket is bound to the client_id that minted it, so the
        // Protection API credential is the caller's explicit PAT — never a silent
        // fallback to whatever this client's session happens to hold.
        self::assertSame('Bearer ' . self::PAT, $history[1]['request']->getHeaderLine('Authorization'));
    }

    public function testDeleteIssuesOneDeleteAndReturnsNothing(): void
    {
        $history = [];
        $client = $this->client([new Response(204)], history: $history);

        $client->umaDeleteResource(self::PAT, self::RESOURCE_ID);

        self::assertSame('DELETE', $history[0]['request']->getMethod());
        self::assertSame('/uma2/rreg/resource_set/' . self::RESOURCE_ID, $history[0]['request']->getUri()->getPath());
    }

    public function testReadReturnsTheRegisteredResourceSet(): void
    {
        $client = $this->client([self::resourceSetResponse(['view', 'edit'])]);

        $resource = $client->umaReadResource(self::PAT, self::RESOURCE_ID);

        self::assertSame('invoice-7', $resource->name);
        self::assertSame('document', $resource->type);
        // §20.6: scopes and the resource id are NOT sensitive and must stay readable —
        // an application cannot act on a resource whose contents it may not inspect.
        self::assertSame(['view', 'edit'], $resource->resourceScopes);
    }

    // ===================================================================================
    // §20.2 rule 6 — the ticket grant is never retried
    // ===================================================================================

    public function testTheTicketGrantIsNotRetriedOnA5xx(): void
    {
        $history = [];
        $client = $this->client([new Response(500)], history: $history);

        try {
            $client->umaExchangeTicket(self::TICKET, self::CLAIM_TOKEN, configuration: $this->configuration());
            self::fail('expected the 500 to surface');
        } catch (NetworkError) {
            // expected
        }

        self::assertCount(
            1,
            $history,
            'the ticket grant must issue exactly one request — retrying a spent ticket is the '
            . 'concurrent redemption ilpanich/axiam#302 describes',
        );
    }

    public function testTheTicketGrantIsNotRetriedOnATimeout(): void
    {
        $history = [];
        $client = $this->client([
            new ConnectException('timed out', new Request('POST', self::BASE_URL . '/oauth2/token')),
        ], history: $history);

        try {
            $client->umaExchangeTicket(self::TICKET, self::CLAIM_TOKEN, configuration: $this->configuration());
            self::fail('expected the timeout to surface');
        } catch (NetworkError) {
            // expected
        }

        // §20.2 rule 6 names the timeout explicitly: a timed-out exchange may well have
        // reached the server and spent the ticket. Silence is not evidence it did not.
        self::assertCount(1, $history);
    }

    public function testTheTicketGrantIsNotRetriedOnInvalidGrant(): void
    {
        $history = [];
        $client = $this->client([self::oauthError('invalid_grant', 400)], history: $history);

        try {
            $client->umaExchangeTicket(self::TICKET, self::CLAIM_TOKEN, configuration: $this->configuration());
            self::fail('expected invalid_grant to surface');
        } catch (OAuthProtocolError $e) {
            // §20.4: unknown, expired, already-used and wrong-client all collapse into
            // this one code, and the SDK must not try to re-derive which — the server
            // withheld the distinction because it lets a caller probe for live tickets.
            self::assertSame('invalid_grant', $e->error);
        }

        self::assertCount(1, $history);
    }

    public function testA403AccessDeniedIsSurfacedAsItselfAndNotAutoNarrowed(): void
    {
        $history = [];
        $client = $this->client([self::oauthError('access_denied', 403)], history: $history);

        try {
            $client->umaExchangeTicket(self::TICKET, self::CLAIM_TOKEN, configuration: $this->configuration());
            self::fail('expected access_denied to surface');
        } catch (OAuthProtocolError $e) {
            // §20.4: `access_denied` answers HTTP 403 here, where RFC 8628's answers 400.
            // Mapping on the `error` field rather than the status is what keeps this
            // correct — a status-driven mapper would have produced an AuthzError.
            self::assertSame('access_denied', $e->error);
        }

        // §20.2 rule 3: a partial grant is refused whole. Whether two-of-three
        // permissions is useful is the application's judgement, not this SDK's.
        self::assertCount(1, $history, 'a refused ticket must not be re-requested with fewer scopes');
    }

    // ===================================================================================
    // §20.1/§20.2 — what the grant sends, and what the result is not
    // ===================================================================================

    public function testTheTicketGrantSendsTheRequiredClaimTokenAndItsFormat(): void
    {
        $history = [];
        $client = $this->client([self::rptResponse()], history: $history);

        $rpt = $client->umaExchangeTicket(
            new Sensitive(self::TICKET),
            new Sensitive(self::CLAIM_TOKEN),
            configuration: $this->configuration(),
        );

        parse_str((string) $history[0]['request']->getBody(), $form);
        self::assertSame('urn:ietf:params:oauth:grant-type:uma-ticket', $form['grant_type']);
        self::assertSame(self::TICKET, $form['ticket']);
        // §20.2 rule 2: required, never defaulted — it is the only channel that names the
        // requesting party, and defaulting it to the resource server's own PAT would mint
        // an RPT for the resource server instead of for the user.
        self::assertSame(self::CLAIM_TOKEN, $form['claim_token']);
        self::assertSame('urn:ietf:params:oauth:token-type:access_token', $form['claim_token_format']);
        // A token-endpoint grant: the client authenticates through the body (§20.1).
        self::assertSame(self::CLIENT_SECRET, $form['client_secret']);

        self::assertSame(self::RPT, $rpt->accessToken->reveal());
        self::assertSame(300, $rpt->expiresIn);
    }

    public function testAPublicClientFailsClientSideWithNoWireCall(): void
    {
        $history = [];
        $client = $this->client([], withSecret: false, history: $history);

        $this->expectException(AuthError::class);
        try {
            $client->umaExchangeTicket(self::TICKET, self::CLAIM_TOKEN, configuration: $this->configuration());
        } finally {
            self::assertCount(0, $history, 'no ticket should be spent on a request that cannot succeed');
        }
    }

    public function testAServerSentRefreshTokenIsNotSurfaced(): void
    {
        // Deliberately hostile fixture: the grant issues no refresh token, so the result
        // type has no property for one and there is nothing to synthesise.
        $client = $this->client([self::rptResponse(refreshToken: 'should-not-exist')]);

        $rpt = $client->umaExchangeTicket(self::TICKET, self::CLAIM_TOKEN, configuration: $this->configuration());

        self::assertFalse(property_exists($rpt, 'refreshToken'));
        self::assertStringNotContainsString('should-not-exist', print_r($rpt, true));
    }

    public function testTheRptIsNotAdoptedAsTheClientsCredentials(): void
    {
        $history = [];
        $client = $this->client([
            self::rptResponse(),
            new Response(200, [], (string) json_encode(['allowed' => true])),
        ], history: $history);

        $client->umaExchangeTicket(self::TICKET, self::CLAIM_TOKEN, configuration: $this->configuration());
        $client->checkAccess('read', 'resource-1');

        // §20.2 rule 4: the RPT is the *requesting party's* token. Adopting it would
        // re-privilege every later call this resource server makes as that user.
        self::assertSame('', $history[1]['request']->getHeaderLine('Authorization'));
    }

    // ===================================================================================
    // §20.3 the challenge helpers
    // ===================================================================================

    public function testParsesAWellFormedChallenge(): void
    {
        $parsed = UmaChallenge::parse(
            sprintf('UMA realm="example", as_uri="https://id.example", ticket="%s"', self::TICKET),
        );

        self::assertNotNull($parsed);
        self::assertSame('example', $parsed->realm);
        self::assertSame('https://id.example', $parsed->asUri);
        self::assertSame(self::TICKET, $parsed->ticket?->reveal());
    }

    public function testRejectsASchemeThatMerelyStartsWithUma(): void
    {
        self::assertNull(UmaChallenge::parse('Bearer realm="example"'));
        self::assertNull(UmaChallenge::parse('UMAX realm="example"'));
    }

    public function testParsingPerformsNoExchange(): void
    {
        $history = [];
        // An empty queue: an accidental exchange would fail with MockHandler's "queue is
        // empty" rather than pass silently.
        $client = $this->client([], history: $history);

        $parsed = $client->umaParseChallenge(
            sprintf('UMA realm="example", as_uri="%s", ticket="%s"', self::BASE_URL, self::TICKET),
        );

        self::assertSame(self::TICKET, $parsed?->ticket?->reveal());
        // §20.3: the as_uri names an authorization server this client has not chosen to
        // trust. Auto-exchanging would send the requesting party's claim_token to
        // whatever host answered the 403.
        self::assertCount(0, $history);
    }

    public function testRoundTripsThroughTheEmitHalf(): void
    {
        $client = $this->client([]);

        $header = $client->umaChallengeHeader('example', 'https://id.example', new Sensitive(self::TICKET));
        $parsed = $client->umaParseChallenge($header);

        self::assertSame('example', $parsed?->realm);
        self::assertSame('https://id.example', $parsed?->asUri);
        self::assertSame(self::TICKET, $parsed?->ticket?->reveal());
    }

    // ===================================================================================
    // §20.6 redaction
    // ===================================================================================

    public function testTheTicketAndRptDoNotRenderWhenSerialized(): void
    {
        $client = $this->client([
            new Response(201, [], (string) json_encode(['ticket' => self::TICKET])),
            self::rptResponse(),
        ]);

        $ticket = $client->umaRequestTicket(self::PAT, [new RequestedPermission(self::RESOURCE_ID, ['view'])]);
        $rpt = $client->umaExchangeTicket($ticket, self::CLAIM_TOKEN, configuration: $this->configuration());
        $challenge = UmaChallenge::parse(sprintf('UMA ticket="%s"', self::TICKET));

        // §20.6: the ticket's 60-second lifetime is exactly what invites treating it as
        // harmless. For those 60 seconds it is the credential that converts into an RPT.
        foreach ([$ticket, $rpt, $challenge] as $subject) {
            self::assertStringNotContainsString(self::TICKET, print_r($subject, true));
            self::assertStringNotContainsString(self::TICKET, (string) json_encode($subject));
            self::assertStringNotContainsString(self::RPT, print_r($subject, true));
            self::assertStringNotContainsString(self::RPT, (string) json_encode($subject));
        }
    }

    public function testAFailedExchangeNeverEchoesTheTicketOrClaimToken(): void
    {
        $client = $this->client([self::oauthError('invalid_grant', 400)]);

        try {
            $client->umaExchangeTicket(self::TICKET, self::CLAIM_TOKEN, configuration: $this->configuration());
            self::fail('expected invalid_grant');
        } catch (OAuthProtocolError $e) {
            // A failed exchange is exactly when a naive implementation logs the body.
            $rendered = $e->getMessage() . $e->error . $e->errorDescription;
            self::assertStringNotContainsString(self::TICKET, $rendered);
            self::assertStringNotContainsString(self::CLAIM_TOKEN, $rendered);
        }
    }

    public function testAFailedProtectionApiCallNeverEchoesThePat(): void
    {
        $client = $this->client([new Response(401, [], (string) json_encode(['message' => 'expired']))]);

        try {
            $client->umaListResources(self::PAT);
            self::fail('expected the 401 to surface');
        } catch (AuthError $e) {
            self::assertStringNotContainsString(self::PAT, $e->getMessage());
        }
    }
}
