<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\OAuthProtocolError;
use Axiam\Sdk\Oidc\OidcClient;
use Axiam\Sdk\Oidc\OidcConfiguration;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * Token Exchange (RFC 8693) — CONTRACT.md §15.
 *
 * Most of §15 is a list of things an SDK must *not* helpfully do, so most of these tests
 * assert an absence: no defaulted `$actorToken`, no auto-narrow after `invalid_scope`, no
 * synthesised refresh token, no adoption.
 */
final class OidcTokenExchangeTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';
    private const CLIENT_ID = 'api-gateway';
    private const CLIENT_SECRET = 'gateway-secret';
    private const TENANT_UUID = '22222222-2222-2222-2222-222222222222';
    private const SUBJECT_TOKEN = 'subject-token-value';
    private const ACTOR_TOKEN = 'actor-token-value';
    private const ISSUED_TOKEN = 'issued-narrow-token';

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
            grant_types_supported: ['urn:ietf:params:oauth:grant-type:token-exchange'],
        );
    }

    /**
     * @param array<int,Response> $queue
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

    private static function exchangeResponse(?string $scope = 'orders:read', ?string $refreshToken = null): Response
    {
        $body = [
            'access_token' => self::ISSUED_TOKEN,
            'issued_token_type' => 'urn:ietf:params:oauth:token-type:access_token',
            'token_type' => 'Bearer',
            'expires_in' => 300,
        ];
        if ($scope !== null) {
            $body['scope'] = $scope;
        }
        if ($refreshToken !== null) {
            $body['refresh_token'] = $refreshToken;
        }

        return new Response(200, [], (string) json_encode($body));
    }

    private static function oauthError(string $code, int $status = 400): Response
    {
        return new Response($status, [], (string) json_encode([
            'error' => $code,
            'error_description' => $code . ' description',
        ]));
    }

    // ===================================================================================
    // §15.1 wire shape
    // ===================================================================================

    public function testSendsTheRfc8693GrantAndAuthenticates(): void
    {
        $history = [];
        $client = $this->client([self::exchangeResponse()], history: $history);

        $result = $client->tokenExchange(
            self::SUBJECT_TOKEN,
            OidcClient::ACCESS_TOKEN_TYPE,
            scopes: ['orders:read', 'orders:write'],
            audience: 'orders-service',
            configuration: $this->configuration(),
        );

        $body = urldecode((string) $history[0]['request']->getBody());
        self::assertStringContainsString('grant_type=urn:ietf:params:oauth:grant-type:token-exchange', $body);
        self::assertStringContainsString('subject_token=' . self::SUBJECT_TOKEN, $body);
        self::assertStringContainsString('subject_token_type=urn:ietf:params:oauth:token-type:access_token', $body);
        self::assertStringContainsString('scope=orders:read orders:write', $body);
        self::assertStringContainsString('audience=orders-service', $body);
        self::assertStringContainsString('client_secret=' . self::CLIENT_SECRET, $body, '§15.1: the exchanging client authenticates');

        self::assertSame(self::ISSUED_TOKEN, $result->accessToken->reveal());
        self::assertSame(
            'urn:ietf:params:oauth:token-type:access_token',
            $result->issuedTokenType,
            '§15.2 rule 6: issued_token_type is surfaced, not dropped',
        );
        self::assertSame(300, $result->expiresIn);
    }

    public function testAPublicClientFailsClientSideWithNoWireCall(): void
    {
        $history = [];
        // An empty queue: reaching the wire would fail with MockHandler's own
        // "queue is empty" error rather than the AuthError we expect.
        $client = $this->client([], withSecret: false, history: $history);

        $this->expectException(AuthError::class);
        try {
            $client->tokenExchange(self::SUBJECT_TOKEN, OidcClient::ACCESS_TOKEN_TYPE, configuration: $this->configuration());
        } finally {
            self::assertCount(0, $history, 'no request should have been sent');
        }
    }

    // ===================================================================================
    // §15.2 rule 1 — delegation vs impersonation
    // ===================================================================================

    public function testAnAbsentActorTokenIsNeverDefaulted(): void
    {
        $history = [];
        $client = $this->client([self::exchangeResponse()], history: $history);

        $client->tokenExchange(self::SUBJECT_TOKEN, OidcClient::ACCESS_TOKEN_TYPE, configuration: $this->configuration());

        $body = urldecode((string) $history[0]['request']->getBody());
        // §15.2 rule 1: passing none asks for IMPERSONATION. An SDK that helpfully
        // substituted its own session token would silently turn that into a delegation —
        // a different operation with different risk.
        self::assertStringNotContainsString('actor_token', $body);
    }

    public function testActorTokenAndTypeAreSentAsAPair(): void
    {
        $history = [];
        $client = $this->client([self::exchangeResponse(scope: null)], history: $history);

        $client->tokenExchange(
            self::SUBJECT_TOKEN,
            OidcClient::ACCESS_TOKEN_TYPE,
            actorToken: self::ACTOR_TOKEN,
            configuration: $this->configuration(),
        );

        $body = urldecode((string) $history[0]['request']->getBody());
        self::assertStringContainsString('actor_token=' . self::ACTOR_TOKEN, $body);
        // RFC 8693 §2.1 requires the pair; the type alone is a malformed request.
        self::assertStringContainsString('actor_token_type=urn:ietf:params:oauth:token-type:access_token', $body);
    }

    // ===================================================================================
    // §15.2 rules 2-3 and §15.3 — refusals surface unchanged
    // ===================================================================================

    /**
     * @return iterable<string,array{0:string,1:int}>
     */
    public static function errorCodeProvider(): iterable
    {
        yield 'invalid_request' => ['invalid_request', 400];
        yield 'invalid_grant' => ['invalid_grant', 400];
        yield 'invalid_scope' => ['invalid_scope', 400];
        yield 'invalid_target' => ['invalid_target', 400];
        yield 'unauthorized_client' => ['unauthorized_client', 400];
        yield 'invalid_client' => ['invalid_client', 401];
    }

    /** @dataProvider errorCodeProvider */
    public function testErrorCodesReachTheCallerUnchangedWithNoRetry(string $code, int $status): void
    {
        // Including cross-tenant, which the server deliberately collapses into
        // invalid_grant — the SDK must not re-derive the distinction it withheld (that is
        // a tenant-enumeration signal).
        $history = [];
        $client = $this->client([self::oauthError($code, $status)], history: $history);

        try {
            $client->tokenExchange(
                self::SUBJECT_TOKEN,
                OidcClient::ACCESS_TOKEN_TYPE,
                scopes: ['orders:read', 'orders:admin'],
                configuration: $this->configuration(),
            );
            self::fail('expected the refusal to surface');
        } catch (OAuthProtocolError $e) {
            self::assertSame($code, $e->error);
        }

        // §15.2 rules 2-3: no retry, no downgrade, no auto-narrowing. The server refuses
        // rather than silently narrowing precisely so the caller finds out HERE.
        self::assertCount(1, $history);
    }

    // ===================================================================================
    // §15.2 rules 4-7 — what the result is, and is not
    // ===================================================================================

    public function testAServerSentRefreshTokenIsNotSurfaced(): void
    {
        // Deliberately hostile fixture: RFC 8693 issues no refresh token, so the type has
        // no property for one and there is nothing to synthesise.
        $client = $this->client([self::exchangeResponse(refreshToken: 'should-not-exist')]);

        $result = $client->tokenExchange(self::SUBJECT_TOKEN, OidcClient::ACCESS_TOKEN_TYPE, configuration: $this->configuration());

        self::assertFalse(property_exists($result, 'refreshToken'));
        self::assertStringNotContainsString('should-not-exist', print_r($result, true));
    }

    public function testTheGrantedScopeIsReadableWhenNarrowerThanRequested(): void
    {
        $client = $this->client([self::exchangeResponse(scope: 'orders:read')]);

        $result = $client->tokenExchange(
            self::SUBJECT_TOKEN,
            OidcClient::ACCESS_TOKEN_TYPE,
            scopes: ['orders:read', 'orders:write'],
            configuration: $this->configuration(),
        );

        // §15.2 rule 7: the response scope is the GRANTED set and may be narrower than
        // requested even on success.
        self::assertSame('orders:read', $result->scope);
    }

    public function testAnEmptyScopeListIsOmittedRatherThanSentEmpty(): void
    {
        $history = [];
        $client = $this->client([self::exchangeResponse(scope: null)], history: $history);

        $result = $client->tokenExchange(
            self::SUBJECT_TOKEN,
            OidcClient::ACCESS_TOKEN_TYPE,
            scopes: [],
            configuration: $this->configuration(),
        );

        // §12.1: an absent optional field is omitted, never sent empty.
        self::assertStringNotContainsString('scope=', urldecode((string) $history[0]['request']->getBody()));
        self::assertNull($result->scope);
    }

    public function testTheIssuedTokenIsRedacted(): void
    {
        $client = $this->client([self::exchangeResponse()]);

        $result = $client->tokenExchange(self::SUBJECT_TOKEN, OidcClient::ACCESS_TOKEN_TYPE, configuration: $this->configuration());

        // §15.5: the issued token is a bearer credential and must not render.
        self::assertStringNotContainsString(self::ISSUED_TOKEN, print_r($result->accessToken, true));
        self::assertStringNotContainsString(self::ISSUED_TOKEN, (string) json_encode($result->accessToken));
    }

    public function testAFailedExchangeNeverEchoesTheSubjectOrActorToken(): void
    {
        // §15.5 calls this out specifically: an exchange failure is exactly when a naive
        // implementation logs the request body.
        $client = $this->client([self::oauthError('invalid_grant')]);

        try {
            $client->tokenExchange(
                self::SUBJECT_TOKEN,
                OidcClient::ACCESS_TOKEN_TYPE,
                actorToken: self::ACTOR_TOKEN,
                configuration: $this->configuration(),
            );
            self::fail('expected invalid_grant');
        } catch (OAuthProtocolError $e) {
            $rendered = $e->getMessage() . $e->error . $e->errorDescription;
            self::assertStringNotContainsString(self::SUBJECT_TOKEN, $rendered);
            self::assertStringNotContainsString(self::ACTOR_TOKEN, $rendered);
        }
    }

    public function testResourceIsSentWhenSupplied(): void
    {
        $history = [];
        $client = $this->client([self::exchangeResponse()], history: $history);

        $client->tokenExchange(
            self::SUBJECT_TOKEN,
            OidcClient::ACCESS_TOKEN_TYPE,
            resource: 'https://orders.example.com',
            configuration: $this->configuration(),
        );

        // RFC 8707's synonym for audience; the server refuses the pair when they
        // disagree, so the SDK passes both through rather than choosing.
        self::assertStringContainsString(
            'resource=https://orders.example.com',
            urldecode((string) $history[0]['request']->getBody()),
        );
    }

    // ===================================================================================
    // §15.7 — external-IdP subject tokens (X4)
    //
    // No new operation: the same tokenExchange carries a partner IdP's token. What changes
    // is which subject tokens the server accepts and what its refusals mean, so these tests
    // are about not getting in the way of either.
    // ===================================================================================

    /**
     * A token minted by a partner's IdP. Opaque to the SDK — deliberately not a well-formed
     * JWT, because nothing here may decode it.
     */
    private const EXTERNAL_SUBJECT_TOKEN = 'partner-idp-subject-token';

    /**
     * The one normative `error_description` (§15.7). It means "fix the AXIAM trust
     * configuration", not "fix your token".
     */
    private const ISSUER_NOT_CONFIGURED =
        "the subject token's issuer is not configured for token exchange";

    private static function oauthErrorWithDescription(string $code, string $description): Response
    {
        return new Response(400, [], (string) json_encode([
            'error' => $code,
            'error_description' => $description,
        ]));
    }

    public function testAnExternalSubjectTokenTypeIsSentVerbatim(): void
    {
        $history = [];
        $client = $this->client([self::exchangeResponse('read:orders')], history: $history);

        $result = $client->tokenExchange(
            self::EXTERNAL_SUBJECT_TOKEN,
            scopes: ['read:orders'],
            audience: 'https://orders.internal',
            configuration: $this->configuration(),
            subjectTokenType: OidcClient::JWT_TOKEN_TYPE,
        );

        $body = urldecode((string) $history[0]['request']->getBody());
        // The caller named …:jwt, so …:jwt goes on the wire. §15.7: the SDK must not inspect
        // the subject token to pick this, and must not override it.
        self::assertStringContainsString(
            'subject_token_type=urn:ietf:params:oauth:token-type:jwt',
            $body,
        );
        self::assertStringContainsString('subject_token=' . self::EXTERNAL_SUBJECT_TOKEN, $body);
        // Delegation across a trust boundary is unsupported; nothing may add one.
        self::assertStringNotContainsString('actor_token', $body);

        // The cross-domain path is not a different result shape, and §15.2 rules 6-7 hold.
        self::assertSame(self::ISSUED_TOKEN, $result->accessToken->reveal());
        self::assertSame('urn:ietf:params:oauth:token-type:access_token', $result->issuedTokenType);
        self::assertSame('read:orders', $result->scope);
    }

    public function testSubjectTokenTypeIsNeverInferredFromTheToken(): void
    {
        $history = [];
        $client = $this->client([self::exchangeResponse()], history: $history);

        // A subject token that *looks* exactly like a JWT, presented as an access token. An
        // SDK that sniffed the token would "correct" this to …:jwt; §15.7 says it must not
        // look, so what the caller named is what goes out. Being able to hold this wrong is
        // the point: only the caller knows.
        $jwtShaped = 'eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJodHRwczovL3BhcnRuZXIuZXhhbXBsZS8ifQ.sig';
        $client->tokenExchange(
            $jwtShaped,
            OidcClient::ACCESS_TOKEN_TYPE,
            configuration: $this->configuration(),
        );

        self::assertStringContainsString(
            'subject_token_type=urn:ietf:params:oauth:token-type:access_token',
            urldecode((string) $history[0]['request']->getBody()),
            '§15.7: the token\'s shape must not override the caller',
        );
    }

    /**
     * §15.1: the type is required and has no default.
     *
     * PHP refuses a call that omits it entirely — an ArgumentCountError, before any SDK code
     * runs. The case the signature cannot catch is a **blank** string, which is the shape a
     * config-driven caller produces, and which must not become an empty field on the wire.
     *
     * @dataProvider blankSubjectTokenTypes
     */
    public function testABlankSubjectTokenTypeNeverReachesTheWire(string $blank): void
    {
        $history = [];
        $client = $this->client([self::exchangeResponse()], history: $history);

        try {
            $client->tokenExchange(
                self::SUBJECT_TOKEN,
                $blank,
                configuration: $this->configuration(),
            );
            self::fail('expected AuthError');
        } catch (AuthError $e) {
            // The message has to name the way out, or the caller has to go read §15.1.
            self::assertStringContainsString('subjectTokenType', $e->getMessage());
        }

        self::assertCount(0, $history, 'no request may be sent for a type nobody chose');
    }

    /** @return array<string, array{string}> */
    public static function blankSubjectTokenTypes(): array
    {
        return ['empty' => [''], 'spaces' => ['   '], 'tab' => ["\t"]];
    }

    public function testAnOmittedSubjectTokenTypeIsARuntimeError(): void
    {
        // The positional argument is required, so PHP itself refuses the call. That refusal
        // IS the enforcement §15.7 asks for; asserting it here means reintroducing a default
        // fails the suite rather than passing silently.
        $client = $this->client([self::exchangeResponse()]);

        $this->expectException(\ArgumentCountError::class);
        // @phpstan-ignore-next-line argument.missing (that is the assertion)
        $client->tokenExchange(self::SUBJECT_TOKEN);
    }

    public function testAnActorTokenWithAnExternalSubjectTokenIsRefusedWithoutRetry(): void
    {
        $history = [];
        $client = $this->client(
            [self::oauthErrorWithDescription(
                'invalid_request',
                'actor_token is not supported for an external subject token',
            )],
            history: $history,
        );

        try {
            $client->tokenExchange(
                self::EXTERNAL_SUBJECT_TOKEN,
                OidcClient::JWT_TOKEN_TYPE,
                self::ACTOR_TOKEN,
                configuration: $this->configuration(),
            );
            self::fail('expected OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame('invalid_request', $e->error);
        }

        // §15.7: no retry, and no rewriting. Dropping the actor token and re-sending would
        // turn a delegation the caller asked for into an impersonation they did not.
        self::assertCount(1, $history, 'exactly one request');
        $body = urldecode((string) $history[0]['request']->getBody());
        self::assertStringContainsString('actor_token=' . self::ACTOR_TOKEN, $body);
        self::assertStringContainsString(
            'subject_token_type=urn:ietf:params:oauth:token-type:jwt',
            $body,
            'subject_token_type must not be rewritten',
        );
    }

    public function testARefusedSubjectTokenTypeIsNeverRetriedAsAnother(): void
    {
        // A refresh token is a re-authentication credential and an ID token is an assertion
        // to a client about a login; neither is a bearer credential for an API, so both are
        // refused BY NAME. Retrying as …:jwt would present one as if it were.
        foreach ([
            'urn:ietf:params:oauth:token-type:refresh_token',
            'urn:ietf:params:oauth:token-type:id_token',
        ] as $refused) {
            $history = [];
            $client = $this->client(
                [self::oauthErrorWithDescription('invalid_request', 'unsupported subject_token_type')],
                history: $history,
            );

            try {
                $client->tokenExchange(
                    self::EXTERNAL_SUBJECT_TOKEN,
                    configuration: $this->configuration(),
                    subjectTokenType: $refused,
                );
                self::fail('expected OAuthProtocolError');
            } catch (OAuthProtocolError) {
                // expected
            }

            self::assertCount(1, $history, 'no retry after a refused type');
            self::assertStringContainsString(
                'subject_token_type=' . $refused,
                urldecode((string) $history[0]['request']->getBody()),
                '§15.7: the refused type must be sent as named, not swapped',
            );
        }
    }

    public function testTheIssuerNotConfiguredDescriptionReachesTheCallerIntact(): void
    {
        $client = $this->client(
            [self::oauthErrorWithDescription('invalid_grant', self::ISSUER_NOT_CONFIGURED)],
        );

        try {
            $client->tokenExchange(
                self::EXTERNAL_SUBJECT_TOKEN,
                configuration: $this->configuration(),
                subjectTokenType: OidcClient::JWT_TOKEN_TYPE,
            );
            self::fail('expected OAuthProtocolError');
        } catch (OAuthProtocolError $e) {
            self::assertSame('invalid_grant', $e->error);
            // This is the ONLY distinguishable external failure, and the whole point of it is
            // that an integrator can tell "fix the AXIAM trust config" from "fix your token".
            // Truncating or rewording it destroys that.
            self::assertSame(self::ISSUER_NOT_CONFIGURED, $e->errorDescription);
        }
    }

    public function testNoHelperReExchangesAnExternallyExchangedToken(): void
    {
        // Tokens minted from an external subject token carry `ext_exchange`, and BOTH
        // exchange paths refuse a subject token bearing it: exchanges do not compose. The
        // SDK's part is to never feed a result back in by itself.
        $history = [];
        $client = $this->client([self::exchangeResponse('read:orders')], history: $history);

        $result = $client->tokenExchange(
            self::EXTERNAL_SUBJECT_TOKEN,
            configuration: $this->configuration(),
            subjectTokenType: OidcClient::JWT_TOKEN_TYPE,
        );

        self::assertSame(self::ISSUED_TOKEN, $result->accessToken->reveal());
        // Exactly one exchange happened: nothing looped the result back in. §15.2 rule 5 is
        // what stops it — had the result been adopted, the next exchange would carry it as a
        // *subject* token, which is exactly the re-exchange §15.7 forbids, arrived at by
        // accident rather than by decision.
        self::assertCount(1, $history, 'exactly one exchange — nothing re-exchanged the result');
    }
}
