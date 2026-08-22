<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Account\PasswordResetConfirmation;
use Axiam\Sdk\Account\PasswordResetRequest;
use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\Sensitive;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * CONTRACT.md §25 — account lifecycle and MFA enrolment.
 *
 * The two assertions worth reading twice are the §25.4 pair:
 * `testRequestPasswordResetSaysNothingAboutWhetherTheAccountExists` pins the
 * account-enumeration guarantee to the SDK's *surface* rather than to the server's
 * behaviour, and `testResetContextSendsTheTokenAsAQueryParameter` exists because building
 * that URL by concatenation percent-escapes the `?` into the path — a bug that produces a
 * 404 reading exactly like an expired token.
 */
final class AccountLifecycleTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';
    private const ORG_SLUG = 'globex';
    private const TENANT_UUID = '22222222-2222-2222-2222-222222222222';
    private const SETUP_TOKEN = 'setup-token-fixture-do-not-log';
    private const RESET_TOKEN = 'reset-token-fixture-do-not-log';
    private const SECRET = 'JBSWY3DPEHPK3PXP';

    /** @var list<RequestInterface> */
    private array $sent = [];

    /** @param array<int,Response|\Throwable> $queue */
    private function client(array $queue, ?string $orgSlug = self::ORG_SLUG, string $tenant = self::TENANT): AxiamClient
    {
        $this->sent = [];
        $mock = new MockHandler($queue);
        $captured = &$this->sent;
        $transportHandler = static function (RequestInterface $request, array $options) use ($mock, &$captured) {
            $captured[] = $request;

            return $mock($request, $options);
        };

        return new AxiamClient(self::BASE_URL, $tenant, orgSlug: $orgSlug, transportHandler: $transportHandler);
    }

    /** @return array<string,mixed> */
    private function bodyOf(int $index): array
    {
        $decoded = json_decode((string) $this->sent[$index]->getBody(), true);
        self::assertIsArray($decoded);

        return $decoded;
    }

    private function enrollmentResponse(): Response
    {
        return new Response(200, ['Content-Type' => 'application/json'], (string) json_encode([
            'secret_base32' => self::SECRET,
            'totp_uri' => 'otpauth://totp/AXIAM:alice?secret=' . self::SECRET . '&issuer=AXIAM',
        ]));
    }

    /** @param array<string,mixed> $claims */
    private function unsignedJwt(array $claims): string
    {
        $segment = static fn (array $data): string => rtrim(
            strtr(base64_encode((string) json_encode($data)), '+/', '-_'),
            '=',
        );

        return $segment(['alg' => 'none', 'typ' => 'JWT']) . '.' . $segment($claims) . '.signature';
    }

    private function loginSuccessResponse(): Response
    {
        return new Response(
            200,
            [
                'Set-Cookie' => 'axiam_access=' . $this->unsignedJwt([
                    'sub' => 'user-1',
                    'tenant_id' => self::TENANT_UUID,
                    'jti' => 'session-1',
                    'exp' => time() + 900,
                ]) . '; Path=/',
                'X-CSRF-Token' => 'csrf-abc',
            ],
            (string) json_encode(['user' => ['id' => 'user-1']]),
        );
    }

    // -----------------------------------------------------------------------
    // §25.2 rule 1 — login gains a third outcome
    // -----------------------------------------------------------------------

    public function testLogin403MfaSetupRequiredIsTheThirdOutcome(): void
    {
        $client = $this->client([new Response(403, ['Content-Type' => 'application/json'], (string) json_encode([
            'mfa_setup_required' => true,
            'setup_token' => self::SETUP_TOKEN,
        ]))]);

        $result = $client->login('alice@example.com', 'pw');

        self::assertTrue(
            $result->mfaSetupRequired,
            'a tenant that requires MFA on an account without it is not a failure',
        );
        self::assertFalse($result->mfaRequired, 'the account has no factor to challenge yet');
        self::assertNull($result->userId, 'there is no session, so there is no user');
        self::assertNotNull($result->setupToken);
        self::assertSame(self::SETUP_TOKEN, $result->setupToken->reveal());
    }

    public function testAnOrdinary403IsStillAFailure(): void
    {
        // §25.2 rule 1 keys the third outcome on the error BODY, never on the status alone:
        // a plain 403 must keep throwing, and must keep its §2 authz mapping.
        $client = $this->client([new Response(403, ['Content-Type' => 'application/json'], (string) json_encode([
            'error' => 'authorization_denied',
            'message' => 'tenant suspended',
        ]))]);

        $this->expectException(AuthzError::class);
        $client->login('alice@example.com', 'pw');
    }

    public function testANonJson403DoesNotBecomeAParseFailure(): void
    {
        $client = $this->client([new Response(403, ['Content-Type' => 'text/plain'], 'forbidden')]);

        // Reading the body for a setup token must leave the §2 mapping intact.
        $this->expectException(AuthzError::class);
        $client->login('alice@example.com', 'pw');
    }

    public function testTheThreeOutcomesAreMutuallyExclusive(): void
    {
        // Additive, so every pre-1.28 construction still compiles and reads false for the
        // new flag.
        $challenge = new \Axiam\Sdk\Auth\LoginResult(mfaRequired: true, challengeToken: new Sensitive('chal'));
        self::assertTrue($challenge->mfaRequired);
        self::assertFalse($challenge->mfaSetupRequired);
        self::assertNull($challenge->setupToken);
    }

    // -----------------------------------------------------------------------
    // §25.1 — voluntary enrolment
    // -----------------------------------------------------------------------

    public function testMfaEnrollReturnsTheSecretAndItsUri(): void
    {
        $client = $this->client([$this->enrollmentResponse()]);

        $enrollment = $client->mfaEnroll();

        self::assertSame(self::SECRET, $enrollment->secretBase32->reveal());
        self::assertStringStartsWith('otpauth://totp/', $enrollment->totpUri->reveal());
        self::assertSame('/api/v1/auth/mfa/enroll', $this->sent[0]->getUri()->getPath());
    }

    public function testBothHalvesOfAnEnrolmentAreSensitive(): void
    {
        $client = $this->client([$this->enrollmentResponse()]);

        $enrollment = $client->mfaEnroll();

        // §25.3: the otpauth URI CONTAINS the secret. Wrapping only the bare secret and
        // printing the URI leaks the same bytes — this is the mistake the rule names.
        self::assertStringNotContainsString(self::SECRET, print_r($enrollment->secretBase32, true));
        self::assertStringNotContainsString(self::SECRET, print_r($enrollment->totpUri, true));
        self::assertStringNotContainsString(self::SECRET, print_r($enrollment, true));
    }

    public function testMfaConfirmReportsWhetherTheFactorIsLive(): void
    {
        $client = $this->client([new Response(200, ['Content-Type' => 'application/json'], '{"mfa_enabled":true}')]);

        self::assertTrue($client->mfaConfirm('123456'));
        self::assertSame('/api/v1/auth/mfa/confirm', $this->sent[0]->getUri()->getPath());
        self::assertSame('123456', $this->bodyOf(0)['totp_code']);
    }

    public function testAWrongCodeIsAnAuthError(): void
    {
        $client = $this->client([new Response(401, ['Content-Type' => 'application/json'], '{"message":"invalid code"}')]);

        $this->expectException(AuthError::class);
        $client->mfaConfirm('000000');
    }

    // -----------------------------------------------------------------------
    // §25.1 / §25.2 rule 2 — forced enrolment completes a login
    // -----------------------------------------------------------------------

    public function testMfaSetupEnrollAuthenticatesWithTheSetupTokenAlone(): void
    {
        $client = $this->client([$this->enrollmentResponse()]);

        $client->mfaSetupEnroll(new Sensitive(self::SETUP_TOKEN));

        self::assertSame('/api/v1/auth/mfa/setup/enroll', $this->sent[0]->getUri()->getPath());
        // There is no session yet — the setup token IS the credential.
        self::assertSame(self::SETUP_TOKEN, $this->bodyOf(0)['setup_token']);
    }

    public function testMfaSetupEnrollAcceptsABareToken(): void
    {
        $client = $this->client([$this->enrollmentResponse()]);

        $client->mfaSetupEnroll(self::SETUP_TOKEN);

        self::assertSame(self::SETUP_TOKEN, $this->bodyOf(0)['setup_token']);
    }

    public function testMfaSetupConfirmAdoptsTheSessionLikeALogin(): void
    {
        $client = $this->client([$this->loginSuccessResponse()]);

        $result = $client->mfaSetupConfirm(new Sensitive(self::SETUP_TOKEN), '123456');

        // §25.2 rule 2: this IS the completion of a login, so the credentials it returns
        // are adopted exactly as login() adopts them — not handed back for the caller to
        // install.
        self::assertFalse($result->mfaRequired);
        self::assertFalse($result->mfaSetupRequired);
        self::assertSame('user-1', $result->userId);
        self::assertSame('/api/v1/auth/mfa/setup/confirm', $this->sent[0]->getUri()->getPath());
    }

    // -----------------------------------------------------------------------
    // §25.1 — email verification
    // -----------------------------------------------------------------------

    public function testVerifyEmailNeedsNoSessionAndCarriesTheTenantInTheBody(): void
    {
        $client = $this->client([new Response(204)]);

        $client->verifyEmail(new Sensitive('verify-token'), self::TENANT_UUID);

        self::assertSame('/api/v1/auth/verify-email', $this->sent[0]->getUri()->getPath());
        $body = $this->bodyOf(0);
        // Not ?tenant_id=: §12.1 rule 2's query convention is scoped to the /oauth2
        // endpoints, and this is not one of those.
        self::assertSame(self::TENANT_UUID, $body['tenant_id']);
        self::assertSame('verify-token', $body['token']);
    }

    public function testResendVerificationAccepts202(): void
    {
        $client = $this->client([new Response(202)]);

        $client->resendVerification('alice@example.com', self::TENANT_UUID);

        self::assertSame('/api/v1/auth/resend-verification', $this->sent[0]->getUri()->getPath());
    }

    public function testAnExpiredVerificationTokenIsAnError(): void
    {
        $client = $this->client([new Response(400, ['Content-Type' => 'application/json'], '{"message":"token expired"}')]);

        $this->expectException(NetworkError::class);
        $client->verifyEmail(new Sensitive('stale'), self::TENANT_UUID);
    }

    // -----------------------------------------------------------------------
    // §25.4 — password reset
    // -----------------------------------------------------------------------

    public function testRequestPasswordResetSaysNothingAboutWhetherTheAccountExists(): void
    {
        $client = $this->client([new Response(202), new Response(202)]);

        // Both an existing and an unknown address answer 202 with an empty body, and the
        // SDK returns void — there is no field, no boolean and no exception for a caller
        // to build an enumeration oracle out of.
        $client->requestPasswordReset(new PasswordResetRequest('alice@example.com'));
        $client->requestPasswordReset(new PasswordResetRequest('nobody@example.com'));

        self::assertCount(2, $this->sent);
    }

    public function testRequestPasswordResetFillsTheWorkspaceFromTheClient(): void
    {
        $client = $this->client([new Response(202)]);

        $client->requestPasswordReset(new PasswordResetRequest('alice@example.com'));

        $body = $this->bodyOf(0);
        self::assertSame(self::ORG_SLUG, $body['org_slug']);
        self::assertSame(self::TENANT, $body['tenant_slug']);
    }

    public function testAnExplicitWorkspaceWinsOverTheClientConfiguration(): void
    {
        $client = $this->client([new Response(202)]);

        $client->requestPasswordReset(new PasswordResetRequest(
            'alice@example.com',
            orgSlug: 'other-org',
            tenantId: self::TENANT_UUID,
        ));

        $body = $this->bodyOf(0);
        self::assertSame('other-org', $body['org_slug']);
        self::assertSame(self::TENANT_UUID, $body['tenant_id']);
        self::assertArrayNotHasKey('tenant_slug', $body, 'a resolved tenant_id makes tenant_slug ambiguous');
    }

    public function testResetContextSendsTheTokenAsAQueryParameter(): void
    {
        $client = $this->client([new Response(200, ['Content-Type' => 'application/json'], '{"opaque":null}')]);

        $client->passwordResetContext(new Sensitive(self::RESET_TOKEN));

        $uri = $this->sent[0]->getUri();
        self::assertSame('GET', $this->sent[0]->getMethod());
        // Not percent-escaped into the path, which 404s in a way that reads exactly like
        // an expired token.
        self::assertSame('/api/v1/auth/reset/context', $uri->getPath());
        self::assertSame('token=' . self::RESET_TOKEN, $uri->getQuery());
    }

    public function testATenantWithoutOpaqueReportsNoPolicy(): void
    {
        $client = $this->client([new Response(200, ['Content-Type' => 'application/json'], '{"opaque":null}')]);

        $context = $client->passwordResetContext(new Sensitive(self::RESET_TOKEN));

        self::assertNull($context->opaque, 'no policy means the plaintext path is allowed');
    }

    public function testATenantWithOpaqueHandsBackTheParametersUntouched(): void
    {
        $opaque = [
            'mode' => 'required',
            'cipher_suite' => 'ristretto255-sha512',
            'server_public_key' => 'c2VydmVyLXBr',
            'vendorSpecific' => 'must-survive',
        ];
        $client = $this->client([new Response(
            200,
            ['Content-Type' => 'application/json'],
            (string) json_encode(['opaque' => $opaque]),
        )]);

        $context = $client->passwordResetContext(new Sensitive(self::RESET_TOKEN));

        // Structural equality: the SDK does not model, validate or re-encode the §23
        // parameter block, it forwards it.
        self::assertSame($opaque, $context->opaque);
    }

    public function testUnknownExpiredAndConsumedResetTokensAllLookAlike(): void
    {
        // §25.4 rule 3: the server refuses to distinguish these three, and the SDK must
        // not invent a distinction of its own.
        $client = $this->client([new Response(404, ['Content-Type' => 'application/json'], '{}')]);

        $this->expectException(NetworkError::class);
        $client->passwordResetContext(new Sensitive(self::RESET_TOKEN));
    }

    public function testConfirmSendsThePlaintextPasswordWhenTheTenantHasNoOpaque(): void
    {
        $client = $this->client([new Response(204)]);

        $client->confirmPasswordReset(new PasswordResetConfirmation(
            new Sensitive(self::RESET_TOKEN),
            new Sensitive('new-password'),
            self::TENANT_UUID,
        ));

        self::assertSame('/api/v1/auth/reset/confirm', $this->sent[0]->getUri()->getPath());
        $body = $this->bodyOf(0);
        self::assertSame('new-password', $body['new_password']);
        self::assertArrayNotHasKey('opaque', $body);
    }

    public function testConfirmForwardsTheOpaqueRegistrationRecordVerbatim(): void
    {
        $record = ['registration_record' => 'cmVjb3Jk', 'export_key_hint' => 'aGludA'];
        $client = $this->client([new Response(204)]);

        $client->confirmPasswordReset(new PasswordResetConfirmation(
            self::RESET_TOKEN,
            'unused',
            self::TENANT_UUID,
            opaque: $record,
        ));

        self::assertSame($record, $this->bodyOf(0)['opaque']);
    }

    public function testARejectedResetSurfacesTheError(): void
    {
        $client = $this->client([new Response(
            400,
            ['Content-Type' => 'application/json'],
            '{"message":"password does not meet policy"}',
        )]);

        $this->expectException(NetworkError::class);
        $client->confirmPasswordReset(new PasswordResetConfirmation(
            new Sensitive(self::RESET_TOKEN),
            new Sensitive('x'),
            self::TENANT_UUID,
        ));
    }
}
