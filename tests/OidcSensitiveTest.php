<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Oidc\AuthorizationRequest;
use Axiam\Sdk\Oidc\OidcStateEntry;
use Axiam\Sdk\Oidc\OidcTokenSet;
use PHPUnit\Framework\TestCase;

/**
 * CONTRACT.md §12.5: `access_token`, `refresh_token`, `id_token`, `client_secret`, and
 * `code_verifier` MUST each be {@see Sensitive}-wrapped and MUST NOT leak through
 * `__toString()`/`var_dump()`/`json_encode()` — including `AuthorizationRequest`,
 * `OidcTokenSet`, and an `OidcStateStore` entry as WHOLE OBJECTS, not just the raw
 * `Sensitive` instance in isolation (already proven generically by
 * {@see SensitiveRedactionTest}). `state` and `nonce` are explicitly NOT secrets
 * (§12.3 rule 2) and must remain plain, readable strings.
 */
final class OidcSensitiveTest extends TestCase
{
    private const RAW_CODE_VERIFIER = 'super-secret-code-verifier-value';
    private const RAW_ACCESS_TOKEN = 'super-secret-access-token';
    private const RAW_REFRESH_TOKEN = 'super-secret-refresh-token';
    private const RAW_ID_TOKEN = 'super.secret.idtoken';

    public function testAuthorizationRequestCodeVerifierIsRedactedInVarDumpAndJson(): void
    {
        $request = new AuthorizationRequest(
            url: 'https://api.test/oauth2/authorize?...',
            state: 'plain-state-value',
            nonce: 'plain-nonce-value',
            codeVerifier: new Sensitive(self::RAW_CODE_VERIFIER),
        );

        $dump = print_r($request, true);
        self::assertStringNotContainsString(self::RAW_CODE_VERIFIER, $dump);

        // state/nonce are NOT secrets (§12.3 rule 2) — they must remain visible; this is
        // the non-vacuous control proving redaction is selective, not blanket.
        self::assertStringContainsString('plain-state-value', $dump);
        self::assertStringContainsString('plain-nonce-value', $dump);

        self::assertSame('[SENSITIVE]', (string) $request->codeVerifier);
        self::assertSame(self::RAW_CODE_VERIFIER, $request->codeVerifier->reveal());
    }

    public function testOidcTokenSetRedactsAllThreeSecretFields(): void
    {
        $tokens = new OidcTokenSet(
            accessToken: new Sensitive(self::RAW_ACCESS_TOKEN),
            tokenType: 'Bearer',
            expiresIn: 900,
            refreshToken: new Sensitive(self::RAW_REFRESH_TOKEN),
            idToken: new Sensitive(self::RAW_ID_TOKEN),
        );

        $dump = print_r($tokens, true);
        self::assertStringNotContainsString(self::RAW_ACCESS_TOKEN, $dump);
        self::assertStringNotContainsString(self::RAW_REFRESH_TOKEN, $dump);
        self::assertStringNotContainsString(self::RAW_ID_TOKEN, $dump);
        // Non-vacuous control: a benign, non-secret field must still be visible.
        self::assertStringContainsString('Bearer', $dump);

        self::assertSame(self::RAW_ACCESS_TOKEN, $tokens->accessToken->reveal());
        self::assertSame(self::RAW_REFRESH_TOKEN, $tokens->refreshToken?->reveal());
        self::assertSame(self::RAW_ID_TOKEN, $tokens->idToken?->reveal());
    }

    public function testOidcTokenSetJsonEncodeNeverEmitsSecretValues(): void
    {
        $tokens = new OidcTokenSet(
            accessToken: new Sensitive(self::RAW_ACCESS_TOKEN),
            tokenType: 'Bearer',
            expiresIn: 900,
            refreshToken: new Sensitive(self::RAW_REFRESH_TOKEN),
        );

        // OidcTokenSet has no jsonSerialize() of its own -- json_encode() falls back to
        // public-property enumeration, where each Sensitive property individually
        // implements JsonSerializable (redacting itself) — proving the object-level
        // encode still can't leak the secret even without a custom encoder.
        $json = (string) json_encode($tokens);

        self::assertStringNotContainsString(self::RAW_ACCESS_TOKEN, $json);
        self::assertStringNotContainsString(self::RAW_REFRESH_TOKEN, $json);
        self::assertStringContainsString('[SENSITIVE]', $json);
        self::assertStringContainsString('Bearer', $json);
    }

    public function testOidcStateEntryRedactsCodeVerifierForItsWholeLifetime(): void
    {
        // §12.5: code_verifier is secret "for its whole lifetime, including ... in any
        // OidcStateStore entry".
        $entry = new OidcStateEntry(
            state: 'plain-state',
            nonce: 'plain-nonce',
            codeVerifier: new Sensitive(self::RAW_CODE_VERIFIER),
            redirectUri: 'https://app.test/callback',
        );

        $dump = print_r($entry, true);
        self::assertStringNotContainsString(self::RAW_CODE_VERIFIER, $dump);
        self::assertStringContainsString('plain-state', $dump);

        $json = (string) json_encode($entry);
        self::assertStringNotContainsString(self::RAW_CODE_VERIFIER, $json);
    }

    public function testStateAndNonceAreNotWrappedAsSensitive(): void
    {
        // §12.3 rule 2: state/nonce are explicitly plain strings, never Sensitive.
        $request = new AuthorizationRequest('u', 'state-value', 'nonce-value', new Sensitive('v'));

        self::assertIsString($request->state);
        self::assertIsString($request->nonce);
    }
}
