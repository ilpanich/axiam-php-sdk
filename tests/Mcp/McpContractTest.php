<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Mcp;

use Axiam\Sdk\Management\ValidationError;
use Axiam\Sdk\Mcp\BearerChallengeError;
use Axiam\Sdk\Mcp\Mcp;
use PHPUnit\Framework\TestCase;

/**
 * CONTRACT.md §28.9 tests 1 and 2 — the two of the five required tests that are
 * framework-independent, since {@see Mcp::protectedResourceMetadata()} and
 * {@see Mcp::bearerChallenge()} perform no I/O and touch no request (§28.0). Tests 3–5
 * and the off-by-default regression need a server and live in
 * {@see \Axiam\Sdk\Tests\Mcp\McpLaravelTest} and
 * {@see \Axiam\Sdk\Tests\Mcp\McpSymfonyTest} — one file per framework surface, so a
 * divergence between the two bridges is visible as a different expected value rather
 * than as a different test.
 *
 * The fixture is §28.9's own, verbatim, reused by every §28 test in this repository.
 */
final class McpContractTest extends TestCase
{
    private const RESOURCE = 'https://mcp.example.com/mcp';
    private const AUTHORIZATION_SERVERS = ['https://axiam.example.com'];
    private const SCOPES_SUPPORTED = ['mcp:read', 'mcp:tools'];
    private const RESOURCE_DOCUMENTATION = 'https://mcp.example.com/docs';
    private const METADATA_PATH = '/.well-known/oauth-protected-resource/mcp';
    private const METADATA_URL = 'https://mcp.example.com/.well-known/oauth-protected-resource/mcp';

    // -------------------------------------------------------------------------------
    // Test 1: document shape, and the validation negatives.
    // -------------------------------------------------------------------------------

    public function testFixtureProducesTheExactDocumentShapeAndDerivedUrls(): void
    {
        $metadata = Mcp::protectedResourceMetadata(
            resource: self::RESOURCE,
            authorizationServers: self::AUTHORIZATION_SERVERS,
            scopesSupported: self::SCOPES_SUPPORTED,
            resourceDocumentation: self::RESOURCE_DOCUMENTATION,
        );

        self::assertSame(
            [
                'resource' => self::RESOURCE,
                'authorization_servers' => self::AUTHORIZATION_SERVERS,
                'scopes_supported' => self::SCOPES_SUPPORTED,
                'bearer_methods_supported' => ['header'],
                'resource_documentation' => self::RESOURCE_DOCUMENTATION,
            ],
            $metadata->document,
        );
        // Member ORDER is fixed by §28.2, and compared explicitly here — not just as a
        // set — because it is what json_encode() will actually emit.
        self::assertSame(
            ['resource', 'authorization_servers', 'scopes_supported', 'bearer_methods_supported', 'resource_documentation'],
            array_keys($metadata->document),
        );
        self::assertSame(self::METADATA_PATH, $metadata->metadataPath);
        self::assertSame(self::METADATA_URL, $metadata->metadataUrl);
    }

    /** @return iterable<string,array{string,string}> */
    public static function metadataPathDerivations(): iterable
    {
        yield 'no path' => ['https://mcp.example.com', '/.well-known/oauth-protected-resource'];
        yield 'bare slash' => ['https://mcp.example.com/', '/.well-known/oauth-protected-resource'];
        yield 'one segment' => ['https://mcp.example.com/mcp', '/.well-known/oauth-protected-resource/mcp'];
        yield 'trailing slash preserved' => ['https://mcp.example.com/mcp/', '/.well-known/oauth-protected-resource/mcp/'];
        yield 'two segments' => ['https://mcp.example.com/a/b', '/.well-known/oauth-protected-resource/a/b'];
    }

    /** @dataProvider metadataPathDerivations */
    public function testMetadataPathDerivation(string $resource, string $expectedPath): void
    {
        $metadata = Mcp::protectedResourceMetadata($resource, self::AUTHORIZATION_SERVERS, self::SCOPES_SUPPORTED);

        self::assertSame($expectedPath, $metadata->metadataPath);
    }

    public function testRelativeResourceIsRejected(): void
    {
        $this->expectException(ValidationError::class);
        Mcp::protectedResourceMetadata('/mcp', self::AUTHORIZATION_SERVERS, self::SCOPES_SUPPORTED);
    }

    public function testResourceWithFragmentIsRejected(): void
    {
        $this->expectException(ValidationError::class);
        Mcp::protectedResourceMetadata(self::RESOURCE . '#frag', self::AUTHORIZATION_SERVERS, self::SCOPES_SUPPORTED);
    }

    public function testResourceWithQueryIsRejected(): void
    {
        $this->expectException(ValidationError::class);
        Mcp::protectedResourceMetadata(self::RESOURCE . '?x=1', self::AUTHORIZATION_SERVERS, self::SCOPES_SUPPORTED);
    }

    public function testHttpResourceOnNonLoopbackHostIsRejected(): void
    {
        $this->expectException(ValidationError::class);
        Mcp::protectedResourceMetadata('http://mcp.example.com/mcp', self::AUTHORIZATION_SERVERS, self::SCOPES_SUPPORTED);
    }

    public function testHttpResourceOnLoopbackHostIsAccepted(): void
    {
        $metadata = Mcp::protectedResourceMetadata('http://127.0.0.1/mcp', self::AUTHORIZATION_SERVERS, self::SCOPES_SUPPORTED);

        self::assertSame('http://127.0.0.1/.well-known/oauth-protected-resource/mcp', $metadata->metadataUrl);
    }

    public function testEmptyAuthorizationServersIsRejected(): void
    {
        $this->expectException(ValidationError::class);
        Mcp::protectedResourceMetadata(self::RESOURCE, [], self::SCOPES_SUPPORTED);
    }

    public function testAuthorizationServersEntryWithQueryIsRejected(): void
    {
        $this->expectException(ValidationError::class);
        Mcp::protectedResourceMetadata(self::RESOURCE, ['https://axiam.example.com?x=1'], self::SCOPES_SUPPORTED);
    }

    public function testAuthorizationServersEntryWithFragmentIsRejected(): void
    {
        $this->expectException(ValidationError::class);
        Mcp::protectedResourceMetadata(self::RESOURCE, ['https://axiam.example.com#frag'], self::SCOPES_SUPPORTED);
    }

    public function testDuplicateAuthorizationServersEntryIsRejected(): void
    {
        $this->expectException(ValidationError::class);
        Mcp::protectedResourceMetadata(
            self::RESOURCE,
            ['https://axiam.example.com', 'https://axiam.example.com'],
            self::SCOPES_SUPPORTED,
        );
    }

    public function testDuplicateScopeIsRejected(): void
    {
        $this->expectException(ValidationError::class);
        Mcp::protectedResourceMetadata(self::RESOURCE, self::AUTHORIZATION_SERVERS, ['mcp:read', 'mcp:read']);
    }

    public function testBearerMethodsSupportedOfQueryIsRejected(): void
    {
        $this->expectException(ValidationError::class);
        Mcp::protectedResourceMetadata(
            self::RESOURCE,
            self::AUTHORIZATION_SERVERS,
            self::SCOPES_SUPPORTED,
            bearerMethodsSupported: ['query'],
        );
    }

    public function testBearerMethodsSupportedOfHeaderAndBodyIsRejected(): void
    {
        $this->expectException(ValidationError::class);
        Mcp::protectedResourceMetadata(
            self::RESOURCE,
            self::AUTHORIZATION_SERVERS,
            self::SCOPES_SUPPORTED,
            bearerMethodsSupported: ['header', 'body'],
        );
    }

    public function testEmptyScopesSupportedIsAcceptedAndOmitsTheMember(): void
    {
        $metadata = Mcp::protectedResourceMetadata(self::RESOURCE, self::AUTHORIZATION_SERVERS, []);

        self::assertArrayNotHasKey('scopes_supported', $metadata->document);
    }

    public function testAbsentResourceDocumentationOmitsTheMemberRatherThanNull(): void
    {
        $metadata = Mcp::protectedResourceMetadata(self::RESOURCE, self::AUTHORIZATION_SERVERS, self::SCOPES_SUPPORTED);

        self::assertArrayNotHasKey('resource_documentation', $metadata->document);
        // Guard against a `json_encode` that would emit `"resource_documentation":null`.
        self::assertStringNotContainsString('resource_documentation', (string) json_encode($metadata->document));
    }

    // -------------------------------------------------------------------------------
    // Test 2: challenge quoting.
    // -------------------------------------------------------------------------------

    public function testChallengeVector1NoCredential(): void
    {
        self::assertSame(
            sprintf('Bearer resource_metadata="%s"', self::METADATA_URL),
            Mcp::bearerChallenge(self::METADATA_URL),
        );
    }

    public function testChallengeVector2CredentialPresentedAndRejected(): void
    {
        self::assertSame(
            sprintf('Bearer error="invalid_token", resource_metadata="%s"', self::METADATA_URL),
            Mcp::bearerChallenge(self::METADATA_URL, error: BearerChallengeError::INVALID_TOKEN),
        );
    }

    public function testChallengeVector3ScopeFailure403(): void
    {
        self::assertSame(
            sprintf('Bearer error="insufficient_scope", scope="mcp:tools", resource_metadata="%s"', self::METADATA_URL),
            Mcp::bearerChallenge(self::METADATA_URL, error: BearerChallengeError::INSUFFICIENT_SCOPE, scope: 'mcp:tools'),
        );
    }

    public function testChallengeVector4AllFourParameters(): void
    {
        self::assertSame(
            sprintf(
                'Bearer error="invalid_request", error_description="The access token is malformed", scope="mcp:read mcp:tools", resource_metadata="%s"',
                self::METADATA_URL,
            ),
            Mcp::bearerChallenge(
                self::METADATA_URL,
                error: BearerChallengeError::INVALID_REQUEST,
                errorDescription: 'The access token is malformed',
                scope: 'mcp:read mcp:tools',
            ),
        );
    }

    public function testUnrecognisedErrorCodeIsRejected(): void
    {
        $this->expectException(ValidationError::class);
        // A well-formed-looking OAuth error code that is NOT one of RFC 6750 §3.1's
        // three — the exact case §28.4 calls out by name.
        Mcp::bearerChallenge(self::METADATA_URL, error: 'invalid_grant');
    }

    /** @return iterable<string,array{string}> */
    public static function invalidErrorDescriptions(): iterable
    {
        yield 'contains a double quote' => ['he said "no"'];
        yield 'contains a backslash' => ['a\\b'];
        yield 'contains a newline' => ["line one\nline two"];
        yield 'contains a non-ASCII character' => ['café'];
    }

    /** @dataProvider invalidErrorDescriptions */
    public function testInvalidErrorDescriptionIsRejectedRatherThanEscaped(string $description): void
    {
        try {
            Mcp::bearerChallenge(self::METADATA_URL, errorDescription: $description);
            self::fail('expected a ValidationError');
        } catch (ValidationError $e) {
            // The refusal itself may legitimately quote the bad value in its message;
            // what must never happen is a CHALLENGE VALUE containing an escape.
            self::assertStringNotContainsString('\\"', $e->getMessage());
        }
    }

    /** @return iterable<string,array{string}> */
    public static function invalidScopes(): iterable
    {
        yield 'leading space' => [' mcp:tools'];
        yield 'doubled space' => ['mcp:read  mcp:tools'];
        yield 'empty' => [''];
    }

    /** @dataProvider invalidScopes */
    public function testInvalidScopeIsRejected(string $scope): void
    {
        $this->expectException(ValidationError::class);
        Mcp::bearerChallenge(self::METADATA_URL, scope: $scope);
    }

    public function testResourceMetadataContainingASpaceIsRejected(): void
    {
        $this->expectException(ValidationError::class);
        Mcp::bearerChallenge('https://mcp.example.com/.well-known/oauth-protected-resource/has space');
    }
}
