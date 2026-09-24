<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use PHPUnit\Framework\TestCase;

// ---------------------------------------------------------------------------
// Test-only doubles for the `ext-grpc` PECL classes, identical in shape to
// {@see UserInfoGrpcClientWrapperTest}'s doubles: `_simpleRequest()` round-trips the
// queued response through real `serializeToString()`/the `$deserialize` callable so
// this file can drive {@see \Axiam\Sdk\Grpc\TokenGrpcClient}'s PUBLIC
// `validateToken()`/`introspectToken()` wrappers end-to-end.
//
// @runTestsInSeparateProcesses / @preserveGlobalState disabled.
// ---------------------------------------------------------------------------

namespace Grpc;

if (!\class_exists(\Grpc\ChannelCredentials::class, false)) {
    if (!\defined('Grpc\\STATUS_OK')) {
        \define('Grpc\\STATUS_OK', 0);
    }
    if (!\defined('Grpc\\STATUS_PERMISSION_DENIED')) {
        \define('Grpc\\STATUS_PERMISSION_DENIED', 7);
    }
    if (!\defined('Grpc\\STATUS_UNAUTHENTICATED')) {
        \define('Grpc\\STATUS_UNAUTHENTICATED', 16);
    }

    final class ChannelCredentials
    {
        public static function createSsl(?string $pemRootCerts = null): object
        {
            return new \stdClass();
        }
    }

    class BaseStub
    {
        public string $capturedHostname = '';

        /** @var array<string, mixed> */
        public array $capturedOptions = [];

        /** @var list<array{method: string, argument: object, metadata: array<string, list<string>>}> */
        public array $calls = [];

        /** @var list<object|null> */
        public array $queuedResponses = [];

        /** @var list<object> */
        public array $queuedStatuses = [];

        /** @param array<string, mixed> $options */
        public function __construct(string $hostname, array $options = [])
        {
            $this->capturedHostname = $hostname;
            $this->capturedOptions = $options;
        }

        public function _simpleRequest(string $method, object $argument, callable $deserialize, array $metadata = [], array $options = []): object
        {
            $this->calls[] = ['method' => $method, 'argument' => $argument, 'metadata' => $metadata];

            $queuedResponse = \array_shift($this->queuedResponses);
            $status = \array_shift($this->queuedStatuses) ?? (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];
            $decoded = $queuedResponse !== null ? $deserialize($queuedResponse->serializeToString()) : null;

            return new class($decoded, $status) {
                public function __construct(private ?object $response, private object $status)
                {
                }

                /** @return array{0: object|null, 1: object} */
                public function wait(): array
                {
                    return [$this->response, $this->status];
                }
            };
        }
    }
}

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Auth\PresentedProofs;
use Axiam\Sdk\Auth\TokenIntrospection;
use Axiam\Sdk\Auth\TokenStatus;
use Axiam\Sdk\Auth\TokenValidation;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\AuthzError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Grpc\Gen\CnfClaim;
use Axiam\Sdk\Grpc\Gen\IntrospectTokenResponse;
use Axiam\Sdk\Grpc\Gen\RptPermission;
use Axiam\Sdk\Grpc\Gen\ValidateTokenResponse;
use Axiam\Sdk\Grpc\TokenGrpcClient;
use PHPUnit\Framework\TestCase;

/**
 * End-to-end tests of {@see TokenGrpcClient}'s PUBLIC `validateToken()`/
 * `introspectToken()` wrappers (CONTRACT.md §1.1.1/§10.3, contract 1.51) — the
 * sibling of {@see UserInfoGrpcClientWrapperTest} for the token transport, and the
 * §10.3 "required tests" set: a `cnf`-bearing response is not treated as a bearer
 * token, an empty `CnfClaim` is refused, and an unbound response still validates.
 *
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
final class TokenGrpcClientWrapperTest extends TestCase
{
    private const THUMBPRINT = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';
    private const OTHER_THUMBPRINT = 'bWluZS1ub3QteW91cnMtdGhpcy1pcy00My1jaGFyc18';

    private function client(?string $callerToken = 'caller-tok'): TokenGrpcClient
    {
        return new TokenGrpcClient('api.axiam.test:9443', static fn (): ?string => $callerToken, 'tenant-1');
    }

    // -- validateToken(): wire round-trip, metadata, the two credentials --------

    public function testValidateTokenSendsTheInspectedTokenInTheMessageAndTheCallersInMetadata(): void
    {
        $client = $this->client('caller-tok');
        $client->queuedResponses[] = (new ValidateTokenResponse())
            ->setValid(true)
            ->setSubjectId('sub-1')
            ->setTenantId('tenant-1')
            ->setOrgId('org-1')
            ->setExp(1234)
            ->setTokenType('Bearer');
        $client->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $result = $client->validateToken(new Sensitive('inspected-tok'));

        self::assertInstanceOf(TokenValidation::class, $result);
        self::assertTrue($result->valid);
        self::assertSame('sub-1', $result->subjectId);
        self::assertSame(1234, $result->exp);
        self::assertNull($result->cnf);
        self::assertSame(TokenStatus::Bearer, $result->status());

        self::assertCount(1, $client->calls);
        self::assertSame('/axiam.v1.TokenService/ValidateToken', $client->calls[0]['method']);
        // The CALLER's token is on the wire as `authorization` metadata...
        self::assertSame(['Bearer caller-tok'], $client->calls[0]['metadata']['authorization']);
        self::assertSame(['tenant-1'], $client->calls[0]['metadata']['x-tenant-id']);
        // ...and the INSPECTED token travels in the request MESSAGE, never in metadata.
        self::assertSame('inspected-tok', $client->calls[0]['argument']->getAccessToken());
    }

    public function testValidateTokenAcceptsABarePlaintextInspectedToken(): void
    {
        $client = $this->client();
        $client->queuedResponses[] = (new ValidateTokenResponse())->setValid(false);
        $client->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $client->validateToken('plain-inspected-tok');

        self::assertSame('plain-inspected-tok', $client->calls[0]['argument']->getAccessToken());
    }

    // -- §10.3 required tests: a `cnf`-bearing response is not a bearer token ---

    public function testValidateTokenBoundResponseIsSenderConstrainedNotBearer(): void
    {
        $client = $this->client();
        $client->queuedResponses[] = (new ValidateTokenResponse())
            ->setValid(true)
            ->setTokenType('Bearer') // §1.1.1 rule 5: token_type stays "Bearer" for a cert-bound token.
            ->setCnf((new CnfClaim())->setX5TS256(self::THUMBPRINT));
        $client->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $result = $client->validateToken(new Sensitive('tok'));

        self::assertSame(TokenStatus::SenderConstrained, $result->status());
        self::assertSame('Bearer', $result->tokenType, 'token_type does not say whether the token is bound (§1.1.1 rule 5)');

        // Satisfied by the matching certificate...
        $result->verifyPossession(PresentedProofs::certificate(self::THUMBPRINT));
        self::assertTrue(true, 'no exception: possession verified');

        // ...and refused by a different one or none at all.
        try {
            $result->verifyPossession(PresentedProofs::none());
            self::fail('expected AuthError: no evidence for a bound token');
        } catch (AuthError) {
        }
        try {
            $result->verifyPossession(PresentedProofs::certificate(self::OTHER_THUMBPRINT));
            self::fail('expected AuthError: wrong certificate');
        } catch (AuthError) {
        }
    }

    /** An empty `CnfClaim` is refused, not read as unbound (§10.3 rule 3). */
    public function testValidateTokenEmptyCnfClaimIsUnverifiableNotUnbound(): void
    {
        $client = $this->client();
        $client->queuedResponses[] = (new ValidateTokenResponse())
            ->setValid(true)
            ->setCnf(new CnfClaim()); // present message, both members empty
        $client->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $result = $client->validateToken(new Sensitive('tok'));

        self::assertNotNull($result->cnf, 'a present CnfClaim message must not decode to null (that means unbound)');
        self::assertSame(TokenStatus::Unverifiable, $result->status());

        try {
            $result->verifyPossession(PresentedProofs::certificate(self::THUMBPRINT));
            self::fail('expected AuthError: nothing satisfies an unverifiable confirmation');
        } catch (AuthError) {
        }
    }

    /** The positive regression: an unbound response still validates, with or without proofs. */
    public function testValidateTokenUnboundResponseStillValidatesWithOrWithoutProofs(): void
    {
        $client = $this->client();
        $client->queuedResponses[] = (new ValidateTokenResponse())->setValid(true);
        $client->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $result = $client->validateToken(new Sensitive('tok'));

        self::assertNull($result->cnf);
        self::assertSame(TokenStatus::Bearer, $result->status());
        $result->verifyPossession(PresentedProofs::none());
        $result->verifyPossession(PresentedProofs::certificate(self::THUMBPRINT));
        self::assertTrue(true, 'both accepted: rule 9 does not become a certificate mandate');
    }

    /** §1.1.1 rule 6: a token of another tenant is `valid: false`, an answer not an error. */
    public function testValidateTokenOfAnotherTenantIsInactiveNotAnError(): void
    {
        $client = $this->client();
        $client->queuedResponses[] = (new ValidateTokenResponse())->setValid(false);
        $client->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $result = $client->validateToken(new Sensitive('tok'));

        self::assertFalse($result->valid);
        self::assertSame(TokenStatus::Inactive, $result->status());
        try {
            $result->verifyPossession(PresentedProofs::none());
            self::fail('expected AuthError: an inactive token grants no possession');
        } catch (AuthError) {
        }
    }

    // -- introspectToken(): RFC 7662 fields, permissions, cnf -------------------

    public function testIntrospectTokenDecodesEveryRfc7662FieldAndPermissions(): void
    {
        $client = $this->client('caller-tok');
        $client->queuedResponses[] = (new IntrospectTokenResponse())
            ->setActive(true)
            ->setSub('sub-1')
            ->setTenantId('tenant-1')
            ->setOrgId('org-1')
            ->setIss('https://axiam.test')
            ->setIat(1000)
            ->setExp(2000)
            ->setJti('jti-1')
            ->setScope('read write')
            ->setClientId('client-1')
            ->setTokenType('Bearer')
            ->setExtExchangeIss('https://other-idp.test')
            ->setPermissions([
                (new RptPermission())->setResourceId('res-1')->setResourceScopes(['read'])->setExp(3000),
            ]);
        $client->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $result = $client->introspectToken(new Sensitive('inspected-tok'));

        self::assertInstanceOf(TokenIntrospection::class, $result);
        self::assertTrue($result->active);
        self::assertSame('sub-1', $result->sub);
        self::assertSame('https://axiam.test', $result->iss);
        self::assertSame(1000, $result->iat);
        self::assertSame(2000, $result->exp);
        self::assertSame('jti-1', $result->jti);
        self::assertSame('read write', $result->scope);
        self::assertSame('client-1', $result->clientId);
        self::assertSame('https://other-idp.test', $result->extExchangeIss);
        self::assertCount(1, $result->permissions);
        self::assertSame('res-1', $result->permissions[0]->resourceId);
        self::assertSame(['read'], $result->permissions[0]->resourceScopes);
        self::assertSame(3000, $result->permissions[0]->exp);

        self::assertSame('/axiam.v1.TokenService/IntrospectToken', $client->calls[0]['method']);
        self::assertSame('inspected-tok', $client->calls[0]['argument']->getAccessToken());
    }

    public function testIntrospectTokenBoundResponseRequiresMatchingProof(): void
    {
        $client = $this->client();
        $client->queuedResponses[] = (new IntrospectTokenResponse())
            ->setActive(true)
            ->setCnf((new CnfClaim())->setJkt(self::THUMBPRINT));
        $client->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_OK, 'details' => ''];

        $result = $client->introspectToken(new Sensitive('tok'));

        self::assertSame(TokenStatus::SenderConstrained, $result->status());
        $result->verifyPossession(PresentedProofs::dpop(self::THUMBPRINT));
        self::assertTrue(true);

        try {
            $result->verifyPossession(PresentedProofs::none());
            self::fail('expected AuthError');
        } catch (AuthError) {
        }
    }

    // -- status mapping (shared machinery with the other gRPC wrappers) ---------

    public function testValidateTokenMapsUnauthenticatedStatusToAuthError(): void
    {
        $client = $this->client();
        $client->queuedResponses[] = null;
        $client->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_UNAUTHENTICATED, 'details' => 'expired'];

        $this->expectException(AuthError::class);
        $client->validateToken(new Sensitive('tok'));
    }

    public function testIntrospectTokenMapsPermissionDeniedStatusToAuthzError(): void
    {
        $client = $this->client();
        $client->queuedResponses[] = null;
        $client->queuedStatuses[] = (object) ['code' => \Grpc\STATUS_PERMISSION_DENIED, 'details' => 'denied'];

        $this->expectException(AuthzError::class);
        $client->introspectToken(new Sensitive('tok'));
    }

    public function testValidateTokenMapsOtherStatusToNetworkError(): void
    {
        $client = $this->client();
        $client->queuedResponses[] = null;
        $client->queuedStatuses[] = (object) ['code' => 14, 'details' => 'unavailable'];

        $this->expectException(NetworkError::class);
        $client->validateToken(new Sensitive('tok'));
    }
}
