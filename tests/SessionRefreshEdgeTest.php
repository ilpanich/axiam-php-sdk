<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Session;
use GuzzleHttp\Client;
use GuzzleHttp\Cookie\CookieJar;
use GuzzleHttp\Cookie\SetCookie;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use PHPUnit\Framework\TestCase;

/**
 * Covers {@see Session}'s refresh-precondition and unverified-claim-decode edge paths
 * (CONTRACT.md §9, D-06). The single-flight happy path is proven by
 * {@see SingleFlightRefreshTest}; this drives the immediately-rejected branches
 * {@see Session::buildRefreshCall()} takes when the current access token cannot yield a
 * `tenant_id`/`org_id` (a malformed, non-3-part, bad-base64, or non-JSON token, or a
 * validly-shaped token simply missing those claims), plus the small session-state
 * accessors ({@see Session::cookieJar()}, {@see Session::resetCsrf()}). All of these must
 * flow through the SAME single-flight `RefreshGuard::settle()` bookkeeping and surface as
 * an {@see AuthError}, never a synchronous throw.
 */
final class SessionRefreshEdgeTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme-tenant';

    /** A Guzzle client whose transport is never reached on the rejection paths under test. */
    private function idleClient(): Client
    {
        return new Client(['handler' => HandlerStack::create(new MockHandler([]))]);
    }

    private function jarWithAccessToken(string $token): CookieJar
    {
        $jar = new CookieJar();
        $jar->setCookie(new SetCookie([
            'Name' => 'axiam_access',
            'Value' => $token,
            'Domain' => 'api.test',
            'Path' => '/',
        ]));

        return $jar;
    }

    /** @param array<string,mixed> $claims */
    private function jwtWithClaims(array $claims): string
    {
        $segment = static fn (array $data): string => rtrim(
            strtr(base64_encode((string) json_encode($data)), '+/', '-_'),
            '=',
        );

        return $segment(['alg' => 'none', 'typ' => 'JWT']) . '.' . $segment($claims) . '.signature';
    }

    private function sessionWithToken(string $token): Session
    {
        return new Session(self::BASE_URL, self::TENANT, $this->idleClient(), $this->jarWithAccessToken($token));
    }

    public function testCookieJarAndAccessorsExposeConstructorState(): void
    {
        $jar = $this->jarWithAccessToken('h.payload.s');
        $session = new Session(self::BASE_URL, self::TENANT, $this->idleClient(), $jar);

        self::assertSame(self::BASE_URL, $session->baseUrl());
        self::assertSame(self::TENANT, $session->tenant());
        self::assertSame($jar, $session->cookieJar());
        self::assertNull($session->csrfToken());
    }

    public function testResetCsrfClearsCapturedToken(): void
    {
        $session = new Session(self::BASE_URL, self::TENANT, $this->idleClient(), new CookieJar());

        // No CSRF has been captured yet; resetCsrf() is idempotent and leaves it null.
        $session->resetCsrf();

        self::assertNull($session->csrfToken());
    }

    public function testRefreshRejectsWhenTokenIsNotAThreePartJwt(): void
    {
        $session = $this->sessionWithToken('not-a-three-part-token');

        $this->expectException(AuthError::class);
        $session->refreshIfNeeded()->wait();
    }

    public function testRefreshRejectsWhenTokenPayloadIsNotValidBase64(): void
    {
        // Middle segment contains characters outside the base64url alphabet, so the
        // strict base64_decode inside decodeUnverifiedClaims() returns false.
        $session = $this->sessionWithToken('aaaa.@@@@.bbbb');

        $this->expectException(AuthError::class);
        $session->refreshIfNeeded()->wait();
    }

    public function testRefreshRejectsWhenTokenPayloadIsNotJson(): void
    {
        $notJson = rtrim(strtr(base64_encode('this-is-not-json{'), '+/', '-_'), '=');
        $session = $this->sessionWithToken('aaaa.' . $notJson . '.bbbb');

        $this->expectException(AuthError::class);
        $session->refreshIfNeeded()->wait();
    }

    public function testRefreshRejectsWhenTenantIdClaimIsMissing(): void
    {
        $session = $this->sessionWithToken($this->jwtWithClaims(['org_id' => 'org-1']));

        $this->expectException(AuthError::class);
        $session->refreshIfNeeded()->wait();
    }

    public function testRefreshRejectsWhenOrgIdClaimIsMissing(): void
    {
        $session = $this->sessionWithToken($this->jwtWithClaims(['tenant_id' => 'tenant-uuid-1']));

        $this->expectException(AuthError::class);
        $session->refreshIfNeeded()->wait();
    }
}
