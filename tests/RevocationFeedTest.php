<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Auth\JwksVerifier;
use Axiam\Sdk\Auth\RevocationFeed;
use Firebase\JWT\JWT;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Middleware;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * CONTRACT.md §10.4 — the optional session-revocation feed (contract 1.44, AXIAM threats
 * T-39 and T-143).
 *
 * The feature is a narrowing, not a control, and the tests are organised around the five
 * rules that make that true rather than around the class's method list:
 *
 * - DEFAULT OFF — a verifier built as every caller builds one today fetches nothing,
 *   asserted by counting requests on the wire rather than by inspecting a flag.
 * - NEVER ON THE REQUEST PATH — a revoked session is rejected AFTER one poll and not
 *   before, which pins that the guard is not fetching per request.
 * - NEVER FAIL CLOSED — unreachable, non-200, unparseable and wrong-`alg` each behave as
 *   no feed at all, and specifically NOT as an empty list.
 * - ONLY EVER REJECTS — a token that fails a §10.1 rule is rejected whatever the feed
 *   says, and the feed is not even consulted for it.
 * - NO `sid`, NEVER MATCHED — a client-credentials token, an RPT or a token exchange has
 *   no session behind it.
 */
final class RevocationFeedTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/Fixtures';
    private const TENANT = 'acme-tenant';
    private const BASE_URL = 'https://api.test';

    /**
     * The §10.4 pinned vector: this `sid` hashes to this entry. Pinned rather than
     * computed so a change to {@see RevocationFeed::entryFor()} is a test failure and not
     * a silently-agreeing round trip.
     */
    private const PINNED_SID = '6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b';

    private const PINNED_ENTRY = 'i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ';

    /** @var list<string> Every path the SDK requested, in order. */
    private array $requested = [];

    protected function setUp(): void
    {
        $this->requested = [];
    }

    /** @return array<string,mixed> */
    private function jwks(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_jwks.json'), true);
        self::assertIsArray($decoded);

        return $decoded;
    }

    /** @return array{0:string,1:string} [raw 64-byte secret key, kid]. */
    private function keypair(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURES . '/ed25519_keypair.json'), true);
        self::assertIsArray($decoded);

        return [(string) base64_decode(strtr($decoded['secret_key_b64url'], '-_', '+/'), true), $decoded['kid']];
    }

    /** @param array<string,mixed> $claims */
    private function sign(array $claims): string
    {
        [$secretKey, $kid] = $this->keypair();

        return JWT::encode($claims, base64_encode($secretKey), 'EdDSA', $kid);
    }

    /** An AXIAM-shaped access token carrying `$sid` — or none. @return string */
    private function token(?string $sid): string
    {
        $claims = [
            'sub' => 'user-1',
            'tenant_id' => self::TENANT,
            'roles' => ['admin'],
            'exp' => time() + 900,
        ];
        if ($sid !== null) {
            $claims['sid'] = $sid;
        }

        return $this->sign($claims);
    }

    /** The feed document as published. @param list<string> $entries */
    private function feedBody(array $entries): string
    {
        return (string) json_encode([
            'alg' => 'SHA-256',
            'issued_at' => time(),
            'ttl' => 900,
            'revoked' => $entries,
        ]);
    }

    /**
     * A Guzzle client whose queue is served in order, recording every requested path so
     * "did not fetch" can be proven rather than asserted.
     *
     * @param list<Response|\Throwable> $queue
     */
    private function http(array $queue): Client
    {
        $stack = HandlerStack::create(new MockHandler($queue));
        $stack->push(Middleware::mapRequest(function (RequestInterface $request): RequestInterface {
            $this->requested[] = $request->getUri()->getPath();

            return $request;
        }));

        return new Client(['handler' => $stack, 'base_uri' => self::BASE_URL]);
    }

    /** The two responses every successful verification needs before the feed is reached. */
    private function servedKeys(): array
    {
        return [
            new Response(200, [], (string) json_encode(['jwks_uri' => '/oauth2/jwks'])),
            new Response(200, [], (string) json_encode($this->jwks())),
        ];
    }

    private function feedFetches(): int
    {
        return count(array_filter(
            $this->requested,
            static fn (string $path): bool => $path === RevocationFeed::FEED_PATH,
        ));
    }

    // --- The entry encoding is pinned -------------------------------------------------

    public function testEntryForMatchesThePinnedVector(): void
    {
        self::assertSame(self::PINNED_ENTRY, RevocationFeed::entryFor(self::PINNED_SID));
    }

    public function testEntryForHashesTheClaimAsReadNotAReRenderedUuid(): void
    {
        // Upper-case is a DIFFERENT string and must hash differently: §10.4 says hash the
        // claim as read, precisely so the answer does not depend on a UUID parser.
        self::assertNotSame(
            RevocationFeed::entryFor(self::PINNED_SID),
            RevocationFeed::entryFor(strtoupper(self::PINNED_SID)),
        );
    }

    public function testEntryForIsBase64UrlUnpadded(): void
    {
        $entry = RevocationFeed::entryFor(self::PINNED_SID);
        self::assertStringNotContainsString('=', $entry);
        self::assertStringNotContainsString('+', $entry);
        self::assertStringNotContainsString('/', $entry);
    }

    // --- Default off ------------------------------------------------------------------

    public function testNoFeedAttachedFetchesNothingAndAcceptsARevokedSession(): void
    {
        // The I4 twin: a verifier built exactly as every caller builds one today. The
        // session IS revoked on the server, and this verifier neither knows nor asks.
        $http = $this->http($this->servedKeys());
        $verifier = new JwksVerifier($http, self::BASE_URL, 300);

        self::assertNotNull($verifier->verify($this->token(self::PINNED_SID), self::TENANT));
        self::assertSame(0, $this->feedFetches());
    }

    // --- Never on the request path ----------------------------------------------------

    public function testARevokedSessionIsRejectedAfterOnePollAndNotBefore(): void
    {
        $http = $this->http([
            ...$this->servedKeys(),
            new Response(200, [], $this->feedBody([self::PINNED_ENTRY])),
        ]);
        $verifier = new JwksVerifier($http, self::BASE_URL, 300, null, null, new RevocationFeed($http, self::BASE_URL));
        $jwt = $this->token(self::PINNED_SID);

        self::assertNull($verifier->verify($jwt, self::TENANT));
        self::assertSame(1, $this->feedFetches());

        // Still rejected, and still exactly one fetch: the second answer came from the
        // cached set, which is what "never on the request path" means. The mock queue is
        // empty now, so a second fetch would blow up rather than pass quietly.
        self::assertNull($verifier->verify($jwt, self::TENANT));
        self::assertSame(1, $this->feedFetches());
    }

    public function testManyVerificationsPollOnceWithinOneInterval(): void
    {
        $http = $this->http([
            ...$this->servedKeys(),
            new Response(200, [], $this->feedBody([self::PINNED_ENTRY])),
        ]);
        $verifier = new JwksVerifier($http, self::BASE_URL, 300, null, null, new RevocationFeed($http, self::BASE_URL));
        $jwt = $this->token('some-other-session');

        for ($i = 0; $i < 25; ++$i) {
            self::assertNotNull($verifier->verify($jwt, self::TENANT));
        }

        self::assertSame(1, $this->feedFetches());
    }

    public function testAnUnlistedSessionIsAccepted(): void
    {
        $http = $this->http([
            ...$this->servedKeys(),
            new Response(200, [], $this->feedBody([self::PINNED_ENTRY])),
        ]);
        $verifier = new JwksVerifier($http, self::BASE_URL, 300, null, null, new RevocationFeed($http, self::BASE_URL));

        self::assertNotNull($verifier->verify($this->token('a-session-nobody-revoked'), self::TENANT));
    }

    // --- Never fail closed ------------------------------------------------------------

    public function testAnUnreachableFeedBehavesAsNoFeedAtAll(): void
    {
        // The I4 twin for the feature ON: the feed is attached and the deployment does not
        // serve it. Every verification must succeed exactly as it does with no feed.
        $http = $this->http([
            ...$this->servedKeys(),
            new \RuntimeException('connection refused'),
        ]);
        $verifier = new JwksVerifier($http, self::BASE_URL, 300, null, null, new RevocationFeed($http, self::BASE_URL));

        self::assertNotNull($verifier->verify($this->token(self::PINNED_SID), self::TENANT));
    }

    /** @dataProvider unusableDocuments */
    public function testAnUnusableDocumentBehavesAsNoFeedAtAll(Response $response): void
    {
        $http = $this->http([...$this->servedKeys(), $response]);
        $verifier = new JwksVerifier($http, self::BASE_URL, 300, null, null, new RevocationFeed($http, self::BASE_URL));

        // Every one of these documents names this very session. An SDK that ignored the
        // defect would reject; acceptance here is §10.4 rule 3.
        self::assertNotNull($verifier->verify($this->token(self::PINNED_SID), self::TENANT));
    }

    /** @return array<string,array{0:Response}> */
    public function unusableDocuments(): array
    {
        $listed = ['revoked' => ['i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ']];

        return [
            '404' => [new Response(404, [], '{}')],
            '500' => [new Response(500, [], '{}')],
            '401' => [new Response(401, [], '{}')],
            'unparseable body' => [new Response(200, [], '{not json')],
            'not an object' => [new Response(200, [], '[]')],
            'unknown alg' => [new Response(200, [], (string) json_encode(['alg' => 'SHA-512'] + $listed))],
            'missing alg' => [new Response(200, [], (string) json_encode($listed))],
            'revoked is not an array' => [new Response(200, [], (string) json_encode(['alg' => 'SHA-256', 'revoked' => 'x']))],
            'a non-string entry' => [new Response(200, [], (string) json_encode(['alg' => 'SHA-256', 'revoked' => [1]]))],
        ];
    }

    public function testAFailedPollDoesNotUnrevokeAnAlreadyKnownSession(): void
    {
        // This is the difference between "unusable" and "empty", made observable: the
        // first poll succeeds and knows the session is revoked; the second fails. A feed
        // that collapsed failure into an empty list would now ADMIT a session it had
        // already been told was revoked.
        $http = $this->http([
            ...$this->servedKeys(),
            new Response(200, [], $this->feedBody([self::PINNED_ENTRY])),
            new Response(500, [], '{}'),
        ]);
        $feed = new RevocationFeed($http, self::BASE_URL);
        $verifier = new JwksVerifier($http, self::BASE_URL, 300, null, null, $feed);
        $jwt = $this->token(self::PINNED_SID);

        self::assertNull($verifier->verify($jwt, self::TENANT));

        // Force the interval to have elapsed, so the next verification really re-polls.
        $feed->setClock(static fn (): float => microtime(true) + 600.0);

        self::assertNull($verifier->verify($jwt, self::TENANT));
        self::assertSame(2, $this->feedFetches());
    }

    public function testAnOverflowingDocumentIsDroppedWholeNotTruncated(): void
    {
        $entries = [self::PINNED_ENTRY];
        for ($i = 0; $i < RevocationFeed::MAX_ENTRIES; ++$i) {
            $entries[] = 'entry-' . $i;
        }

        $http = $this->http([...$this->servedKeys(), new Response(200, [], $this->feedBody($entries))]);
        $verifier = new JwksVerifier($http, self::BASE_URL, 300, null, null, new RevocationFeed($http, self::BASE_URL));

        // Listed in the document, and admitted — because the whole set was dropped. A
        // truncating implementation would admit some revoked sessions and report none.
        self::assertNotNull($verifier->verify($this->token(self::PINNED_SID), self::TENANT));
    }

    // --- It only ever rejects ---------------------------------------------------------

    public function testATokenFailingASectionTenOneRuleIsRejectedWithoutConsultingTheFeed(): void
    {
        $http = $this->http([...$this->servedKeys(), new Response(200, [], $this->feedBody([]))]);
        $verifier = new JwksVerifier($http, self::BASE_URL, 300, null, null, new RevocationFeed($http, self::BASE_URL));

        // Wrong tenant: rejected by §10.1 long before §10.4 could have an opinion.
        $jwt = $this->sign([
            'sub' => 'user-1',
            'tenant_id' => 'some-other-tenant',
            'roles' => ['admin'],
            'exp' => time() + 900,
            'sid' => self::PINNED_SID,
        ]);

        self::assertNull($verifier->verify($jwt, self::TENANT));
        self::assertSame(0, $this->feedFetches());
    }

    public function testAnExpiredTokenIsRejectedWithoutConsultingTheFeed(): void
    {
        $http = $this->http([...$this->servedKeys(), new Response(200, [], $this->feedBody([]))]);
        $verifier = new JwksVerifier($http, self::BASE_URL, 300, null, null, new RevocationFeed($http, self::BASE_URL));

        $jwt = $this->sign([
            'sub' => 'user-1',
            'tenant_id' => self::TENANT,
            'roles' => ['admin'],
            'exp' => time() - 1800,
            'sid' => self::PINNED_SID,
        ]);

        self::assertNull($verifier->verify($jwt, self::TENANT));
        self::assertSame(0, $this->feedFetches());
    }

    // --- A token with no sid is never matched -----------------------------------------

    public function testATokenWithoutSidIsNeverMatched(): void
    {
        // A client-credentials token, an RPT or a token exchange. The feed happens to list
        // the hash of the empty string; nothing may match it.
        $http = $this->http([
            ...$this->servedKeys(),
            new Response(200, [], $this->feedBody([RevocationFeed::entryFor('')])),
        ]);
        $verifier = new JwksVerifier($http, self::BASE_URL, 300, null, null, new RevocationFeed($http, self::BASE_URL));

        self::assertNotNull($verifier->verify($this->token(null), self::TENANT));
    }

    // --- Bounds -----------------------------------------------------------------------

    public function testThePollIntervalIsClampedUpNotRefused(): void
    {
        $http = $this->http([]);

        self::assertSame(
            RevocationFeed::MIN_POLL_INTERVAL_SECONDS,
            (new RevocationFeed($http, self::BASE_URL, 1))->pollIntervalSeconds(),
        );
        self::assertSame(120, (new RevocationFeed($http, self::BASE_URL, 120))->pollIntervalSeconds());
        self::assertSame(
            RevocationFeed::DEFAULT_POLL_INTERVAL_SECONDS,
            (new RevocationFeed($http, self::BASE_URL))->pollIntervalSeconds(),
        );
    }

    public function testTheFeedUrlIsTheDocumentedPath(): void
    {
        $feed = new RevocationFeed($this->http([]), self::BASE_URL);

        self::assertSame('https://api.test/oauth2/revocations', $feed->feedUrl());
        self::assertSame('/oauth2/revocations', RevocationFeed::FEED_PATH);
    }

    public function testATrailingSlashOnTheBaseUrlDoesNotDoubleTheSeparator(): void
    {
        $feed = new RevocationFeed($this->http([]), self::BASE_URL . '/');

        self::assertSame('https://api.test/oauth2/revocations', $feed->feedUrl());
    }
}
