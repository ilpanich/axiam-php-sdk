<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract158;

use Axiam\Sdk\AxiamClient;
use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Management\NotFoundError;
use Axiam\Sdk\Management\ValidationError;
use Axiam\Sdk\Ssf\InMemoryReplayStore;
use Axiam\Sdk\Ssf\SetErr;
use Axiam\Sdk\Ssf\SetFailureReason;
use Axiam\Sdk\Ssf\SetVerificationError;
use Axiam\Sdk\Ssf\SsfEventTypes;
use Axiam\Sdk\Ssf\SsfPollOptions;
use Axiam\Sdk\Ssf\SsfReceiver;
use Axiam\Sdk\Tests\Fixtures\RedactionAssertions;
use Axiam\Sdk\Tests\Fixtures\RoutedHandler;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;

/**
 * The SSF receiver helper — CONTRACT.md §32.8's eight helper tests (and the poll-not-retried
 * case). Every key is an Ed25519 key generated here, and every SET is signed here.
 */
final class SsfReceiverTest extends TestCase
{
    use RedactionAssertions;

    private const BASE_URL = 'https://iam.example.test';
    private const ISSUER = 'https://iam.example.test/t/22222222-2222-4222-8222-222222222222';
    private const AUDIENCE = 'https://rp.example.test';
    private const JWKS = '/oauth2/jwks';

    private RoutedHandler $routes;

    private int $now = 1791500000;

    protected function setUp(): void
    {
        $this->routes = new RoutedHandler();
    }

    /** @return array{kid:string,secret:string,public:string} */
    private static function key(): array
    {
        $pair = sodium_crypto_sign_keypair();

        return [
            'kid' => 'k-' . bin2hex(random_bytes(8)),
            'secret' => sodium_crypto_sign_secretkey($pair),
            'public' => sodium_crypto_sign_publickey($pair),
        ];
    }

    private static function b64(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * @param array{kid:string,secret:string,public:string} $key
     * @return array<string,string>
     */
    private static function jwk(array $key): array
    {
        return ['kty' => 'OKP', 'crv' => 'Ed25519', 'alg' => 'EdDSA', 'use' => 'sig', 'kid' => $key['kid'], 'x' => self::b64($key['public'])];
    }

    /**
     * @param array{kid:string,secret:string,public:string} $key
     * @param array<string,mixed> $header
     * @param array<string,mixed> $claims
     */
    private static function sign(array $key, array $header, array $claims): string
    {
        $input = self::b64((string) json_encode($header)) . '.' . self::b64((string) json_encode($claims, JSON_UNESCAPED_SLASHES));

        return $input . '.' . self::b64(sodium_crypto_sign_detached($input, $key['secret']));
    }

    /**
     * @param array{kid:string,secret:string,public:string} $key
     * @param array<string,mixed> $claims
     */
    private static function signSet(array $key, array $claims): string
    {
        return self::sign($key, ['alg' => 'EdDSA', 'typ' => 'secevent+jwt', 'kid' => $key['kid']], $claims);
    }

    /** @return array<string,mixed> */
    private static function claims(): array
    {
        return [
            'iss' => self::ISSUER, 'aud' => self::AUDIENCE, 'iat' => 1791500000,
            'jti' => bin2hex(random_bytes(16)), 'txn' => 't-1',
            'sub_id' => ['format' => 'iss_sub', 'iss' => self::ISSUER, 'sub' => bin2hex(random_bytes(8))],
            'events' => [SsfEventTypes::SESSION_REVOKED => ['event_timestamp' => 1791500000]],
        ];
    }

    /** @param list<array<string,string>> $jwks */
    private function serveJwks(array $jwks): void
    {
        $this->routes->on('GET', self::JWKS, RoutedHandler::json(200, ['keys' => $jwks]));
    }

    private function client(bool $retry = false): AxiamClient
    {
        return new AxiamClient(self::BASE_URL, 'acme', transportHandler: $this->routes, retryEnabled: $retry);
    }

    private function receiver(bool $retry = false, ?string &$token = null): SsfReceiver
    {
        $token = 'cc-' . bin2hex(random_bytes(16));
        $bearer = $token;

        return new SsfReceiver(
            http: new \GuzzleHttp\Client(['handler' => \GuzzleHttp\HandlerStack::create($this->routes)]),
            baseUrl: self::BASE_URL,
            issuer: self::ISSUER,
            audience: self::AUDIENCE,
            jwksUri: self::BASE_URL . self::JWKS,
            accessTokenProvider: static fn (): Sensitive => new Sensitive($bearer),
            retryEnabled: $retry,
            clock: fn (): int => $this->now,
        );
    }

    private static function reason(SsfReceiver $receiver, string $set): SetFailureReason
    {
        try {
            $receiver->verifySet($set);
        } catch (SetVerificationError $e) {
            self::assertInstanceOf(AuthError::class, $e);
            self::assertSame($e->failureReason->value, $e->getReason());

            return $e->failureReason;
        }
        self::fail('the SET was not refused');
    }

    // -- 1 -------------------------------------------------------------------------------

    public function testASetSignedByTheJwksKeyVerifiesIntoItsClaims(): void
    {
        $key = self::key();
        $this->serveJwks([self::jwk($key)]);
        $claims = self::claims();

        $event = $this->client()->ssfReceiver(self::ISSUER, self::AUDIENCE, jwksUri: self::BASE_URL . self::JWKS)
            ->verifySet(self::signSet($key, $claims));

        self::assertSame($claims['jti'], $event->jti);
        self::assertSame(1791500000, $event->iat);
        self::assertSame(self::ISSUER, $event->iss);
        self::assertSame(self::AUDIENCE, $event->aud);
        self::assertSame('t-1', $event->txn);
        self::assertSame(SsfEventTypes::SESSION_REVOKED, $event->eventType);
        self::assertSame(['event_timestamp' => 1791500000], $event->event);
        self::assertSame($claims['sub_id'], $event->subId);

        // An aud array containing the audience verifies, and so does the media-type typ.
        $array = array_merge(self::claims(), ['aud' => ['other', self::AUDIENCE]]);
        unset($array['txn']);
        $set = self::sign($key, ['alg' => 'EdDSA', 'typ' => 'Application/SecEvent+JWT', 'kid' => $key['kid']], $array);
        $event = $this->receiver()->verifySet($set);
        self::assertSame(['other', self::AUDIENCE], $event->aud);
        self::assertNull($event->txn);
    }

    // -- 2 -------------------------------------------------------------------------------

    public function testAWrongTypOrAlgIsRefusedInThatOrder(): void
    {
        $key = self::key();
        $this->serveJwks([self::jwk($key)]);
        $r = $this->receiver();
        $claims = self::claims();
        foreach ([['alg' => 'EdDSA', 'kid' => $key['kid']], ['alg' => 'EdDSA', 'typ' => 'JWT', 'kid' => $key['kid']]] as $header) {
            self::assertSame(SetFailureReason::InvalidType, self::reason($r, self::sign($key, $header, $claims)));
        }
        $payload = self::b64((string) json_encode($claims));
        self::assertSame(SetFailureReason::InvalidKey, self::reason($r, self::b64('{"alg":"none","typ":"secevent+jwt"}') . '.' . $payload . '.'));
        $hsInput = self::b64((string) json_encode(['alg' => 'HS256', 'typ' => 'secevent+jwt', 'kid' => $key['kid']])) . '.' . $payload;
        $hs = $hsInput . '.' . self::b64(hash_hmac('sha256', $hsInput, random_bytes(32), true));
        self::assertSame(SetFailureReason::InvalidKey, self::reason($r, $hs));
        self::assertSame(SetFailureReason::InvalidKey, self::reason($r, self::sign($key, ['alg' => 'EdDSA', 'typ' => 'secevent+jwt'], $claims)), 'no kid');
        self::assertSame(SetFailureReason::Malformed, self::reason($r, 'a.b'));
        self::assertSame(SetFailureReason::Malformed, self::reason($r, '!!.@@.##'));
        self::assertSame(SetFailureReason::Malformed, self::reason($r, self::b64('[1]') . '.' . $payload . '.'));
        self::assertSame(SetFailureReason::Malformed, self::reason($r, self::b64('not json') . '.' . $payload . '.'));
        self::assertSame([], $this->routes->requests, 'no step before 4 fetched anything');
    }

    // -- 3 -------------------------------------------------------------------------------

    public function testAnotherKeyOrATamperedPayloadIsInvalidKey(): void
    {
        $key = self::key();
        $rogue = self::key();
        $rogue['kid'] = $key['kid'];
        $this->serveJwks([self::jwk($key)]);
        $r = $this->receiver();
        self::assertSame(SetFailureReason::InvalidKey, self::reason($r, self::signSet($rogue, self::claims())));

        $parts = explode('.', self::signSet($key, self::claims()));
        $parts[1] = self::b64((string) json_encode(array_merge(self::claims(), ['txn' => 'x'])));
        self::assertSame(SetFailureReason::InvalidKey, self::reason($r, implode('.', $parts)));
        $parts[2] = self::b64('short');
        self::assertSame(SetFailureReason::InvalidKey, self::reason($r, implode('.', $parts)));
    }

    // -- 4 -------------------------------------------------------------------------------

    public function testAnotherIssuerOrAudienceIsRefused(): void
    {
        $key = self::key();
        $this->serveJwks([self::jwk($key)]);
        $r = $this->receiver();
        self::assertSame(SetFailureReason::InvalidIssuer, self::reason($r, self::signSet($key, array_merge(self::claims(), ['iss' => 'https://iam.example.test']))));
        self::assertSame(SetFailureReason::InvalidAudience, self::reason($r, self::signSet($key, array_merge(self::claims(), ['aud' => ['https://elsewhere.test']]))));
        self::assertSame(SetFailureReason::InvalidAudience, self::reason($r, self::signSet($key, array_merge(self::claims(), ['aud' => 7]))));
    }

    // -- 5 -------------------------------------------------------------------------------

    public function testExpSubTwoEventsOrNoJtiIsInvalidRequest(): void
    {
        $key = self::key();
        $this->serveJwks([self::jwk($key)]);
        $r = $this->receiver();
        $without = static function (string $member): array {
            $claims = self::claims();
            unset($claims[$member]);

            return $claims;
        };
        foreach ([
            array_merge(self::claims(), ['exp' => 1891500000]),
            array_merge(self::claims(), ['sub' => 'u']),
            array_merge(self::claims(), ['events' => [SsfEventTypes::ACCOUNT_DISABLED => [], SsfEventTypes::ACCOUNT_PURGED => []]]),
            array_merge(self::claims(), ['events' => []]),
            array_merge(self::claims(), ['jti' => '']),
            array_merge(self::claims(), ['iat' => '1791500000']),
            array_merge(self::claims(), ['sub_id' => 'u']),
            $without('jti'),
            $without('iat'),
            $without('sub_id'),
            $without('events'),
        ] as $i => $claims) {
            self::assertSame(SetFailureReason::InvalidRequest, self::reason($r, self::signSet($key, $claims)), 'case ' . $i);
        }
    }

    // -- 6 -------------------------------------------------------------------------------

    public function testAReplayIsRefusedAndAShortWindowIsRefusedAtConfiguration(): void
    {
        $key = self::key();
        $this->serveJwks([self::jwk($key)]);
        $r = $this->receiver();
        $set = self::signSet($key, self::claims());
        $r->verifySet($set);
        self::assertSame(SetFailureReason::Replayed, self::reason($r, $set));

        $client = $this->client();
        foreach ([
            fn () => $client->ssfReceiver(self::ISSUER, self::AUDIENCE, jwksUri: self::BASE_URL . self::JWKS, replayWindowSeconds: 6 * 24 * 3600),
            fn () => $client->ssfReceiver('', self::AUDIENCE, jwksUri: self::BASE_URL . self::JWKS),
            fn () => $client->ssfReceiver(self::ISSUER, '', jwksUri: self::BASE_URL . self::JWKS),
            fn () => $client->ssfReceiver(self::ISSUER, self::AUDIENCE),
            fn () => $client->ssfReceiver(self::ISSUER, self::AUDIENCE, jwksUri: 'https://a', discoveryUrl: 'https://b'),
        ] as $call) {
            try {
                $call();
                self::fail('expected a local ValidationError');
            } catch (ValidationError $e) {
                self::assertStringContainsString('§32.7', $e->getMessage());
            }
        }
    }

    public function testTheMemoryStoreForgetsAfterTheWindow(): void
    {
        $now = 100;
        $store = new InMemoryReplayStore(static function () use (&$now): int {
            return $now;
        });
        self::assertTrue($store->checkAndRecord('a', 60));
        self::assertFalse($store->checkAndRecord('a', 60));
        $now = 161;
        self::assertTrue($store->checkAndRecord('a', 60), 'expired, so new again');
        self::assertTrue((new InMemoryReplayStore())->checkAndRecord('b', 60));
    }

    // -- 7 -------------------------------------------------------------------------------

    public function testAnUnknownKidCostsOneRefetchAndASecondOneNone(): void
    {
        $key = self::key();
        $this->serveJwks([self::jwk($key)]);
        $r = $this->receiver();
        $r->verifySet(self::signSet($key, self::claims()));
        self::assertCount(1, $this->routes->sent('GET', self::JWKS), 'primes the cache');

        self::assertSame(SetFailureReason::InvalidKey, self::reason($r, self::signSet(self::key(), self::claims())));
        self::assertCount(2, $this->routes->sent('GET', self::JWKS), 'exactly one refetch');
        $this->now += 59;
        self::assertSame(SetFailureReason::InvalidKey, self::reason($r, self::signSet(self::key(), self::claims())));
        self::assertCount(2, $this->routes->sent('GET', self::JWKS), 'no refetch within the minute');

        // A key rotated in after the minute is found by the next forced refetch.
        $rotated = self::key();
        $this->serveJwks([self::jwk($key), self::jwk($rotated)]);
        $this->now += 1;
        $r->verifySet(self::signSet($rotated, self::claims()));
        self::assertCount(3, $this->routes->sent('GET', self::JWKS));

        // And the cache expires on its own after the TTL.
        $this->now += SsfReceiver::JWKS_TTL_SECONDS;
        $r->verifySet(self::signSet($key, self::claims()));
        self::assertCount(4, $this->routes->sent('GET', self::JWKS));
    }

    public function testAJwksFailureIsANetworkErrorNotARefusal(): void
    {
        $key = self::key();
        $this->routes->on('GET', self::JWKS, new Response(503), RoutedHandler::json(200, ['nokeys' => true]), new ConnectException('down', new Request('GET', self::JWKS)));
        $r = $this->receiver();
        foreach ([1, 2, 3] as $_) {
            try {
                $r->verifySet(self::signSet($key, self::claims()));
                self::fail('expected a NetworkError');
            } catch (NetworkError) {
            }
        }

        // Keys that are not Ed25519 OKP keys are ignored, not trusted.
        $this->routes->on('GET', self::JWKS, RoutedHandler::json(200, ['keys' => [
            ['kty' => 'RSA', 'kid' => $key['kid'], 'n' => 'x', 'e' => 'AQAB'],
            ['kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => $key['kid'], 'x' => 'short'],
            'garbage',
        ]]));
        self::assertSame(SetFailureReason::InvalidKey, self::reason($this->receiver(), self::signSet($key, self::claims())));

        try {
            $this->client()->ssfReceiver(self::ISSUER, self::AUDIENCE, jwksUri: 'http://iam.example.test/oauth2/jwks')
                ->verifySet(self::signSet($key, self::claims()));
            self::fail('a plaintext JWKS URL is refused');
        } catch (NetworkError $e) {
            self::assertStringContainsString('https', $e->getMessage());
        }
    }

    // -- 8 -------------------------------------------------------------------------------

    public function testPollPassesAckAndSetErrsThroughAndSortsTheAnswer(): void
    {
        $key = self::key();
        $this->serveJwks([self::jwk($key)]);
        $stream = 'stream/1';
        $good = self::claims();
        $bad = array_merge(self::claims(), ['iss' => 'https://impostor.test']);
        $mismatched = self::claims();
        $this->routes->on('POST', '/ssf/v1/poll/stream%2F1', RoutedHandler::json(200, [
            'sets' => [
                $good['jti'] => self::signSet($key, $good),
                $bad['jti'] => self::signSet($key, $bad),
                'another-key' => self::signSet($key, $mismatched),
                'not-a-string' => 7,
            ],
            'moreAvailable' => true,
        ]), RoutedHandler::json(200, ['sets' => new \stdClass(), 'moreAvailable' => false]));

        $token = null;
        $r = $this->receiver(token: $token);
        $result = $r->poll($stream, new SsfPollOptions(
            maxEvents: 10,
            returnImmediately: true,
            ack: ['done-1', 'done-2'],
            setErrs: ['old-1' => SetErr::fromReason(SetFailureReason::InvalidRequest), 'old-2' => new SetErr('invalid_key', 'rotated')],
        ));

        self::assertTrue($result->moreAvailable);
        self::assertCount(1, $result->events);
        self::assertSame($good['jti'], $result->events[0]->jti);
        $refused = [];
        foreach ($result->refused as $r2) {
            $refused[$r2->jti] = $r2->reason;
        }
        self::assertSame([
            $bad['jti'] => SetFailureReason::InvalidIssuer,
            'another-key' => SetFailureReason::InvalidRequest,
            'not-a-string' => SetFailureReason::Malformed,
        ], $refused);

        $sent = $this->routes->sent('POST', '/ssf/v1/poll/stream%2F1');
        self::assertCount(1, $sent);
        self::assertSame(
            '{"maxEvents":10,"returnImmediately":true,"ack":["done-1","done-2"],"setErrs":{"old-1":{"err":"invalid_request"},"old-2":{"err":"invalid_key","description":"rotated"}}}',
            (string) $sent[0]->getBody(),
            'exactly as given, and nothing acknowledged on the caller\'s behalf',
        );
        self::assertTrue($sent[0]->getHeaderLine('Authorization') === 'Bearer ' . $token, 'the provider\'s bearer');
        self::assertSame('', $sent[0]->getHeaderLine('Cookie'));

        // A second poll with no options sends an empty object: still no ack.
        $second = $r->poll($stream);
        self::assertSame('{}', (string) $this->routes->sent('POST', '/ssf/v1/poll/stream%2F1')[1]->getBody());
        self::assertSame([], $second->events);
        self::assertFalse($second->moreAvailable);
    }

    public function testPollIsNotRetriedOn400ButIsOn503(): void
    {
        $this->routes->on('POST', '/ssf/v1/poll/s-1', RoutedHandler::json(400, ['error' => 'push stream']));
        $this->routes->on('POST', '/ssf/v1/poll/s-2', new Response(503), RoutedHandler::json(200, ['sets' => []]));
        $this->routes->on('POST', '/ssf/v1/poll/s-3', RoutedHandler::json(404, ['error' => 'not_found']));
        $r = $this->receiver(retry: true);
        try {
            $r->poll('s-1');
            self::fail('expected a ValidationError');
        } catch (ValidationError) {
        }
        self::assertCount(1, $this->routes->sent('POST', '/ssf/v1/poll/s-1'), 'never retried on a 4xx');
        $r->poll('s-2');
        self::assertCount(2, $this->routes->sent('POST', '/ssf/v1/poll/s-2'), '§16 on a 5xx');
        $this->expectException(NotFoundError::class);
        $r->poll('s-3');
    }

    public function testPollWithoutAProviderIsRefusedLocallyAndAMalformedReplyIsANetworkError(): void
    {
        $r = $this->client()->ssfReceiver(self::ISSUER, self::AUDIENCE, jwksUri: self::BASE_URL . self::JWKS);
        try {
            $r->poll('s');
            self::fail('expected an AuthError');
        } catch (AuthError $e) {
            self::assertNotInstanceOf(SetVerificationError::class, $e);
        }
        self::assertSame([], $this->routes->requests);

        $this->routes->on('POST', '/ssf/v1/poll/s', new Response(200, [], '[]'));
        $this->expectException(NetworkError::class);
        $this->receiver()->poll('s');
    }

    public function testAJwksFailureAbortsThePoll(): void
    {
        $key = self::key();
        $this->routes->on('GET', self::JWKS, new Response(500));
        $claims = self::claims();
        $this->routes->on('POST', '/ssf/v1/poll/s', RoutedHandler::json(200, ['sets' => [$claims['jti'] => self::signSet($key, $claims)]]));
        $this->expectException(NetworkError::class);
        $this->receiver()->poll('s');
    }

    /**
     * §32.8 helper test 8's two-SET batch (contract 1.59, §34.2 P1): the second SET names an
     * unknown `kid` while the refetch fails. Afterwards the first SET's `jti` is not in the
     * store, or the first SET is returned — `poll` never keeps a `jti` it does not return.
     */
    public function testATwoSetBatchWhoseSecondKeyFetchFailsKeepsNoJtiItDoesNotReturn(): void
    {
        $key = self::key();
        $rotated = self::key();
        // The fetch that fills the cache answers; the one refetch the unknown kid triggers fails.
        $this->routes->on('GET', self::JWKS, RoutedHandler::json(200, ['keys' => [self::jwk($key)]]), new Response(500));
        $first = self::claims();
        $second = self::claims();
        $this->routes->on('POST', '/ssf/v1/poll/s', RoutedHandler::json(200, ['sets' => [
            $first['jti'] => self::signSet($key, $first),
            $second['jti'] => self::signSet($rotated, $second),
        ]]));
        $store = new InMemoryReplayStore(fn (): int => $this->now);
        $r = $this->receiverWithStore($store);

        $result = null;
        try {
            $result = $r->poll('s');
        } catch (NetworkError) {
            // Raising is conformant only if nothing was kept.
        }
        $returned = $result !== null && in_array($first['jti'], array_map(static fn ($e) => $e->jti, $result->events), true);
        $recorded = !$store->checkAndRecord($first['jti'], SsfReceiver::MIN_REPLAY_WINDOW_SECONDS);
        self::assertTrue(
            $returned || !$recorded,
            'the first SET\'s jti is recorded but the first SET was not returned: a re-offer would read replayed and the event is lost',
        );

        // This SDK takes P1's second form: what was judged is returned, the unjudged SET is
        // listed and left unrecorded, so the transmitter offers it again.
        self::assertNotNull($result);
        self::assertSame([$first['jti']], array_map(static fn ($e) => $e->jti, $result->events));
        self::assertSame([], $result->refused, 'an unjudged SET is not refused');
        self::assertSame([$second['jti']], $result->unjudged);
        self::assertInstanceOf(NetworkError::class, $result->unjudgedCause);
        self::assertTrue($store->checkAndRecord($second['jti'], SsfReceiver::MIN_REPLAY_WINDOW_SECONDS), 'the unjudged jti was not recorded');
    }

    /** A replay store that cannot answer is no verdict either (§34.2 P1, P3, P4). */
    public function testAStoreThatCannotAnswerMidBatchLeavesTheRestUnjudged(): void
    {
        $key = self::key();
        $this->serveJwks([self::jwk($key)]);
        $first = self::claims();
        $second = self::claims();
        $third = self::claims();
        $this->routes->on('POST', '/ssf/v1/poll/s', RoutedHandler::json(200, ['sets' => [
            $first['jti'] => self::signSet($key, $first),
            $second['jti'] => self::signSet($key, $second),
            $third['jti'] => self::signSet($key, $third),
        ]]));
        $store = new class () implements \Axiam\Sdk\Ssf\ReplayStore {
            /** @var list<string> */
            public array $recorded = [];

            public function checkAndRecord(string $jti, int $windowSeconds): bool
            {
                if ($this->recorded !== []) {
                    throw new \RuntimeException('store unavailable');
                }
                $this->recorded[] = $jti;

                return true;
            }
        };
        $result = $this->receiverWithStore($store)->poll('s');
        self::assertSame([$first['jti']], array_map(static fn ($e) => $e->jti, $result->events));
        self::assertSame([$first['jti']], $store->recorded, 'every recorded jti is returned');
        self::assertSame([$second['jti'], $third['jti']], $result->unjudged);
        self::assertInstanceOf(\RuntimeException::class, $result->unjudgedCause);
        self::assertSame([], $result->refused);

        // A store that fails on the very first SET: nothing was kept, so the failure is raised.
        $failing = new class () implements \Axiam\Sdk\Ssf\ReplayStore {
            public function checkAndRecord(string $jti, int $windowSeconds): bool
            {
                throw new \RuntimeException('store unavailable');
            }
        };
        $this->expectException(\RuntimeException::class);
        $this->receiverWithStore($failing)->poll('s');
    }

    /**
     * §32.8 test 6, the store-failure case (contract 1.60, §34.2 P4 / B1 *verify*): a store that
     * cannot answer gives NO verdict. `verifySet()` raises the store's own failure — never a
     * {@see SetVerificationError}, so never `replayed` and never carrying a reason code — and the
     * SET is not recorded. The PHP interface answers `bool` but is fallible through an exception,
     * so B1's "bare bool" defect does not apply; this pins that an exception is never read as
     * "already seen", whatever it is (a `\Exception`, an SDK error, or a PHP `\Error`).
     *
     * @dataProvider unanswerableStoreFailures
     */
    public function testAStoreThatCannotAnswerGivesNoVerdictOnVerifySet(\Throwable $failure): void
    {
        $key = self::key();
        $this->serveJwks([self::jwk($key)]);
        $store = new class ($failure) implements \Axiam\Sdk\Ssf\ReplayStore {
            public int $asked = 0;

            public function __construct(private readonly \Throwable $failure)
            {
            }

            public function checkAndRecord(string $jti, int $windowSeconds): bool
            {
                ++$this->asked;
                throw $this->failure;
            }
        };
        $set = self::signSet($key, self::claims());
        $receiver = $this->receiverWithStore($store);
        try {
            $receiver->verifySet($set);
            self::fail('a store that cannot answer must raise, not accept the SET');
        } catch (SetVerificationError $e) {
            self::fail('a store that cannot answer is never read as ' . $e->failureReason->value);
        } catch (\Throwable $e) {
            self::assertSame($failure, $e, 'the store\'s own failure, with no reason code');
        }
        self::assertSame(1, $store->asked);

        // Still no verdict when the very same SET is offered again: nothing was recorded.
        try {
            $receiver->verifySet($set);
            self::fail('expected the store failure again');
        } catch (SetVerificationError $e) {
            self::fail('the failed SET read as ' . $e->failureReason->value . ' on a second look');
        } catch (\Throwable) {
        }
        self::assertSame(2, $store->asked, 'asked again, not remembered as replayed');
    }

    /** @return iterable<string,array{\Throwable}> */
    public static function unanswerableStoreFailures(): iterable
    {
        yield 'a runtime failure' => [new \RuntimeException('redis: connection refused')];
        yield 'an SDK network error' => [NetworkError::fromMessage('store timed out')];
        yield 'a PHP error' => [new \TypeError('store returned garbage')];
    }

    /**
     * §32.8 test 6's `poll` half (§34.2 P4): the SET whose store cannot answer is in neither
     * `events` nor `refused`, its `jti` is not recorded, and no `ack` leaves the receiver on its
     * own. Mid-batch it is listed `unjudged`; as the first SET it is raised, having kept nothing.
     */
    public function testAStoreThatCannotAnswerLeavesThePolledSetInNeitherEventsNorRefused(): void
    {
        $key = self::key();
        $this->serveJwks([self::jwk($key)]);
        $ok = self::claims();
        $unanswerable = self::claims();
        $this->routes->on('POST', '/ssf/v1/poll/s', RoutedHandler::json(200, ['sets' => [
            $ok['jti'] => self::signSet($key, $ok),
            $unanswerable['jti'] => self::signSet($key, $unanswerable),
        ]]));
        $store = new class ($unanswerable['jti']) implements \Axiam\Sdk\Ssf\ReplayStore {
            /** @var list<string> */
            public array $recorded = [];

            public function __construct(private readonly string $failsFor)
            {
            }

            public function checkAndRecord(string $jti, int $windowSeconds): bool
            {
                if ($jti === $this->failsFor) {
                    throw new \RuntimeException('store unavailable');
                }
                $this->recorded[] = $jti;

                return true;
            }
        };
        $result = $this->receiverWithStore($store)->poll('s');
        self::assertSame([$ok['jti']], array_map(static fn ($e) => $e->jti, $result->events));
        self::assertSame([], $result->refused, 'not refused, and in particular not replayed');
        self::assertSame([$unanswerable['jti']], $result->unjudged);
        self::assertSame([$ok['jti']], $store->recorded, 'the unanswerable jti was not recorded');
        $sent = $this->routes->sent('POST', '/ssf/v1/poll/s');
        self::assertCount(1, $sent);
        self::assertSame('{}', (string) $sent[0]->getBody(), 'nothing acknowledged on the caller\'s behalf');

        // The first SET of a batch: nothing had been kept, so the failure is raised and the
        // SET is in neither list.
        $only = self::claims();
        $this->routes->on('POST', '/ssf/v1/poll/only', RoutedHandler::json(200, ['sets' => [
            $only['jti'] => self::signSet($key, $only),
        ]]));
        $failing = new class () implements \Axiam\Sdk\Ssf\ReplayStore {
            public function checkAndRecord(string $jti, int $windowSeconds): bool
            {
                throw new \RuntimeException('store unavailable');
            }
        };
        try {
            $this->receiverWithStore($failing)->poll('only');
            self::fail('expected the store failure to be raised');
        } catch (SetVerificationError $e) {
            self::fail('read as ' . $e->failureReason->value);
        } catch (\RuntimeException $e) {
            self::assertSame('store unavailable', $e->getMessage());
        }
    }

    /**
     * A7 (R-2, §34.2 P2): a `replayed` SET on a later poll is acknowledged in `ack`, not
     * reported in `setErrs`. Drives the README's poll loop verbatim: the re-offered SET comes
     * back refused `replayed`, the loop puts it in `ack`, and the next request carries no
     * `setErrs` entry for it. The docblock and the README example say so too.
     */
    public function testAReplayedSetIsAcknowledgedAndNeverReportedInSetErrs(): void
    {
        $key = self::key();
        $this->serveJwks([self::jwk($key)]);
        $claims = self::claims();
        $other = array_merge(self::claims(), ['iss' => 'https://impostor.test']);
        $set = self::signSet($key, $claims);
        $this->routes->on(
            'POST',
            '/ssf/v1/poll/s',
            RoutedHandler::json(200, ['sets' => [$claims['jti'] => $set]]),
            // Re-offered because the caller never acknowledged it, plus one genuinely bad SET.
            RoutedHandler::json(200, ['sets' => [$claims['jti'] => $set, $other['jti'] => self::signSet($key, $other)]]),
            RoutedHandler::json(200, ['sets' => new \stdClass()]),
        );
        $receiver = $this->receiverWithStore(new InMemoryReplayStore(fn (): int => $this->now));

        $first = $receiver->poll('s');
        self::assertSame([$claims['jti']], array_map(static fn ($e) => $e->jti, $first->events));

        $result = $receiver->poll('s');
        self::assertSame([], $result->events);

        // The README's loop.
        $ack = array_map(static fn ($e) => $e->jti, $result->events);
        $setErrs = [];
        foreach ($result->refused as $refused) {
            if ($refused->reason === SetFailureReason::Replayed) {
                $ack[] = $refused->jti;
                continue;
            }
            $setErrs[$refused->jti] = SetErr::fromReason($refused->reason);
        }
        self::assertSame([$claims['jti']], $ack, 'the replayed SET is acknowledged');
        self::assertSame([$other['jti']], array_keys($setErrs), 'only the genuinely bad SET is reported');
        self::assertSame('invalid_issuer', $setErrs[$other['jti']]->err);

        $receiver->poll('s', new SsfPollOptions(ack: $ack, setErrs: $setErrs));
        $sent = $this->routes->sent('POST', '/ssf/v1/poll/s');
        self::assertCount(3, $sent);
        $body = json_decode((string) $sent[2]->getBody(), true);
        self::assertSame([$claims['jti']], $body['ack']);
        self::assertArrayNotHasKey($claims['jti'], $body['setErrs']);
        self::assertSame(['err' => 'invalid_issuer'], $body['setErrs'][$other['jti']]);

        // Documentation: the poll() docblock and the README example say the same.
        $doc = (string) (new \ReflectionMethod(SsfReceiver::class, 'poll'))->getDocComment();
        self::assertMatchesRegularExpression('/`replayed`[^`]*one, which you acknowledge in\s+\*\s+`ack`/', $doc);
        $readme = (string) file_get_contents(\dirname(__DIR__, 2) . '/README.md');
        self::assertStringContainsString('if ($refused->reason === SetFailureReason::Replayed) {', $readme);
        self::assertStringContainsString('$ack[] = $refused->jti;', $readme);
        self::assertStringContainsString('**not** in `setErrs`', $readme);
    }

    /**
     * R-33: the receiver verifies Ed25519 through ext-sodium, so `composer.json` declares it
     * and, where it is absent anyway, `verifySet` fails with a typed SDK error — never PHP's
     * "Call to undefined function", and never a SET refusal (it is no verdict on the SET).
     */
    public function testTheReceiverDeclaresExtSodiumAndFailsTypedWithoutIt(): void
    {
        $raw = file_get_contents(\dirname(__DIR__, 2) . '/composer.json');
        self::assertIsString($raw);
        /** @var array{require?: array<string,string>} $manifest */
        $manifest = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        self::assertArrayHasKey('ext-sodium', $manifest['require'] ?? [], 'composer.json require declares ext-sodium');

        // A child PHP with the verification primitive disabled stands in for a build without
        // ext-sodium; the key, the JWKS and the SET are made at run time inside it.
        $autoload = \dirname(__DIR__, 2) . '/vendor/autoload.php';
        $script = tempnam(sys_get_temp_dir(), 'ssf-sodium-');
        self::assertIsString($script);
        file_put_contents($script, '<?php
require ' . var_export($autoload, true) . ';
$b64 = static fn (string $r): string => rtrim(strtr(base64_encode($r), "+/", "-_"), "=");
$pair = sodium_crypto_sign_keypair();
$kid = "k-" . bin2hex(random_bytes(4));
$jwks = ["keys" => [["kty" => "OKP", "crv" => "Ed25519", "kid" => $kid, "x" => $b64(sodium_crypto_sign_publickey($pair))]]];
$http = new GuzzleHttp\Client(["handler" => GuzzleHttp\HandlerStack::create(new GuzzleHttp\Handler\MockHandler([
    new GuzzleHttp\Psr7\Response(200, [], (string) json_encode($jwks)),
]))]);
$claims = ["iss" => "https://iam.example.test", "aud" => "https://rp.example.test", "iat" => 1, "jti" => bin2hex(random_bytes(8)),
    "sub_id" => ["format" => "opaque", "id" => "x"], "events" => ["urn:example" => new stdClass()]];
$input = $b64((string) json_encode(["alg" => "EdDSA", "typ" => "secevent+jwt", "kid" => $kid])) . "." . $b64((string) json_encode($claims));
$set = $input . "." . $b64(sodium_crypto_sign_detached($input, sodium_crypto_sign_secretkey($pair)));
$r = new Axiam\Sdk\Ssf\SsfReceiver($http, "https://iam.example.test", "https://iam.example.test", "https://rp.example.test", jwksUri: "https://iam.example.test/jwks");
try {
    $r->verifySet($set);
    echo "verified";
} catch (Throwable $e) {
    echo get_class($e), "|", $e->getMessage();
}
');
        $output = [];
        exec(escapeshellarg(PHP_BINARY) . ' -d disable_functions=sodium_crypto_sign_verify_detached ' . escapeshellarg($script) . ' 2>&1', $output);
        unlink($script);
        $line = implode("\n", $output);
        self::assertStringStartsWith(\Axiam\Sdk\Core\AxiamException::class . '|', $line, 'a typed SDK error, not a PHP Error: ' . $line);
        self::assertStringContainsString('ext-sodium', $line);
    }

    private function receiverWithStore(\Axiam\Sdk\Ssf\ReplayStore $store): SsfReceiver
    {
        $bearer = 'cc-' . bin2hex(random_bytes(16));

        return new SsfReceiver(
            http: new \GuzzleHttp\Client(['handler' => \GuzzleHttp\HandlerStack::create($this->routes)]),
            baseUrl: self::BASE_URL,
            issuer: self::ISSUER,
            audience: self::AUDIENCE,
            jwksUri: self::BASE_URL . self::JWKS,
            accessTokenProvider: static fn (): Sensitive => new Sensitive($bearer),
            replayStore: $store,
            clock: fn (): int => $this->now,
        );
    }

    public function testDiscoverySuppliesTheJwksUriAndMustNameTheIssuer(): void
    {
        $key = self::key();
        $this->serveJwks([self::jwk($key)]);
        $this->routes->on('GET', '/.well-known/ssf-configuration', RoutedHandler::json(200, [
            'issuer' => self::ISSUER, 'jwks_uri' => self::BASE_URL . self::JWKS,
        ]));
        $client = $this->client();
        $discovery = self::BASE_URL . '/.well-known/ssf-configuration';
        $r = $client->ssfReceiver(self::ISSUER, self::AUDIENCE, discoveryUrl: $discovery);
        $r->verifySet(self::signSet($key, self::claims()));
        $r->verifySet(self::signSet($key, self::claims()));
        self::assertCount(1, $this->routes->sent('GET', '/.well-known/ssf-configuration'), 'read once');

        foreach ([
            RoutedHandler::json(200, ['issuer' => 'https://someone-else.test', 'jwks_uri' => self::BASE_URL . self::JWKS]),
            RoutedHandler::json(200, ['issuer' => self::ISSUER]),
            new Response(404),
        ] as $answer) {
            $this->routes->on('GET', '/.well-known/ssf-configuration', $answer);
            try {
                $client->ssfReceiver(self::ISSUER, self::AUDIENCE, discoveryUrl: $discovery)->verifySet(self::signSet($key, self::claims()));
                self::fail('expected a NetworkError');
            } catch (NetworkError) {
            } catch (AuthError $e) {
                self::assertNotInstanceOf(SetVerificationError::class, $e, 'never a SET refusal');
            }
        }
    }

    public function testPushErrorCodesAreRfc8935Codes(): void
    {
        foreach ([
            [SetFailureReason::Malformed, 'invalid_request'],
            [SetFailureReason::InvalidType, 'invalid_request'],
            [SetFailureReason::Replayed, 'invalid_request'],
            [SetFailureReason::InvalidKey, 'invalid_key'],
            [SetFailureReason::InvalidIssuer, 'invalid_issuer'],
            [SetFailureReason::InvalidAudience, 'invalid_audience'],
            [SetFailureReason::InvalidRequest, 'invalid_request'],
        ] as [$reason, $code]) {
            self::assertSame($code, $reason->pushErrorCode());
            self::assertSame(['err' => $code], SetErr::fromReason($reason)->toArray());
        }
        self::assertSame('{"setErrs":{}}', (string) json_encode((object) (new SsfPollOptions(setErrs: []))->toArray()));
    }

    public function testTheProviderTokenReachesNoRenderingOfTheReceiver(): void
    {
        $token = null;
        $r = $this->receiver(token: $token);
        self::assertIsString($token);
        ob_start();
        var_dump($r);
        self::assertNoFragment(print_r($r, true) . (string) ob_get_clean(), $token);
        self::assertStringContainsString('[provider]', print_r($r, true));
    }

    /** The test transport's own requests are never redirected — the option is set. */
    public function testPollFollowsNoRedirect(): void
    {
        $this->routes->on('POST', '/ssf/v1/poll/s', static fn (RequestInterface $r): Response => new Response(307, ['Location' => 'https://elsewhere.test/']));
        try {
            $this->receiver()->poll('s');
            self::fail('a 307 is not an answer');
        } catch (NetworkError) {
        }
        self::assertCount(1, $this->routes->requests);
    }
}
