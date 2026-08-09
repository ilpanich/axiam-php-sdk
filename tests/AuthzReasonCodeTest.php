<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Rest\AccessDecision;
use Axiam\Sdk\Rest\AuthzRestClient;
use Axiam\Sdk\Rest\ReasonCode;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * Decision reason codes — CONTRACT.md §11 rule 9 (B1 deny-override).
 *
 * The rule exists because the two refusals mean **opposite things to the person on the
 * other end**: `no_grant` says *ask an admin for access*, `denied_by_rule` says *an admin
 * has already decided*. An application that cannot tell them apart sends users to raise
 * tickets that will be refused.
 */
final class AuthzReasonCodeTest extends TestCase
{
    /** @param array<int,Response> $queue */
    private function client(array $queue): AuthzRestClient
    {
        return new AuthzRestClient(new Client([
            'base_uri' => 'https://api.test',
            'handler' => HandlerStack::create(new MockHandler($queue)),
        ]));
    }

    private function check(string $json): AccessDecision
    {
        return $this->client([new Response(200, [], $json)])
            ->checkAccessDecision('users:get', 'r-1');
    }

    public function testAnAllowSurfacesTheAllowedReasonCode(): void
    {
        $decision = $this->check('{"allowed":true,"reason_code":"allowed"}');

        self::assertTrue($decision->allowed);
        self::assertSame(ReasonCode::ALLOWED, $decision->reasonCode);
    }

    public function testNoGrantAndDeniedByRuleAreNotCollapsed(): void
    {
        $noGrant = $this->check('{"allowed":false,"reason_code":"no_grant"}');
        $byRule = $this->check('{"allowed":false,"reason_code":"denied_by_rule"}');

        // Both are refusals…
        self::assertFalse($noGrant->allowed);
        self::assertFalse($byRule->allowed);
        // …and the SDK must not reduce them to that shared false.
        self::assertSame(ReasonCode::NO_GRANT, $noGrant->reasonCode);
        self::assertSame(ReasonCode::DENIED_BY_RULE, $byRule->reasonCode);
        self::assertNotSame($noGrant->reasonCode, $byRule->reasonCode);
    }

    public function testAnUnknownReasonCodeIsSurfacedVerbatimAndChangesNothing(): void
    {
        // §11 rule 9: an SDK that does not recognise a code MUST surface it unchanged and
        // MUST NOT let it affect the outcome, which `allowed` carries alone. This is what
        // lets the server add a fourth code without breaking every deployed SDK.
        $denied = $this->check('{"allowed":false,"reason_code":"denied_by_some_future_thing"}');
        self::assertFalse($denied->allowed);
        self::assertSame('denied_by_some_future_thing', $denied->reasonCode);

        $allowed = $this->check('{"allowed":true,"reason_code":"something-unrecognised"}');
        self::assertTrue($allowed->allowed, 'an unknown code must not flip an allow');
    }

    public function testAnOlderServerOmittingTheFieldIsNotAnError(): void
    {
        // A newer SDK against an older server: the field is simply absent, and that MUST
        // degrade to today's behaviour rather than failing to parse.
        $denied = $this->check('{"allowed":false}');
        self::assertFalse($denied->allowed);
        self::assertNull($denied->reasonCode);

        $allowed = $this->check('{"allowed":true,"reason":"role grants it"}');
        self::assertTrue($allowed->allowed);
        self::assertNull($allowed->reasonCode);
        self::assertSame('role grants it', $allowed->reason);
    }

    /**
     * @return iterable<string,array{0:string}>
     */
    public static function refusalProvider(): iterable
    {
        yield 'no_grant' => [ReasonCode::NO_GRANT];
        yield 'denied_by_rule' => [ReasonCode::DENIED_BY_RULE];
    }

    /** @dataProvider refusalProvider */
    public function testCheckAccessStillReturnsFalseForBothRefusals(string $code): void
    {
        // §11 rule 9 is about REPORTING, not enforcement: the bool-returning methods
        // answer false identically for either refusal, and an SDK must not start varying
        // enforcement on the code.
        $json = sprintf('{"allowed":false,"reason_code":"%s"}', $code);

        self::assertFalse($this->client([new Response(200, [], $json)])->checkAccess('users:get', 'r-1'));
        self::assertFalse($this->client([new Response(200, [], $json)])->can('users:get', 'r-1'));
    }

    public function testBatchCheckDecisionsSurfacesAReasonCodePerDecision(): void
    {
        $client = $this->client([new Response(200, [], (string) json_encode([
            'results' => [
                ['allowed' => true, 'reason_code' => 'allowed'],
                ['allowed' => false, 'reason_code' => 'no_grant'],
                ['allowed' => false, 'reason_code' => 'denied_by_rule'],
            ],
        ]))]);

        $decisions = $client->batchCheckDecisions([
            ['action' => 'users:get', 'resource_id' => 'r-1'],
            ['action' => 'users:update', 'resource_id' => 'r-1'],
            ['action' => 'users:delete', 'resource_id' => 'r-1'],
        ]);

        self::assertSame(
            [ReasonCode::ALLOWED, ReasonCode::NO_GRANT, ReasonCode::DENIED_BY_RULE],
            array_map(static fn (AccessDecision $d): ?string => $d->reasonCode, $decisions),
        );
    }
}
