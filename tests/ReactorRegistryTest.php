<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Reactor\ReactorEvents;
use PHPUnit\Framework\TestCase;

/**
 * CONTRACT.md §22.5 (the event registry and its mutable-field allow-lists),
 * §22.7 (the hot-path exclusion, a normative MUST NOT), §22.8 (strictest-wins
 * failure-policy composition) and §22.1 (a reactor never declares topology).
 */
final class ReactorRegistryTest extends TestCase
{
    /** The five interceptable events in contract v1, and nothing else. */
    public function testRegistryShape(): void
    {
        $names = array_map(static fn ($spec): string => $spec->name, ReactorEvents::all());

        self::assertSame([
            ReactorEvents::TOKEN_PRE_ISSUE,
            ReactorEvents::LOGIN_POST_AUTH,
            ReactorEvents::USER_PRE_CREATE,
            ReactorEvents::USER_PRE_UPDATE,
            ReactorEvents::GRANT_PRE_ASSIGN,
        ], $names);

        foreach (ReactorEvents::all() as $spec) {
            self::assertTrue($spec->interceptable, $spec->name);
            self::assertNotSame('', $spec->description, $spec->name);
            self::assertSame($spec, $spec, $spec->name);
        }

        self::assertNull(ReactorEvents::specFor('nope.not_an_event'));
        self::assertSame(ReactorEvents::TOKEN_PRE_ISSUE, ReactorEvents::specFor(ReactorEvents::TOKEN_PRE_ISSUE)?->name);
    }

    /**
     * §22.8's per-event defaults and budget constants, pinned against the
     * contract's own table.
     */
    public function testPerEventDefaultsAndBudget(): void
    {
        self::assertSame(ReactorEvents::FAIL_OPEN, ReactorEvents::specFor(ReactorEvents::TOKEN_PRE_ISSUE)?->defaultFailurePolicy);
        foreach ([
            ReactorEvents::LOGIN_POST_AUTH,
            ReactorEvents::USER_PRE_CREATE,
            ReactorEvents::USER_PRE_UPDATE,
            ReactorEvents::GRANT_PRE_ASSIGN,
        ] as $name) {
            self::assertSame(ReactorEvents::FAIL_CLOSED, ReactorEvents::specFor($name)?->defaultFailurePolicy, $name);
        }

        self::assertSame(500, ReactorEvents::DEFAULT_TIMEOUT_MS);
        self::assertSame(1, ReactorEvents::MIN_TIMEOUT_MS);
        self::assertSame(5000, ReactorEvents::MAX_TIMEOUT_MS);
        self::assertSame(5000, ReactorEvents::CHAIN_CEILING_MS);
    }

    /**
     * §22.8: a registration naming no `failure_policy` gets `fail_closed` if ANY
     * of its events defaults closed, and `fail_open` only when all of them default
     * open — **in either array order**.
     *
     * An SDK MUST NOT reimplement this as "take the first event's default": that
     * lets the order of a JSON array decide whether an unreachable fraud check
     * passes.
     */
    public function testStrictestWinsInEitherOrder(): void
    {
        self::assertSame(
            ReactorEvents::FAIL_OPEN,
            ReactorEvents::defaultFailurePolicy([ReactorEvents::TOKEN_PRE_ISSUE]),
        );

        $mixed = [ReactorEvents::TOKEN_PRE_ISSUE, ReactorEvents::LOGIN_POST_AUTH];
        self::assertSame(ReactorEvents::FAIL_CLOSED, ReactorEvents::defaultFailurePolicy($mixed));
        self::assertSame(ReactorEvents::FAIL_CLOSED, ReactorEvents::defaultFailurePolicy(array_reverse($mixed)));

        // An unknown name and an empty list are both fail_closed: the server will
        // refuse the registration outright, and guessing open on a name this SDK
        // does not recognise is the wrong way to be wrong.
        self::assertSame(ReactorEvents::FAIL_CLOSED, ReactorEvents::defaultFailurePolicy([]));
        self::assertSame(
            ReactorEvents::FAIL_CLOSED,
            ReactorEvents::defaultFailurePolicy([ReactorEvents::TOKEN_PRE_ISSUE, 'nope.not_an_event']),
        );
    }

    /**
     * §22.13's registry assertions, verbatim: the namespace-prefix rule and the
     * standard claims it keeps out of reach.
     *
     * @dataProvider patchFieldProvider
     */
    public function testPatchFieldAllowList(string $event, string $field, bool $allowed): void
    {
        $spec = ReactorEvents::specFor($event);
        self::assertNotNull($spec);
        self::assertSame($allowed, $spec->patchFieldAllowed($field), "$event / $field");
    }

    /** @return array<string, array{string, string, bool}> */
    public static function patchFieldProvider(): array
    {
        $cases = [];

        foreach (['ext.department' => true, 'ext.a.b.c' => true, 'ext.' => false, 'ext' => false,
            'extra' => false, 'external_id' => false, 'evil.ext.department' => false] as $field => $allowed) {
            $cases["token.pre_issue $field"] = [ReactorEvents::TOKEN_PRE_ISSUE, (string) $field, $allowed];
        }

        // Not one standard claim begins with `ext.`, so not one is reachable. A
        // hook that can rewrite `sub` is a hook that can mint a token for anyone.
        foreach (['iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti', 'scope', 'scp', 'azp', 'act', 'client_id'] as $claim) {
            $cases["token.pre_issue claim $claim"] = [ReactorEvents::TOKEN_PRE_ISSUE, $claim, false];
        }

        foreach (['email' => true, 'username' => true, 'metadata.source' => true, 'metadata' => false,
            'password' => false, 'password_hash' => false, 'tenant_id' => false, 'id' => false,
            'roles' => false, 'is_admin' => false] as $field => $allowed) {
            $cases["user.pre_create $field"] = [ReactorEvents::USER_PRE_CREATE, (string) $field, $allowed];
            $cases["user.pre_update $field"] = [ReactorEvents::USER_PRE_UPDATE, (string) $field, $allowed];
        }

        // The veto-only events accept no patch field at all.
        foreach ([ReactorEvents::LOGIN_POST_AUTH, ReactorEvents::GRANT_PRE_ASSIGN] as $event) {
            foreach (['ext.department', 'email', 'anything', 'role'] as $field) {
                $cases["$event $field"] = [$event, $field, false];
            }
        }

        return $cases;
    }

    /**
     * §22.7's MUST NOT, asserted on the enum/list and on the source rather than on
     * a comment.
     *
     * The three hot-path decision operations are not hookable and no SDK may
     * present them as such: a reactor round-trip is milliseconds and the check
     * path's budget is microseconds. This test file is the ONE place under this
     * repository's reactor surface that names them, and it names them in order to
     * ban them everywhere else — including in a documentation example, which a
     * registry lookup alone would never catch.
     *
     * An application that needs external input on an authorization decision writes
     * a deny grant, which the engine evaluates in the hot path at hot-path cost.
     */
    public function testHotPathExclusion(): void
    {
        $excluded = ['authz.check', 'authz.check_batch', 'token.introspect'];

        foreach ($excluded as $name) {
            self::assertNull(ReactorEvents::specFor($name), "$name MUST NOT be in the reactor event registry");
            foreach (ReactorEvents::all() as $spec) {
                self::assertNotSame($name, $spec->name, "$name MUST NOT appear in ReactorEvents::all()");
            }
        }

        foreach (self::reactorSurfaceFiles() as $file) {
            $source = file_get_contents($file);
            self::assertIsString($source);
            foreach ($excluded as $name) {
                self::assertStringNotContainsString(
                    $name,
                    $source,
                    "$file names the non-hookable operation $name (§22.7)",
                );
            }
        }
    }

    /**
     * §22.13's "the runtime declares no exchange, queue or binding", asserted two
     * ways because either alone is weak.
     *
     * Structurally: {@see \Axiam\Sdk\Reactor\ReactorTransport} carries no declare
     * or bind method, so there is no seam through which the runtime could ask for
     * one. Textually: no reactor source file names `php-amqplib`'s declare/bind
     * calls, which is what catches somebody reaching around the interface to the
     * concrete channel.
     */
    public function testRuntimeDeclaresNoTopology(): void
    {
        $reflection = new \ReflectionClass(\Axiam\Sdk\Reactor\ReactorTransport::class);
        $methods = array_map(static fn ($m): string => $m->getName(), $reflection->getMethods());
        sort($methods);
        self::assertSame(['close', 'consume', 'publishReply', 'wait'], $methods);

        $banned = ['exchange_declare', 'queue_declare', 'queue_bind', 'exchange_bind'];
        foreach (self::reactorSurfaceFiles() as $file) {
            $source = file_get_contents($file);
            self::assertIsString($source);
            foreach ($banned as $call) {
                self::assertStringNotContainsString($call, $source, "$file reaches for $call (§22.1)");
            }
        }
    }

    /**
     * Every file the §22.7 and §22.1 source scans police: the reactor package plus
     * its shipped example, which §22.7 bars from naming a hot-path operation just
     * as firmly as a constant list does.
     *
     * @return list<string>
     */
    private static function reactorSurfaceFiles(): array
    {
        $files = array_merge(
            glob(__DIR__ . '/../src/Reactor/*.php') ?: [],
            glob(__DIR__ . '/../examples/reactor/*.php') ?: [],
        );
        self::assertNotEmpty($files);
        sort($files);

        return $files;
    }
}
