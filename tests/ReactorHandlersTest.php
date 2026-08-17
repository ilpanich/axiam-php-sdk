<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Attributes\OnReactorEvent;
use Axiam\Sdk\Reactor\ReactorAnswer;
use Axiam\Sdk\Reactor\ReactorEvent;
use Axiam\Sdk\Reactor\ReactorEvents;
use Axiam\Sdk\Reactor\ReactorHandlers;
use Axiam\Sdk\Reactor\ReactorRejection;
use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * A class-based reactor, the shape §22.14 exists to make writable.
 */
final class HandlersFixtureReactor
{
    public function __construct(private readonly string $team = 'platform')
    {
    }

    #[OnReactorEvent(ReactorEvents::TOKEN_PRE_ISSUE)]
    public function enrich(ReactorEvent $event): ReactorAnswer
    {
        return ReactorAnswer::mutate(['ext.team' => $this->team]);
    }

    #[OnReactorEvent(ReactorEvents::LOGIN_POST_AUTH)]
    public function screen(ReactorEvent $event): ReactorAnswer
    {
        return ReactorAnswer::deny('embargoed region');
    }

    /** Not marked — must not be collected. */
    public function helper(ReactorEvent $event): ReactorAnswer
    {
        return ReactorAnswer::allow();
    }
}

/**
 * CONTRACT.md §22.14 — declarative reactor handler binding.
 *
 * Six groups for six rules. None needs a broker: ReactorHandlers is pure
 * composition over the callable ReactorServer already takes, so what is under
 * test is the binding table and the one answer it gives for an event nobody
 * bound.
 */
final class ReactorHandlersTest extends TestCase
{
    private static function event(string $name): ReactorEvent
    {
        return new ReactorEvent(
            tenantId: '11111111-1111-1111-1111-111111111111',
            event: $name,
            correlationId: 'c-1',
            payload: [],
            timeoutMs: 500,
            nonce: 'n-1',
            issuedAt: 0,
            deadline: 0.0,
        );
    }

    // -- rule 1: it composes, it does not replace ---------------------------

    public function testCollectsMarkedMethodsAndDispatchesEachToItsOwn(): void
    {
        $handler = ReactorHandlers::of(new HandlersFixtureReactor())->handler();

        $enriched = $handler(self::event(ReactorEvents::TOKEN_PRE_ISSUE));
        self::assertSame(ReactorAnswer::MUTATE, $enriched->decision());
        // The bound method kept its instance, so constructor state survives.
        self::assertSame(['ext.team' => 'platform'], $enriched->patch());

        $screened = $handler(self::event(ReactorEvents::LOGIN_POST_AUTH));
        self::assertSame(ReactorAnswer::DENY, $screened->decision());
    }

    public function testIgnoresUnmarkedMethods(): void
    {
        $handlers = ReactorHandlers::of(new HandlersFixtureReactor());

        self::assertSame(
            [ReactorEvents::TOKEN_PRE_ISSUE, ReactorEvents::LOGIN_POST_AUTH],
            $handlers->events(),
        );
    }

    public function testBindAcceptsAClosure(): void
    {
        $handler = (new ReactorHandlers())
            ->bind(ReactorEvents::USER_PRE_CREATE, static fn (ReactorEvent $e): ReactorAnswer => ReactorAnswer::allow())
            ->handler();

        self::assertSame(ReactorAnswer::ALLOW, $handler(self::event(ReactorEvents::USER_PRE_CREATE))->decision());
    }

    // -- rule 2: an unregistered name is refused at bind time ---------------

    public function testRejectsAMisspelledEventName(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/not a hookable reactor event/');

        (new ReactorHandlers())->bind('token.pre_isue', static fn (ReactorEvent $e): ReactorAnswer => ReactorAnswer::allow());
    }

    /**
     * §22.7's three are in no registry row, so rule 2 refuses them as unknown
     * names. Asserted on behaviour rather than on a comment; this is a test
     * file, which the §22.7 source scan over src/Reactor/ and examples/reactor/
     * does not police.
     */
    public function testRejectsTheHotPathOperations(): void
    {
        foreach (['authz.check', 'authz.check_batch', 'token.introspect'] as $excluded) {
            try {
                (new ReactorHandlers())->bind($excluded, static fn (ReactorEvent $e): ReactorAnswer => ReactorAnswer::allow());
                self::fail("binding $excluded was accepted; §22.7 makes it un-hookable");
            } catch (InvalidArgumentException $e) {
                self::assertStringContainsString('not a hookable reactor event', $e->getMessage());
            }
        }
    }

    /** The rejection names what IS hookable, never what is excluded (rule 2). */
    public function testRejectionNamesTheRegistryNotTheExclusions(): void
    {
        try {
            new OnReactorEvent('nope');
            self::fail('an unregistered event name was accepted');
        } catch (InvalidArgumentException $e) {
            self::assertStringContainsString(ReactorEvents::TOKEN_PRE_ISSUE, $e->getMessage());
            foreach (['authz.check', 'authz.check_batch', 'token.introspect'] as $excluded) {
                self::assertStringNotContainsString($excluded, $e->getMessage());
            }
        }
    }

    // -- rule 3: one handler per event --------------------------------------

    public function testRejectsADuplicateBinding(): void
    {
        $handlers = (new ReactorHandlers())
            ->bind(ReactorEvents::TOKEN_PRE_ISSUE, static fn (ReactorEvent $e): ReactorAnswer => ReactorAnswer::allow());

        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/already bound/');

        $handlers->bind(ReactorEvents::TOKEN_PRE_ISSUE, static fn (ReactorEvent $e): ReactorAnswer => ReactorAnswer::deny('second'));
    }

    // -- rule 4: an unbound event abstains -----------------------------------

    public function testUnboundEventAbstainsRatherThanAllowing(): void
    {
        $handler = ReactorHandlers::of(new HandlersFixtureReactor())->handler();

        try {
            $answer = $handler(self::event(ReactorEvents::GRANT_PRE_ASSIGN));
            self::fail(sprintf(
                'an unbound event produced a "%s" answer; §22.14 rule 4 requires no reply at all',
                $answer->decision(),
            ));
        } catch (ReactorRejection $rejection) {
            // Throwing publishes NOTHING, so the registration's failure_policy
            // decides (§22.8) — not a synthesized allow (§22.10 rule 2).
            self::assertSame(ReactorRejection::UNKNOWN_EVENT, $rejection->reason());
            self::assertStringContainsString(ReactorEvents::GRANT_PRE_ASSIGN, $rejection->getMessage());
        }
    }

    public function testEmptyBindingSetIsRefused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/no bindings/');

        (new ReactorHandlers())->handler();
    }

    // -- rule 5: a handler's own failure propagates ---------------------------

    public function testHandlerThrowablePropagates(): void
    {
        $handler = (new ReactorHandlers())
            ->bind(ReactorEvents::LOGIN_POST_AUTH, static function (ReactorEvent $e): ReactorAnswer {
                throw new RuntimeException('fraud service unreachable');
            })
            ->handler();

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('fraud service unreachable');

        $handler(self::event(ReactorEvents::LOGIN_POST_AUTH));
    }

    // -- rule 6 and the SHOULD ------------------------------------------------

    public function testForbiddenPatchKeyIsSentUnfiltered(): void
    {
        $handler = (new ReactorHandlers())
            ->bind(
                ReactorEvents::TOKEN_PRE_ISSUE,
                static fn (ReactorEvent $e): ReactorAnswer => ReactorAnswer::mutate(['sub' => 'attacker']),
            )
            ->handler();

        $answer = $handler(self::event(ReactorEvents::TOKEN_PRE_ISSUE));

        self::assertSame(['sub' => 'attacker'], $answer->patch(), 'the binder silently dropped a patch key');
    }

    public function testBoundEventsFeedTheFailurePolicy(): void
    {
        $handlers = ReactorHandlers::of(new HandlersFixtureReactor());

        // token.pre_issue defaults open, login.post_auth defaults closed; §22.8's
        // strictest-wins composition makes the pair fail_closed.
        self::assertSame(
            ReactorEvents::FAIL_CLOSED,
            ReactorEvents::defaultFailurePolicy($handlers->events()),
        );
    }

    public function testHandlerSnapshotsItsBindings(): void
    {
        $handlers = (new ReactorHandlers())
            ->bind(ReactorEvents::TOKEN_PRE_ISSUE, static fn (ReactorEvent $e): ReactorAnswer => ReactorAnswer::allow());
        $handler = $handlers->handler();

        $handlers->bind(ReactorEvents::GRANT_PRE_ASSIGN, static fn (ReactorEvent $e): ReactorAnswer => ReactorAnswer::deny('late'));

        $this->expectException(ReactorRejection::class);
        $handler(self::event(ReactorEvents::GRANT_PRE_ASSIGN));
    }
}
