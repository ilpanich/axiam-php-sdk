<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\AuthError;
use PHPUnit\Framework\TestCase;

/**
 * Source-compatibility lock on {@see AuthError}'s constructor (conformance-review F-18).
 *
 * §12 added the machine-readable `$reason` code as the SECOND positional parameter,
 * ahead of `$previous` — which silently redefined what the second positional argument
 * means for anyone who already constructed this class directly, turning
 * `new AuthError($message, $previous)` into a `TypeError`. `$reason` now comes last,
 * where an added parameter belongs, and `$previous` is back in the slot PHP's own
 * exception convention and this SDK's `NetworkError` both put it in.
 *
 * These assertions are about the shape of a PUBLIC constructor, not about behaviour that
 * any other test would notice breaking — that is exactly why they are written down.
 */
final class AuthErrorParameterOrderTest extends TestCase
{
    public function testPreviousIsTheSecondPositionalParameter(): void
    {
        $cause = new \RuntimeException('the underlying transport failure');

        $error = new AuthError('refresh failed', $cause);

        self::assertSame($cause, $error->getPrevious());
        self::assertNull($error->getReason(), 'a cause-only AuthError carries no §12.4 reason code');
    }

    public function testReasonIsAcceptedByName(): void
    {
        $error = new AuthError('id_token validation failed', reason: 'token_expired');

        self::assertSame('token_expired', $error->getReason());
        self::assertNull($error->getPrevious());
    }

    public function testBothMayBeGivenTogether(): void
    {
        $cause = new \RuntimeException('jwt decode blew up');

        $error = new AuthError('id_token signature verification failed', $cause, reason: 'invalid_signature');

        self::assertSame($cause, $error->getPrevious());
        self::assertSame('invalid_signature', $error->getReason());
    }

    /**
     * The declared order itself, asserted by reflection: a future additive parameter must
     * be appended after `$reason`, never inserted ahead of it (which is the mistake F-18
     * records).
     */
    public function testDeclaredParameterOrderIsMessagePreviousReason(): void
    {
        $constructor = (new \ReflectionClass(AuthError::class))->getConstructor();
        self::assertNotNull($constructor);

        self::assertSame(
            ['message', 'previous', 'reason'],
            array_map(
                static fn (\ReflectionParameter $p): string => $p->getName(),
                $constructor->getParameters(),
            ),
        );
    }
}
