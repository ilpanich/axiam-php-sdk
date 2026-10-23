<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Contract164;

use Axiam\Sdk\Core\NetworkError;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * C164-09: `Retry-After` is read in the RFC 9110 forms only. `strtotime()` read `17.0` as a time
 * of day about seven hours ahead, and a polling loop that honours the value then ended its flow.
 */
final class RetryAfterParsingTest extends TestCase
{
    /** @return iterable<string,array{string}> */
    public static function notRetryAfterValues(): iterable
    {
        yield 'a decimal' => ['17.0'];
        yield 'a fraction' => ['1.5'];
        yield 'a signed number' => ['-5'];
        yield 'a time of day' => ['10:30'];
        yield 'a relative phrase' => ['+2 hours'];
        yield 'a word' => ['tomorrow'];
        yield 'a date without the GMT zone' => ['Wed, 21 Oct 2099 07:28:00 PST'];
        yield 'a date that does not exist' => ['Wed, 31 Feb 2099 07:28:00 GMT'];
        yield 'empty' => [''];
    }

    /** @dataProvider notRetryAfterValues */
    public function testAValueThatIsNotARetryAfterFormIsIgnored(string $value): void
    {
        self::assertNull(NetworkError::parseRetryAfterMs(new Response(429, ['Retry-After' => $value])));
    }

    public function testDeltaSecondsAreMilliseconds(): void
    {
        self::assertSame(12000.0, NetworkError::parseRetryAfterMs(new Response(429, ['Retry-After' => '12'])));
        self::assertNull(NetworkError::parseRetryAfterMs(new Response(429, ['Retry-After' => '0'])));
        self::assertNull(NetworkError::parseRetryAfterMs(new Response(429)));
    }

    /** @return iterable<string,array{string}> */
    public static function httpDateForms(): iterable
    {
        yield 'IMF-fixdate' => ['D, d M Y H:i:s \G\M\T'];
        yield 'RFC 850' => ['l, d-M-y H:i:s \G\M\T'];
        yield 'asctime' => ['D M j H:i:s Y'];
    }

    /** @dataProvider httpDateForms */
    public function testEachHttpDateFormIsReadAsTheWaitUntilThen(string $format): void
    {
        // The date is built here, not in the provider, which runs before the suite does.
        $value = gmdate($format, time() + 60);
        $ms = NetworkError::parseRetryAfterMs(new Response(503, ['Retry-After' => $value]));

        self::assertNotNull($ms, $value);
        self::assertEqualsWithDelta(60000.0, $ms, 3000.0);
    }

    public function testAPastDateIsNoWait(): void
    {
        self::assertNull(NetworkError::parseRetryAfterMs(new Response(503, ['Retry-After' => 'Wed, 21 Oct 2015 07:28:00 GMT'])));
    }
}
