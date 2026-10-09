<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Fixtures;

/**
 * Redaction assertions for the contract-1.58 tests.
 *
 * Every failure message here is FIXED TEXT or an offset: a redaction test that fails must not
 * itself print the secret it caught, nor the rendering it found it in (PHPUnit's
 * `assertStringNotContainsString()` would print both, which is exactly the cleartext logging a
 * redaction test exists to prevent).
 */
trait RedactionAssertions
{
    /** A random value of `$bytes` bytes as hex, with a recognisable prefix. */
    protected static function runtimeSecret(string $prefix, int $bytes = 20): string
    {
        return $prefix . bin2hex(random_bytes($bytes));
    }

    /**
     * Every stringification sink a value can reach: `print_r`, `var_export`, `var_dump`,
     * `json_encode`, `serialize`, and a string cast when the value has one.
     */
    protected static function renderings(mixed $value): string
    {
        ob_start();
        var_dump($value);
        $dump = (string) ob_get_clean();
        $out = print_r($value, true) . "\n" . var_export($value, true) . "\n" . $dump . "\n"
            . (string) json_encode($value) . "\n";
        try {
            $out .= serialize($value) . "\n";
        } catch (\Throwable) {
            // not serializable: nothing rendered
        }
        if ($value instanceof \Throwable) {
            $out .= $value->getMessage() . "\n" . $value . "\n";
            for ($cause = $value->getPrevious(); $cause !== null; $cause = $cause->getPrevious()) {
                $out .= $cause->getMessage() . "\n";
            }
        } elseif (is_object($value) && method_exists($value, '__toString')) {
            $out .= (string) $value . "\n";
        }

        return $out;
    }

    /** Asserts that no 8-character substring of `$secret` occurs in `$haystack`. */
    protected static function assertNoFragment(string $haystack, string $secret): void
    {
        $last = max(0, strlen($secret) - 8);
        for ($i = 0; $i <= $last; $i++) {
            self::assertFalse(
                str_contains($haystack, substr($secret, $i, 8)),
                sprintf('an 8-character fragment of the secret (offset %d) appears in a rendering', $i),
            );
        }
    }

    /** Asserts `$actual` equals the secret `$expected`, printing neither on failure. */
    protected static function assertSecretEquals(string $expected, mixed $actual, string $what): void
    {
        self::assertTrue($actual === $expected, $what . ': the value on the wire is not the expected secret');
    }
}
