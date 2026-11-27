<?php

declare(strict_types=1);

namespace Axiam\Sdk\Amqp;

/**
 * The strict-parse half of CONTRACT.md §8 consumer obligation 1: a body whose keys are
 * ambiguous is not a decision.
 *
 * `json_decode()` silently keeps the LAST of two equal keys, so a duplicate-key body is read
 * one way by this SDK and another way by any parser that keeps the first. This scanner finds
 * what `json_decode()` hides: the same key twice in ANY object, and — at the top level, the
 * one object a response is decoded from — two keys that differ only by case.
 *
 * @internal
 */
final class StrictJson
{
    private string $s = '';

    private int $i = 0;

    private function __construct()
    {
    }

    /**
     * True when `$body` must be refused: not valid JSON, not an object, or an object with an
     * ambiguous key. Nothing about a body this returns `true` for is trusted.
     */
    public static function isAmbiguousObject(string $body): bool
    {
        // §8 step 2a: the first byte is the opening `{`. A byte-order mark, whitespace or any other
        // prefix is refused here, never stripped (json_decode itself tolerates leading whitespace).
        if ($body === '' || $body[0] !== '{') {
            return true;
        }
        try {
            $decoded = json_decode($body, false, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return true;
        }
        if (!$decoded instanceof \stdClass) {
            return true;
        }

        $scanner = new self();
        $scanner->s = $body;
        $scanner->skipWhitespace();

        return $scanner->scanObject(true);
    }

    /** Scans one object starting at `{`; true when it (or anything inside it) is ambiguous. */
    private function scanObject(bool $top): bool
    {
        $this->i++; // {
        $seen = [];
        $folded = [];
        $this->skipWhitespace();
        if ($this->s[$this->i] === '}') {
            $this->i++;

            return false;
        }

        while (true) {
            $this->skipWhitespace();
            $literal = $this->scanStringLiteral();
            $key = json_decode($literal, false);
            if (!is_string($key)) {
                return true;
            }
            if (isset($seen['k' . $key])) {
                return true;
            }
            $seen['k' . $key] = true;
            if ($top) {
                $fold = 'k' . strtolower($key);
                if (isset($folded[$fold])) {
                    return true;
                }
                $folded[$fold] = true;
            }

            $this->skipWhitespace();
            $this->i++; // :
            if ($this->scanValue()) {
                return true;
            }

            $this->skipWhitespace();
            $c = $this->s[$this->i++];
            if ($c === '}') {
                return false;
            }
            // else ',' — the body already parsed as valid JSON.
        }
    }

    private function scanValue(): bool
    {
        $this->skipWhitespace();
        $c = $this->s[$this->i];
        if ($c === '{') {
            return $this->scanObject(false);
        }
        if ($c === '[') {
            $this->i++;
            $this->skipWhitespace();
            if ($this->s[$this->i] === ']') {
                $this->i++;

                return false;
            }
            while (true) {
                if ($this->scanValue()) {
                    return true;
                }
                $this->skipWhitespace();
                if ($this->s[$this->i++] === ']') {
                    return false;
                }
            }
        }
        if ($c === '"') {
            $this->scanStringLiteral();

            return false;
        }
        // number, true, false, null
        while ($this->i < strlen($this->s) && !in_array($this->s[$this->i], [',', '}', ']', ' ', "\t", "\r", "\n"], true)) {
            $this->i++;
        }

        return false;
    }

    /** Consumes a string literal and returns it with its quotes. */
    private function scanStringLiteral(): string
    {
        $start = $this->i;
        $this->i++; // opening quote
        $n = strlen($this->s);
        while ($this->i < $n) {
            $c = $this->s[$this->i];
            if ($c === '\\') {
                $this->i += 2;
                continue;
            }
            $this->i++;
            if ($c === '"') {
                break;
            }
        }

        return substr($this->s, $start, $this->i - $start);
    }

    private function skipWhitespace(): void
    {
        $n = strlen($this->s);
        while ($this->i < $n && in_array($this->s[$this->i], [' ', "\t", "\r", "\n"], true)) {
            $this->i++;
        }
    }
}
