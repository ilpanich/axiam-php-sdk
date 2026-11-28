<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

/**
 * What a login/callback handler should do next — one shape per outcome kind. Framework
 * controllers ({@see \Axiam\Sdk\Laravel\OidcLoginController}/`OidcCallbackController`,
 * {@see \Axiam\Sdk\Symfony\OidcLoginController}/`OidcCallbackController`) translate this
 * into their own framework's redirect/JSON response and add nothing of their own, so
 * Laravel and Symfony cannot drift (mirrors the TypeScript reference's
 * `OidcLoginOutcome` discriminated union).
 */
final class OidcLoginOutcome
{
    public const KIND_REDIRECT = 'redirect';
    public const KIND_JSON = 'json';
    public const KIND_ERROR = 'error';

    private function __construct(
        public readonly string $kind,
        public readonly ?string $redirectUrl = null,
        public readonly ?bool $authenticated = null,
        public readonly ?string $sub = null,
        public readonly ?int $expiresIn = null,
        public readonly ?int $status = null,
        public readonly ?string $error = null,
        public readonly ?string $message = null,
        /**
         * A complete `Set-Cookie` header value the controller MUST send with this response,
         * or `null`. The login redirect carries the browser-binding cookie; EVERY callback
         * outcome carries its clearing twin (CONTRACT.md §12.8 rule 1 (a), (d)).
         */
        public readonly ?string $setCookie = null,
    ) {
    }

    /** The same outcome carrying `$setCookie` as its `Set-Cookie` header value. */
    public function withSetCookie(string $setCookie): self
    {
        return new self(
            $this->kind,
            $this->redirectUrl,
            $this->authenticated,
            $this->sub,
            $this->expiresIn,
            $this->status,
            $this->error,
            $this->message,
            $setCookie,
        );
    }

    /** Send a 302 to `$url` — the IdP authorization URL, or the post-login destination. */
    public static function redirect(string $url): self
    {
        return new self(self::KIND_REDIRECT, redirectUrl: $url);
    }

    /**
     * The value a controller writes into the `Location` header for a redirect to `$destination`:
     * its percent-encoded form (login-glue Decision 7, §12.8 rule 3). The ADAPTER encodes, at the
     * point where it writes the header; the application is never asked to, and its hooks
     * (`allowReturnTo`, `$onSuccess`) see the raw value. The core keeps returning the raw
     * destination in {@see self::$redirectUrl}.
     *
     * Why it is needed: `return_to` is accepted raw (the framework has already percent-decoded the
     * query parameter), so `/a b`, `/café` and, for an integrator whose `allowReturnTo` admits
     * it, CR/LF are all valid stored values, while a header may hold only visible ASCII. The
     * rules, those of `encodeurl`:
     *
     *  1. every byte outside `A-Z a-z 0-9 ! # $ % & ' ( ) * + , - . / : ; = ? @ [ \ ] ^ _ | ~` is
     *     written as `%XX` with upper-case hex (UTF-8 bytes of a non-ASCII character each; space
     *     `%20`, CR `%0D`, LF `%0A`, `"` `%22`, `<` `%3C`, `>` `%3E`, `` ` `` `%60`); a backslash is
     *     KEPT as it is; each maximal subpart of an ill-formed UTF-8 sequence becomes one U+FFFD
     *     (`%EF%BF%BD`) first, never an error;
     *  2. a `%` that starts a well-formed escape (`%` and two hex digits) is kept, so a value
     *     that is already encoded is not encoded twice; any other `%` becomes `%25`;
     *  3. the result is pure visible ASCII (`0x21`–`0x7E`), so CR/LF can never split the header.
     *
     * Applying it to a value that is already in this form changes nothing, so the IdP
     * authorization URL of the login redirect passes through it unchanged.
     */
    public static function encodeLocation(string $destination): string
    {
        $valid = self::scrubUtf8($destination);

        return (string) preg_replace_callback(
            '/%(?![0-9A-Fa-f]{2})|[^A-Za-z0-9!#$%&\'()*+,\-.\/:;=?@\[\\\\\]^_|~]/',
            static function (array $m): string {
                $encoded = '';
                foreach (str_split($m[0]) as $byte) {
                    $encoded .= sprintf('%%%02X', ord($byte));
                }

                return $encoded;
            },
            $valid,
        );
    }

    /**
     * Replaces each maximal subpart of an ill-formed UTF-8 sequence by one U+FFFD (the Unicode /
     * WHATWG substitution, what Node's decoder and Python's `errors='replace'` do): `E2 82` is one
     * U+FFFD, `FF` one, `C0 80` two. Valid sequences pass through. Never throws.
     */
    private static function scrubUtf8(string $s): string
    {
        $out = '';
        $n = strlen($s);
        for ($i = 0; $i < $n;) {
            $b = ord($s[$i]);
            if ($b < 0x80) {
                $out .= $s[$i++];
                continue;
            }
            // [continuation count, allowed range of the FIRST continuation byte]
            if ($b >= 0xC2 && $b <= 0xDF) {
                [$need, $lo, $hi] = [1, 0x80, 0xBF];
            } elseif ($b === 0xE0) {
                [$need, $lo, $hi] = [2, 0xA0, 0xBF];
            } elseif ($b === 0xED) {
                [$need, $lo, $hi] = [2, 0x80, 0x9F];
            } elseif ($b >= 0xE1 && $b <= 0xEF) {
                [$need, $lo, $hi] = [2, 0x80, 0xBF];
            } elseif ($b === 0xF0) {
                [$need, $lo, $hi] = [3, 0x90, 0xBF];
            } elseif ($b >= 0xF1 && $b <= 0xF3) {
                [$need, $lo, $hi] = [3, 0x80, 0xBF];
            } elseif ($b === 0xF4) {
                [$need, $lo, $hi] = [3, 0x80, 0x8F];
            } else {
                $out .= "\xEF\xBF\xBD"; // a stray continuation or an invalid lead byte
                $i++;
                continue;
            }
            $j = $i + 1;
            $ok = true;
            for ($k = 0; $k < $need; $k++, $j++) {
                $c = $j < $n ? ord($s[$j]) : -1;
                $min = $k === 0 ? $lo : 0x80;
                $max = $k === 0 ? $hi : 0xBF;
                if ($c < $min || $c > $max) {
                    $ok = false;
                    break;
                }
            }
            $out .= $ok ? substr($s, $i, $need + 1) : "\xEF\xBF\xBD";
            $i = $j; // on failure: past the consumed prefix (the maximal subpart)
        }

        return $out;
    }

    /** Reply `200` with a token-free login summary — the fallback when no post-login redirect is configured. */
    public static function json(?string $sub, int $expiresIn): self
    {
        return new self(self::KIND_JSON, authenticated: true, sub: $sub, expiresIn: $expiresIn);
    }

    /** Reply `$status` with the standardized `{error, message}` body (§10/§11 shape). */
    public static function error(int $status, string $error, string $message): self
    {
        return new self(self::KIND_ERROR, status: $status, error: $error, message: $message);
    }

    /** @return array{error: string, message: string} */
    public function errorBody(): array
    {
        \assert($this->error !== null && $this->message !== null);

        return ['error' => $this->error, 'message' => $this->message];
    }

    /** @return array{authenticated: true, sub?: string, expiresIn: int} */
    public function jsonBody(): array
    {
        \assert($this->expiresIn !== null);

        return array_filter(
            ['authenticated' => true, 'sub' => $this->sub, 'expiresIn' => $this->expiresIn],
            static fn (mixed $v): bool => $v !== null,
        );
    }
}
