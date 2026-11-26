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
     *     KEPT as it is; a byte sequence that is not valid UTF-8 becomes U+FFFD (`%EF%BF%BD`)
     *     first, never an error;
     *  2. a `%` that starts a well-formed escape (`%` and two hex digits) is kept, so a value
     *     that is already encoded is not encoded twice; any other `%` becomes `%25`;
     *  3. the result is pure visible ASCII (`0x21`–`0x7E`), so CR/LF can never split the header.
     *
     * Applying it to a value that is already in this form changes nothing, so the IdP
     * authorization URL of the login redirect passes through it unchanged.
     */
    public static function encodeLocation(string $destination): string
    {
        // Invalid UTF-8 (the PHP counterpart of a lone surrogate) becomes U+FFFD before encoding.
        $valid = (string) preg_replace(
            '/(?:[\x00-\x7F]|[\xC2-\xDF][\x80-\xBF]|\xE0[\xA0-\xBF][\x80-\xBF]|[\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}|\xED[\x80-\x9F][\x80-\xBF]|\xF0[\x90-\xBF][\x80-\xBF]{2}|[\xF1-\xF3][\x80-\xBF]{3}|\xF4[\x80-\x8F][\x80-\xBF]{2})(*SKIP)(*FAIL)|./s',
            "\xEF\xBF\xBD",
            $destination,
        );

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
