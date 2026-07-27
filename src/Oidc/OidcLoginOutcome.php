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
    ) {
    }

    /** Send a 302 to `$url` — the IdP authorization URL, or the post-login destination. */
    public static function redirect(string $url): self
    {
        return new self(self::KIND_REDIRECT, redirectUrl: $url);
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
