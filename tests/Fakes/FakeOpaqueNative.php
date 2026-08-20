<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Fakes;

use Axiam\Sdk\Opaque\OpaqueNativeInterface;

/**
 * An in-process stand-in for `libaxiam_opaque_ffi`.
 *
 * CONTRACT.md §23.1 forbids this SDK from implementing OPAQUE, so there is no cryptography to
 * test. What there is — and what this fake exercises — is the layer above the ABI: single-use
 * exchanges, the key-stretching function the *server* named being the one used, which failure
 * means what, and what goes on the wire.
 *
 * It does **not** stand in for pointer ownership. In PHP that lives entirely inside
 * {@see \Axiam\Sdk\Opaque\FfiOpaqueNative}, which needs the real shared library to exercise —
 * which is exactly why that class is the thinnest in the package. Requiring the real `cdylib`
 * here would give a suite that runs only where a per-platform release asset happens to be
 * installed, and would be testing `opaque-ke` rather than this SDK.
 *
 * Every value it returns is hex, as the real ABI's are: a fake that handed back raw bytes would
 * let a binding bug survive.
 */
final class FakeOpaqueNative implements OpaqueNativeInterface
{
    /** What `available()` answers. */
    public bool $availableValue = true;

    /** Key-stretching handles built and not yet released. Must be zero after any finish. */
    public int $ksfAlive = 0;

    /** @var array<int, string> live state handles, by id, mapped to their kind */
    private array $states = [];

    private int $nextHandle = 0x1000;

    /** @var array<string, true> */
    private array $failing = [];

    /** @var array<string, string> */
    private array $failMessages = [];

    private string $lastErrorText = '';

    /** Makes an entry point return `null` instead of working. */
    public function fail(string $entryPoint): void
    {
        $this->failing[$entryPoint] = true;
    }

    /**
     * Overrides what `lastError()` reports for a failing entry point. An empty string models a
     * library that failed without saying why — a bug, but one the caller still needs a sentence
     * for.
     */
    public function failMessage(string $entryPoint, string $message): void
    {
        $this->failMessages[$entryPoint] = $message;
    }

    /** State handles neither consumed nor released. */
    public function statesAlive(): int
    {
        return \count($this->states);
    }

    /** Decodes one of this fake's hex payloads. */
    public static function decode(string $hex): string
    {
        return (string) hex2bin($hex);
    }

    private function failed(string $entryPoint, string $message): bool
    {
        if (!isset($this->failing[$entryPoint])) {
            return false;
        }

        $this->lastErrorText = $this->failMessages[$entryPoint] ?? $message;

        return true;
    }

    private function newState(string $kind): int
    {
        $this->nextHandle += 0x10;
        $this->states[$this->nextHandle] = $kind;

        return $this->nextHandle;
    }

    private function consumeState(mixed $handle, string $kind): void
    {
        $id = (int) $handle;
        if (($this->states[$id] ?? null) !== $kind) {
            throw new \LogicException(\sprintf('handle 0x%x was not a live %s', $id, $kind));
        }

        unset($this->states[$id]);
    }

    public function available(): bool
    {
        return $this->availableValue;
    }

    public function lastError(): string
    {
        return $this->lastErrorText;
    }

    public function ksfArgon2id(int $memoryKib, int $iterations, int $parallelism): mixed
    {
        if ($this->failed('ksf_argon2id', 'argon2id parameters rejected')) {
            return null;
        }

        ++$this->ksfAlive;

        return 0xA0000 + $memoryKib + $iterations + $parallelism;
    }

    public function ksfScrypt(int $logN, int $r, int $p): mixed
    {
        if ($this->failed('ksf_scrypt', 'scrypt parameters rejected')) {
            return null;
        }

        ++$this->ksfAlive;

        return 0xB0000 + $logN + $r + $p;
    }

    public function ksfFree(mixed $ksf): void
    {
        if ($ksf === null) {
            throw new \LogicException('free of a null ksf handle');
        }

        --$this->ksfAlive;
    }

    public function registrationStart(string $password): ?array
    {
        if ($this->failed('registration_start', 'registration could not be started')) {
            return null;
        }

        return [$this->newState('registration'), bin2hex('req:' . $password)];
    }

    public function registrationFinish(
        mixed $state,
        string $password,
        string $registrationResponse,
        mixed $ksf,
    ): ?string {
        $this->consumeState($state, 'registration');
        if ($this->failed('registration_finish', 'the envelope could not be sealed')) {
            return null;
        }

        return bin2hex(\sprintf(
            'record:%s:%s:%x',
            $password,
            $registrationResponse,
            (int) $ksf
        ));
    }

    public function registrationFree(mixed $state): void
    {
        $this->consumeState($state, 'registration');
    }

    public function loginStart(string $password): ?array
    {
        if ($this->failed('login_start', 'login could not be started')) {
            return null;
        }

        return [$this->newState('login'), bin2hex('ke1:' . $password)];
    }

    public function loginFinish(mixed $state, string $password, string $ke2, mixed $ksf): ?string
    {
        $this->consumeState($state, 'login');
        if ($this->failed('login_finish', 'the envelope did not open')) {
            return null;
        }

        return bin2hex(\sprintf('ke3:%s:%s:%x', $password, $ke2, (int) $ksf));
    }

    public function loginFree(mixed $state): void
    {
        $this->consumeState($state, 'login');
    }
}
