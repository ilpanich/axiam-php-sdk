<?php

declare(strict_types=1);

namespace Axiam\Sdk\Opaque;

use Axiam\Sdk\Core\NetworkError;

/**
 * One in-flight OPAQUE exchange, owning a native state handle.
 *
 * The handle is **single-use**: the library consumes it in `finish` whether that succeeds or
 * fails. This class takes it out of a one-shot slot, so a second `finish` raises a PHP exception
 * rather than handing a dangling pointer across the ABI.
 *
 * `__destruct` releases an exchange the caller abandoned — a login started and never completed.
 * PHP's refcounting makes that prompt rather than eventual, which is the one place its object
 * model is kinder here than a tracing GC's.
 */
abstract class OpaqueExchange
{
    private mixed $handle;

    /**
     * Adopts `$handle`, which this exchange now owns and must release exactly once — through
     * `finish`, `close()` or the destructor, whichever comes first.
     */
    public function __construct(
        protected readonly OpaqueNativeInterface $lib,
        mixed $handle,
        /** The first protocol message, hex — `RegistrationRequest` or `KE1`. */
        protected readonly string $firstMessage,
    ) {
        $this->handle = $handle;
    }

    /**
     * Spends the handle, or refuses if it is already spent.
     *
     * @throws NetworkError if this exchange has already been completed
     */
    protected function consume(): mixed
    {
        if ($this->handle === null) {
            throw NetworkError::fromMessage('OPAQUE: this exchange has already been completed');
        }

        $handle = $this->handle;
        $this->handle = null;

        return $handle;
    }

    /** Releases the state this exchange still owns. Called by `__destruct` and by `close()`. */
    abstract protected function free(mixed $handle): void;

    /**
     * Releases the exchange if it was never finished.
     *
     * Idempotent, and a no-op once `finish` has spent the handle. Calling it is optional —
     * `__destruct` does the same thing — but an application that knows the exchange is over
     * should not wait for a refcount to say so.
     */
    public function close(): void
    {
        if ($this->handle === null) {
            return;
        }

        $handle = $this->handle;
        $this->handle = null;
        $this->free($handle);
    }

    /**
     * Releases an exchange the caller abandoned — a login started and never completed. PHP's
     * refcounting makes that prompt rather than eventual.
     */
    public function __destruct()
    {
        $this->close();
    }
}
