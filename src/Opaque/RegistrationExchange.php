<?php

declare(strict_types=1);

namespace Axiam\Sdk\Opaque;

use Axiam\Sdk\Core\NetworkError;

/** One in-flight enrolment (CONTRACT.md §23). */
final class RegistrationExchange extends OpaqueExchange
{
    /** The hex `RegistrationRequest` to send to `register/start`. */
    public function request(): string
    {
        return $this->firstMessage;
    }

    /**
     * Seals the envelope under the server's oblivious PRF, returning the hex
     * `RegistrationRecord`.
     *
     * @throws NetworkError if the exchange is already spent, the key-stretching function is one
     *                      this SDK cannot ask for, or the library refuses the response
     */
    public function finish(string $password, string $registrationResponse, KsfParams $ksf): string
    {
        // The key-stretching handle is built BEFORE the state is spent, and the
        // order is load-bearing. `build()` refuses an unrecognised function or an
        // out-of-band cost, and if the state had already been taken out of its
        // slot by then it could never be freed -- a leaked Rust allocation per
        // refused attempt, which is once per login against a misconfigured
        // tenant. Built first, a refusal leaves the exchange intact: `close()`
        // still releases it, and a caller who fixes the parameters can retry.
        $ksfHandle = $ksf->build($this->lib);

        try {
            $state = $this->consume();
            $record = $this->lib->registrationFinish(
                $state,
                $password,
                $registrationResponse,
                $ksfHandle,
            );

            if ($record === null) {
                throw NetworkError::fromMessage(
                    'OPAQUE: ' . Opaque::lastError($this->lib, 'the envelope could not be sealed')
                );
            }

            return $record;
        } finally {
            $this->lib->ksfFree($ksfHandle);
        }
    }

    protected function free(mixed $handle): void
    {
        $this->lib->registrationFree($handle);
    }
}
