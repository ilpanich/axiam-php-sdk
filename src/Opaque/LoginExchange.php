<?php

declare(strict_types=1);

namespace Axiam\Sdk\Opaque;

use Axiam\Sdk\Core\AuthError;
use Axiam\Sdk\Core\NetworkError;

/** One in-flight login (CONTRACT.md §23). */
final class LoginExchange extends OpaqueExchange
{
    /** The hex `KE1` to send to `login/start`. */
    public function ke1(): string
    {
        return $this->firstMessage;
    }

    /**
     * Opens the envelope, producing `KE3`.
     *
     * A failure here is the **whole** of the client's authentication check, and covers both
     * halves of the mutual authentication: the envelope only opens under the right password, and
     * `KE2`'s MAC only verifies if the server actually holds the record. Nothing may be sent
     * afterwards (§23.4 rule 7).
     *
     * That case is an {@see AuthError}, unlike every other refusal in this package. The
     * distinction is the point: a wrong password, an account that does not exist and a server
     * that does not hold the record are indistinguishable by design and are all authentication
     * failures, whereas a key-stretching function this build cannot perform is a configuration
     * problem, and reporting it as "invalid password" would send an operator looking in the wrong
     * place.
     *
     * @throws AuthError    when the envelope does not open or `KE2` does not verify
     * @throws NetworkError if the exchange is already spent, or the key-stretching function is
     *                      one this SDK cannot ask for
     */
    public function finish(string $password, string $ke2, KsfParams $ksf): string
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
            $ke3 = $this->lib->loginFinish($state, $password, $ke2, $ksfHandle);

            if ($ke3 === null) {
                throw new AuthError(
                    'invalid credentials: ' .
                    Opaque::lastError($this->lib, 'the OPAQUE envelope did not open')
                );
            }

            return $ke3;
        } finally {
            $this->lib->ksfFree($ksfHandle);
        }
    }

    protected function free(mixed $handle): void
    {
        $this->lib->loginFree($handle);
    }
}
