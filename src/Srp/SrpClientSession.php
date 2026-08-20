<?php

declare(strict_types=1);

namespace Axiam\Sdk\Srp;

use Axiam\Sdk\Core\NetworkError;

/**
 * One SRP exchange's client half: the ephemeral secret `a` held between the challenge request and
 * the proof that answers it (CONTRACT.md §23.2).
 *
 * A session is single-use. `a` is drawn fresh per exchange by {@see self::begin()} and there is no
 * way to supply one there, because reusing it across logins leaks the relationship between two
 * session secrets (§23.3 rule 7).
 */
final class SrpClientSession
{
    /** `A = g^a mod N`, lowercase hex — sent with the challenge request. */
    public readonly string $clientPublic;

    private function __construct(
        private readonly Srp $srp,
        /** The group this exchange runs in. */
        public readonly SrpGroup $group,
        private readonly string $ephemeralHex,
    ) {
        $this->clientPublic = Srp::pad(
            $srp->backend()->modPow(\dechex($group->generator), $ephemeralHex, $group->modulusHex),
            $group->byteLength,
        );
    }

    /**
     * Starts an exchange in `$group`: draws a fresh `a` of at least 256 bits from the platform
     * CSPRNG and computes `A`.
     */
    public static function begin(Srp $srp, SrpGroup $group): self
    {
        $raw = \random_bytes(32);
        // Set the top bit so a is unambiguously >= 2^255.
        $raw[0] = \chr(\ord($raw[0]) | 0x80);

        return new self($srp, $group, \bin2hex($raw));
    }

    /**
     * Starts an exchange with `a` pinned to a supplied value.
     *
     * For the §23.7 cross-language vectors **only**: they fix `a` so every intermediate is
     * reproducible. Never call this from application code — a predictable `a` defeats the protocol.
     */
    public static function withFixedEphemeral(Srp $srp, SrpGroup $group, string $ephemeralHex): self
    {
        return new self($srp, $group, $ephemeralHex);
    }

    /**
     * Completes the exchange: `S`, `K`, `M1` and the `M2` the server must return.
     *
     * @param string $identity        the identity from the challenge response, never what the user
     *                                typed (§23.3 rule 2)
     * @param string $saltHex         the `salt` field of the challenge response
     * @param string $serverPublicHex the `b_pub` field of the challenge response
     * @param string $x               the KDF output from {@see Srp::deriveX()}, raw bytes
     *
     * @throws NetworkError if `B mod N == 0`, if `u` would be zero, or if a hex field is malformed
     */
    public function finish(string $identity, string $saltHex, string $serverPublicHex, string $x): SrpProofs
    {
        $backend = $this->srp->backend();
        $group = $this->group;
        $modulus = $group->modulusHex;

        $salt = Srp::hexToBytes($saltHex, 'salt');
        // Validate before padding: pad() would reject an over-wide value with a different message,
        // and a malformed b_pub is a hex problem rather than a width problem.
        Srp::hexToBytes($serverPublicHex, 'b_pub');

        // §23.3 rule 5. B ≡ 0 is the classic SRP break: S becomes predictable and the exchange
        // would authenticate against a server that never knew the verifier. That is a broken or
        // hostile server, not a wrong password.
        $serverPublic = $backend->mod($serverPublicHex, $modulus);
        if ($backend->isZero($serverPublic)) {
            throw NetworkError::fromMessage('SRP: the server sent an invalid public value (B mod N == 0)');
        }

        $paddedA = Srp::hexToBytes($this->clientPublic, 'client_public');
        $paddedB = Srp::hexToBytes(Srp::pad($serverPublicHex, $group->byteLength), 'b_pub');

        // u = H(PAD(A) | PAD(B))
        $u = Srp::hash($paddedA, $paddedB);
        if ($backend->isZero($u)) {
            throw NetworkError::fromMessage("SRP: the server's parameters produce u == 0");
        }

        $xHex = $backend->mod(\bin2hex($x), $modulus);
        $k = Srp::multiplier($group);

        // S = (B - k*g^x)^(a + u*x) mod N
        $gx = $backend->modPow(\dechex($group->generator), $xHex, $modulus);
        $kgx = $backend->mulMod($k, $gx, $modulus);
        $base = $backend->subMod($serverPublic, $kgx, $modulus);
        // The exponent is NOT reduced: a + u*x is an exponent, and reducing it modulo N rather
        // than the group order would produce a different — wrong — S that still looks fine.
        $exponent = $backend->add($this->ephemeralHex, $backend->mul($u, $xHex));
        $sharedSecret = $backend->modPow($base, $exponent, $modulus);

        $paddedS = Srp::hexToBytes(Srp::pad($sharedSecret, $group->byteLength), 'session_secret');
        $sessionKey = Srp::hexToBytes(Srp::hash($paddedS), 'session_key');

        // M1 = H(H(N) XOR H(PAD(g)) | H(I) | s | PAD(A) | PAD(B) | K)
        $hn = Srp::hexToBytes(Srp::hash(Srp::hexToBytes(Srp::pad($modulus, $group->byteLength))));
        $hg = Srp::hexToBytes(Srp::hash(Srp::hexToBytes(Srp::pad(\dechex($group->generator), $group->byteLength))));
        $hxor = $hn ^ $hg;
        $hi = Srp::hexToBytes(Srp::hash($identity));
        $m1 = Srp::hash($hxor, $hi, $salt, $paddedA, $paddedB, $sessionKey);

        // M2 = H(PAD(A) | M1 | K)
        $m2 = Srp::hash($paddedA, Srp::hexToBytes($m1, 'client_proof'), $sessionKey);

        return new SrpProofs($m1, $m2);
    }
}
