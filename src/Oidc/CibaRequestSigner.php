<?php

declare(strict_types=1);

namespace Axiam\Sdk\Oidc;

use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Management\FieldError;
use Axiam\Sdk\Management\ValidationError;
use Firebase\JWT\JWT;

/**
 * The key and algorithm for CIBA's signed authentication request (CONTRACT.md §33.2, CIBA
 * Core §7.1.1). Both are the caller's: there is no default for either, and the SDK signs under
 * exactly the algorithm given — the one the client registered as
 * `backchannel_authentication_request_signing_alg`.
 *
 * The key material is held only behind {@see Sensitive} (§33.5): `print_r()`, `var_dump()`,
 * `var_export()` and `json_encode()` of a signer show the algorithm and `kid`, never the key.
 *
 * Signing uses `firebase/php-jwt`, this SDK's JOSE library: `EdDSA` (through ext-sodium) and
 * `ES256` (through ext-openssl). `PS256` is refused at construction — the library signs it
 * only through phpseclib 3, which this SDK does not depend on (see {@see CibaSigningAlg}).
 */
final class CibaRequestSigner implements \JsonSerializable
{
    /** The DER prefix of an RFC 8410 Ed25519 PKCS#8 private key, before its 32-byte seed. */
    private const ED25519_PKCS8_PREFIX = '302e020100300506032b657004220420';

    /** @param Sensitive $key The key in the form `firebase/php-jwt` signs `$alg` with. */
    private function __construct(
        public readonly CibaSigningAlg $alg,
        private readonly Sensitive $key,
        public readonly ?string $kid,
    ) {
    }

    /**
     * A signer from a PEM private key and the algorithm it signs under: a PKCS#8
     * (`BEGIN PRIVATE KEY`) Ed25519 key for `EdDSA`, a P-256 EC key (PKCS#8 or SEC1) for
     * `ES256`.
     *
     * The key is proved by signing a probe before this returns, so a key that cannot sign
     * under `$alg` is refused here, before any request.
     *
     * @param CibaSigningAlg $alg           The registered algorithm.
     * @param Sensitive      $privateKeyPem The private key, PEM.
     * @param string|null    $kid           The `kid` to put in the JWS header, if your registered
     *                                      JWKS names one.
     *
     * @throws ValidationError locally: an empty key, a key that does not sign under `$alg`, or
     *         `PS256`, which this SDK does not sign.
     */
    public static function fromPem(CibaSigningAlg $alg, Sensitive $privateKeyPem, ?string $kid = null): self
    {
        $pem = $privateKeyPem->reveal();
        $key = match ($alg) {
            CibaSigningAlg::EdDSA => self::ed25519SecretKey($pem),
            CibaSigningAlg::ES256 => self::p256Key($pem),
            CibaSigningAlg::PS256 => throw self::refuse(
                'PS256 is not supported by this SDK: its JOSE library (firebase/php-jwt) signs PS256 only '
                . 'through phpseclib 3, which this SDK does not depend on — register ES256 or EdDSA',
            ),
        };
        if ($key === null) {
            throw self::refuse('the key is not a private key that signs under ' . $alg->value);
        }
        try {
            JWT::sign('axiam-ciba-probe', $key, $alg->value);
        } catch (\Throwable) {
            throw self::refuse('the key is not a private key that signs under ' . $alg->value);
        }

        return new self($alg, new Sensitive($key), $kid);
    }

    /**
     * The compact JWS of `$claims`, signed under this signer's algorithm with its `kid`.
     *
     * @param array<string,mixed> $claims
     */
    public function sign(array $claims): Sensitive
    {
        return new Sensitive(JWT::encode($claims, $this->key->reveal(), $this->alg->value, $this->kid));
    }

    /**
     * The signer for a log line: the algorithm and `kid` only.
     *
     * @return array{alg: string, kid: string|null, key: string}
     */
    public function jsonSerialize(): array
    {
        return ['alg' => $this->alg->value, 'kid' => $this->kid, 'key' => '[SENSITIVE]'];
    }

    /** The 64-byte sodium secret key, base64 — `firebase/php-jwt`'s EdDSA key form. */
    private static function ed25519SecretKey(string $pem): ?string
    {
        if (preg_match('/-----BEGIN PRIVATE KEY-----(.+?)-----END PRIVATE KEY-----/s', $pem, $m) !== 1) {
            return null;
        }
        $der = base64_decode((string) preg_replace('/\s+/', '', $m[1]), true);
        $prefix = (string) hex2bin(self::ED25519_PKCS8_PREFIX);
        if ($der === false || strlen($der) !== strlen($prefix) + 32 || !str_starts_with($der, $prefix)) {
            return null;
        }
        $pair = sodium_crypto_sign_seed_keypair(substr($der, strlen($prefix)));

        return base64_encode(sodium_crypto_sign_secretkey($pair));
    }

    /** The PEM itself, when it is a P-256 EC private key. */
    private static function p256Key(string $pem): ?string
    {
        if (trim($pem) === '') {
            return null;
        }
        $key = @openssl_pkey_get_private($pem);
        if ($key === false) {
            return null;
        }
        $details = openssl_pkey_get_details($key);
        if (!is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_EC
            || ($details['ec']['curve_name'] ?? null) !== 'prime256v1') {
            return null;
        }

        return $pem;
    }

    private static function refuse(string $why): ValidationError
    {
        return new ValidationError(
            sprintf('ciba_initiate: signing_key — %s (CONTRACT.md §33.2)', $why),
            [new FieldError('signing_key', $why)],
        );
    }
}
