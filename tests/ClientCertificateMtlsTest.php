<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\AxiamClient;
use PHPUnit\Framework\TestCase;

/**
 * §6.1 (mTLS) proof: `AxiamClient` accepts a PEM client-certificate chain plus a PEM private
 * key (`clientCert`/`clientKey`) and wires that identity onto its Guzzle transports as
 * `cert`/`ssl_key` — WITHOUT ever relaxing server verification (§6.1.2). Both PEM strings are
 * all-or-nothing (§6.1.1): supplying exactly one is a construction-time error, and a non-PEM
 * value is rejected. The wiring is asserted through the `debugClientCertOptions()` test seam
 * (mirroring how {@see ClientConstructionTest} asserts `debugVerifyOption()`), since a full
 * client-cert-requiring TLS handshake is impractical in a pure-PHPUnit unit test.
 *
 * The test PKI (a self-signed cert + key) is generated at run time with PHP's own openssl
 * functions and written only under {@see sys_get_temp_dir()} — no private key or certificate
 * is ever committed to the repository.
 */
final class ClientCertificateMtlsTest extends TestCase
{
    private const BASE_URL = 'https://api.test';
    private const TENANT = 'acme';

    /**
     * Generates a throwaway self-signed X.509 identity and returns `[certPem, keyPem]` — used
     * only to prove the SDK forwards the exact PEM bytes it is handed. Requires the `openssl`
     * extension; the whole test is skipped when it is unavailable.
     *
     * @return array{0: string, 1: string}
     */
    private function generateTestIdentity(): array
    {
        if (!\function_exists('openssl_pkey_new')) {
            self::markTestSkipped('ext-openssl is required to generate the test client identity');
        }

        $config = [
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];

        $key = openssl_pkey_new($config);
        self::assertNotFalse($key, 'failed to generate a test private key');

        $csr = openssl_csr_new(['commonName' => 'axiam-mtls-test'], $key, $config);
        self::assertNotFalse($csr, 'failed to generate a test CSR');

        $cert = openssl_csr_sign($csr, null, $key, 1, $config);
        self::assertNotFalse($cert, 'failed to self-sign the test certificate');

        $certPem = '';
        self::assertTrue(openssl_x509_export($cert, $certPem));

        $keyPem = '';
        self::assertTrue(openssl_pkey_export($key, $keyPem, null, $config));

        return [$certPem, $keyPem];
    }

    public function testClientCertificateAndKeyAreWiredOntoGuzzleTransport(): void
    {
        [$certPem, $keyPem] = $this->generateTestIdentity();

        $client = new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            clientCert: $certPem,
            clientKey: $keyPem,
        );

        $options = $client->debugClientCertOptions();

        self::assertIsString($options['cert'], 'cert must be wired as a Guzzle `cert` file path');
        self::assertIsString($options['ssl_key'], 'ssl_key must be wired as a Guzzle `ssl_key` file path');
        self::assertFileExists($options['cert']);
        self::assertFileExists($options['ssl_key']);

        // The seam exposes FILE PATHS whose contents match the PEM strings passed in — never
        // the raw key material inline.
        self::assertSame($certPem, file_get_contents($options['cert']));
        self::assertSame($keyPem, file_get_contents($options['ssl_key']));
    }

    public function testClientCertOptionsAreNullWhenMtlsNotConfigured(): void
    {
        $client = new AxiamClient(self::BASE_URL, self::TENANT);

        self::assertSame(['cert' => null, 'ssl_key' => null], $client->debugClientCertOptions());
    }

    public function testConfiguringMtlsNeverRelaxesServerVerification(): void
    {
        [$certPem, $keyPem] = $this->generateTestIdentity();

        $client = new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            clientCert: $certPem,
            clientKey: $keyPem,
        );

        // §6.1.2: presenting a client certificate is additive — `verify` stays strict `true`.
        self::assertTrue($client->debugVerifyOption());
    }

    public function testSupplyingOnlyClientCertThrows(): void
    {
        [$certPem] = $this->generateTestIdentity();

        $this->expectException(\InvalidArgumentException::class);
        new AxiamClient(self::BASE_URL, self::TENANT, clientCert: $certPem);
    }

    public function testSupplyingOnlyClientKeyThrows(): void
    {
        [, $keyPem] = $this->generateTestIdentity();

        $this->expectException(\InvalidArgumentException::class);
        new AxiamClient(self::BASE_URL, self::TENANT, clientKey: $keyPem);
    }

    public function testNonPemClientCertIsRejectedAtConstruction(): void
    {
        [, $keyPem] = $this->generateTestIdentity();

        $this->expectException(\InvalidArgumentException::class);
        new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            clientCert: 'not-a-pem-certificate',
            clientKey: $keyPem,
        );
    }

    public function testTempFilesAreRemovedWhenClientIsDestroyed(): void
    {
        [$certPem, $keyPem] = $this->generateTestIdentity();

        $client = new AxiamClient(
            self::BASE_URL,
            self::TENANT,
            clientCert: $certPem,
            clientKey: $keyPem,
        );
        $options = $client->debugClientCertOptions();
        $certFile = $options['cert'];
        $keyFile = $options['ssl_key'];
        self::assertIsString($certFile);
        self::assertIsString($keyFile);

        unset($client);
        gc_collect_cycles();

        self::assertFileDoesNotExist($certFile, 'the client-cert temp file must be cleaned up on destruction');
        self::assertFileDoesNotExist($keyFile, 'the private-key temp file must be cleaned up on destruction');
    }
}
