<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Management\ValidationError;
use Axiam\Sdk\Oidc\CibaRequestSigner;
use Axiam\Sdk\Oidc\CibaSigningAlg;
use PHPUnit\Framework\TestCase;

/**
 * The README's conformance statement against the code (CONTRACT.md Conformance Statement).
 *
 * R-32 (contract 1.59, §34.2 P12.7): an SDK that signs the §33.2 request with a subset of
 * `PS256`, `ES256` and `EdDSA` names the subset in its claim — "§33.2 signed (ES256, EdDSA)";
 * "§33.2 signed" alone means all three, which this SDK does not ship.
 */
final class ConformanceStatementTest extends TestCase
{
    private static function readme(): string
    {
        $readme = file_get_contents(\dirname(__DIR__) . '/README.md');
        self::assertIsString($readme);

        return $readme;
    }

    /** The paragraph under "## Contract conformance" that states the claim. */
    private static function statement(): string
    {
        $readme = self::readme();
        $start = strpos($readme, "## Contract conformance\n");
        self::assertIsInt($start, 'the README has a conformance section');
        $body = substr($readme, $start);
        $end = strpos($body, "\n\n", strlen("## Contract conformance\n\n"));

        return substr($body, 0, $end === false ? null : $end);
    }

    public function testTheSignedFormClaimNamesTheAlgorithmSubset(): void
    {
        $statement = self::statement();
        self::assertStringContainsString('§33.2 signed (ES256, EdDSA)', $statement);

        // Nowhere does the README claim "§33.2 signed" bare, which would mean all three.
        $readme = self::readme();
        $offset = 0;
        while (($at = strpos($readme, '§33.2 signed', $offset)) !== false) {
            self::assertSame(
                '§33.2 signed (ES256, EdDSA)',
                substr($readme, $at, strlen('§33.2 signed (ES256, EdDSA)')),
                'a bare "§33.2 signed" claims PS256 too: ' . substr($readme, max(0, $at - 40), 100),
            );
            $offset = $at + 1;
        }
    }

    /** The subset the claim names is the subset the signer accepts: PS256 is refused locally. */
    public function testTheAlgorithmTheClaimLeavesOutIsRefusedLocally(): void
    {
        $claimed = ['ES256', 'EdDSA'];
        $missing = array_values(array_diff(array_map(static fn (CibaSigningAlg $a): string => $a->value, CibaSigningAlg::cases()), $claimed));
        self::assertSame(['PS256'], $missing);

        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($key);
        $pem = '';
        self::assertTrue(openssl_pkey_export($key, $pem));
        $this->expectException(ValidationError::class);
        CibaRequestSigner::fromPem(CibaSigningAlg::PS256, new Sensitive($pem));
    }
}
