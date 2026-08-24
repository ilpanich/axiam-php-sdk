<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\SupportedVersions;
use PHPUnit\Framework\TestCase;

/**
 * Language-version support policy.
 *
 * "Which PHP does this SDK support?" is declared in two places, and nothing
 * compares them:
 *
 * 1. the `php` constraint in `composer.json` — what Composer enforces at
 *    install time, and the only one that can refuse an install;
 * 2. the `php` matrix in `.github/workflows/sdk-ci-php.yml` — the only one
 *    that is ever executed.
 *
 * They did not merely drift here, they were **incompatible by construction**.
 * The package declared `php: >=8.1` while CI could only ever run 8.2, because
 * the require-dev framework bridges (`illuminate/support` ^11, `symfony/*` ^7)
 * themselves require PHP ^8.2 — so `composer install` was unsatisfiable on the
 * declared floor and the job died before running a single test. The floor was
 * advertised to every Packagist consumer and had never been executed once.
 *
 * The policy pinned here is floor + newest: the gating matrix runs exactly the
 * two ends of the supported range, and the low end is the constraint
 * `composer.json` actually publishes.
 */
final class VersionPolicyTest extends TestCase
{
    /** Repository root, from this file's location. */
    private static function repoRoot(): string
    {
        return \dirname(__DIR__);
    }

    /**
     * The `>=X.Y` floor from composer.json's `require.php`.
     *
     * @return array{int, int} major, minor
     */
    private static function declaredFloor(): array
    {
        $raw = file_get_contents(self::repoRoot() . '/composer.json');
        self::assertIsString($raw, 'composer.json is unreadable');

        /** @var array{require?: array{php?: string}} $manifest */
        $manifest = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
        $constraint = $manifest['require']['php'] ?? null;

        self::assertIsString($constraint, 'composer.json declares no require.php');
        self::assertSame(
            1,
            preg_match('/^>=\s*(\d+)\.(\d+)$/', trim($constraint), $m),
            sprintf(
                'require.php is "%s", which this policy test cannot interpret. The '
                . 'support policy is a single inclusive floor (">=X.Y"); if that has '
                . 'deliberately changed, update this test rather than the pattern.',
                $constraint,
            ),
        );

        return [(int) $m[1], (int) $m[2]];
    }

    /**
     * The `php: ['8.2', '8.5']` list from the CI build-test matrix, ascending.
     *
     * @return list<array{int, int}>
     */
    private static function ciMatrix(): array
    {
        $raw = file_get_contents(
            self::repoRoot() . '/.github/workflows/sdk-ci-php.yml',
        );
        self::assertIsString($raw, 'sdk-ci-php.yml is unreadable');

        $found = preg_match_all('/^\s*php:\s*\[([^\]]*)\]\s*$/m', $raw, $m);
        self::assertSame(
            1,
            $found,
            'expected exactly one `php:` matrix in sdk-ci-php.yml; a second would '
            . 'mean this test only checks one of them',
        );

        $versions = [];
        foreach (explode(',', $m[1][0]) as $entry) {
            $entry = trim($entry, " \t'\"");
            if ($entry === '') {
                continue;
            }
            $parts = explode('.', $entry);
            $versions[] = [(int) $parts[0], (int) ($parts[1] ?? 0)];
        }
        usort($versions, static fn (array $a, array $b): int => $a <=> $b);

        return $versions;
    }

    private static function fmt(array $v): string
    {
        return $v[0] . '.' . $v[1];
    }

    /**
     * End-of-life dates for the PHP release lines this policy can reason about.
     *
     * Published at https://www.php.net/supported-versions.php. A hardcoded
     * table needs occasional maintenance, but the alternative — a
     * greater-than-or-equal against a number someone typed once — silently
     * stops meaning anything the day that number goes out of support, which is
     * exactly how `>=8.1` survived here past 2025-12-31.
     *
     * @var array<string, string>
     */
    private const PHP_EOL_DATES = [
        '8.1' => '2025-12-31',
        '8.2' => '2026-12-31',
        '8.3' => '2027-12-31',
        '8.4' => '2028-12-31',
        '8.5' => '2029-12-31',
    ];

    /**
     * The declared floor is a PHP version that still receives security fixes.
     *
     * This fails on the date the floor goes out of support, not whenever
     * somebody next thinks to look. 8.1 reached end of life on 2025-12-31, and
     * this is the assertion that would have caught the `>=8.1` the package
     * shipped with — as it does today, six months late.
     */
    public function testFloorStillReceivesSecurityFixes(): void
    {
        $floor = self::fmt(self::declaredFloor());

        self::assertArrayHasKey(
            $floor,
            self::PHP_EOL_DATES,
            sprintf(
                'PHP %s has no end-of-life date in this test\'s table. Add it from '
                . 'https://www.php.net/supported-versions.php rather than removing '
                . 'the check.',
                $floor,
            ),
        );

        $eol = strtotime(self::PHP_EOL_DATES[$floor] . ' 23:59:59 UTC');
        self::assertIsInt($eol);
        self::assertGreaterThan(
            time(),
            $eol,
            sprintf(
                'the declared floor, PHP %s, reached end of life on %s and no longer '
                . 'receives security fixes. Raise require.php in composer.json, the CI '
                . 'matrix floor and SupportedVersions::MIN_PHP together.',
                $floor,
                self::PHP_EOL_DATES[$floor],
            ),
        );
    }

    /**
     * CI runs the floor, so the published constraint is a promise something keeps.
     *
     * This is the failure the old configuration could never surface: a floor
     * that `composer install` cannot even satisfy is never executed, and
     * nothing says so.
     */
    public function testCiBuildsTheDeclaredFloor(): void
    {
        $floor = self::declaredFloor();
        self::assertContains(
            $floor,
            self::ciMatrix(),
            sprintf(
                'composer.json publishes php >=%s but no CI leg runs it',
                self::fmt($floor),
            ),
        );
    }

    /** The gating matrix is the two ends of the range — not a subset, not all of it. */
    public function testCiMatrixIsFloorAndNewest(): void
    {
        $matrix = self::ciMatrix();
        self::assertCount(
            2,
            $matrix,
            'expected exactly 2 CI legs (floor + newest), got: '
            . implode(', ', array_map([self::class, 'fmt'], $matrix)),
        );
        self::assertSame(self::declaredFloor(), $matrix[0]);
        self::assertGreaterThan($matrix[0], $matrix[1]);
    }

    /** No CI leg runs a PHP that Composer would refuse to install on. */
    public function testCiNeverRunsBelowTheFloor(): void
    {
        $floor = self::declaredFloor();
        foreach (self::ciMatrix() as $version) {
            self::assertGreaterThanOrEqual(
                $floor,
                $version,
                sprintf(
                    'CI runs PHP %s, below the %s floor',
                    self::fmt($version),
                    self::fmt($floor),
                ),
            );
        }
    }

    /**
     * SupportedVersions::MIN_PHP matches the constraint Composer publishes.
     *
     * It is the only part of the floor a consumer can read from the API, so a
     * stale value is worse than none: a preflight built on it would report a
     * range the installer does not actually enforce.
     */
    public function testMinPhpConstantMatchesComposerJson(): void
    {
        self::assertSame(
            self::fmt(self::declaredFloor()),
            SupportedVersions::MIN_PHP,
            'SupportedVersions::MIN_PHP has drifted from composer.json require.php',
        );
    }

    /** SupportedVersions::NEWEST_TESTED_PHP matches the top CI leg. */
    public function testNewestTestedConstantMatchesTheTopCiLeg(): void
    {
        $matrix = self::ciMatrix();
        self::assertSame(
            self::fmt($matrix[\count($matrix) - 1]),
            SupportedVersions::NEWEST_TESTED_PHP,
            'SupportedVersions::NEWEST_TESTED_PHP claims a version CI does not build',
        );
    }

    /**
     * The interpreter running this suite satisfies the published constraint.
     *
     * Whichever leg CI launched, composer.json covers it — the loop closed
     * from the other direction.
     */
    public function testRunningInterpreterSatisfiesTheFloor(): void
    {
        $floor = self::declaredFloor();
        self::assertGreaterThanOrEqual(
            $floor,
            [\PHP_MAJOR_VERSION, \PHP_MINOR_VERSION],
            sprintf(
                'tests are running on PHP %d.%d, below the %s floor',
                \PHP_MAJOR_VERSION,
                \PHP_MINOR_VERSION,
                self::fmt($floor),
            ),
        );
    }
}
