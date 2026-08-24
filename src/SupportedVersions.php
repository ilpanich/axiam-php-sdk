<?php

declare(strict_types=1);

namespace Axiam\Sdk;

/**
 * The range of PHP versions this SDK is built and tested against.
 *
 * Composer already enforces the lower bound at install time via the `php`
 * constraint in the SDK's `composer.json`, but that constraint is awkward to
 * read back at run time — it lives in the installed package's manifest under
 * `vendor/`, not in any API — and it says nothing at all about the upper end.
 * These constants are the readable half, so a deployment preflight or a
 * startup assertion can report the range without hardcoding numbers that go
 * stale.
 *
 * The SDK is *built* against {@see self::MIN_PHP} and additionally *tested*
 * against {@see self::NEWEST_TESTED_PHP}; every release between the two is
 * supported and sits between two green CI legs.
 *
 * `tests/VersionPolicyTest.php` asserts both values against `composer.json`
 * and the CI matrix respectively, so neither can drift from what is actually
 * published and executed.
 *
 * @see https://github.com/ilpanich/axiam-php-sdk#supported-php-versions
 */
final class SupportedVersions
{
    /**
     * The minimum PHP version, as `major.minor`.
     *
     * Mirrors the `php` constraint in `composer.json`. This is the version the
     * SDK is compiled and tested against, and the one Composer refuses to
     * install below.
     */
    public const MIN_PHP = '8.2';

    /**
     * The newest PHP version the SDK has a green build against, as `major.minor`.
     *
     * Mirrors the upper leg of the CI matrix. A runtime newer than this is
     * expected to work — the SDK uses no version-gated syntax beyond the floor
     * — but is not yet proven by a build.
     */
    public const NEWEST_TESTED_PHP = '8.5';

    /**
     * Not instantiable: this is a namespace for constants, not a value type.
     */
    private function __construct()
    {
    }
}
