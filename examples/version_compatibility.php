<?php

declare(strict_types=1);

/**
 * examples/version_compatibility.php — reports the running PHP runtime against the
 * range of versions this SDK is built and tested against.
 *
 * The SDK is *built* against its floor (the oldest PHP still receiving security
 * fixes) and additionally *tested* against the newest release, so any runtime
 * between the two is covered by a green CI leg. Composer enforces the lower end at
 * install time via the `php` constraint — but only at install time, and it is
 * routinely bypassed: `--ignore-platform-reqs` in a Dockerfile, a `config.platform`
 * override pinned to a version the image does not actually run, or a `vendor/`
 * directory built on one runtime and deployed onto another. In each of those cases
 * the mismatch surfaces as a parse error at the first request, not at deploy.
 *
 * `Axiam\Sdk\SupportedVersions` exposes the range so a preflight can assert it,
 * rather than restating numbers that go stale.
 *
 * Run: php examples/version_compatibility.php
 * (this example is illustrative and self-contained — it needs no AXIAM server, no
 * network, and no configuration.)
 */

require __DIR__ . '/../vendor/autoload.php';

use Axiam\Sdk\SupportedVersions;

/**
 * Compare two `major.minor` strings.
 *
 * @return int negative, zero or positive, like the spaceship operator
 */
function compareMajorMinor(string $a, string $b): int
{
    $pa = array_map('intval', explode('.', $a));
    $pb = array_map('intval', explode('.', $b));

    return [$pa[0], $pa[1] ?? 0] <=> [$pb[0], $pb[1] ?? 0];
}

$running = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;

printf("running PHP:        %s (%s)%s", PHP_VERSION, PHP_BINARY, PHP_EOL);
printf("SDK minimum PHP:    %s%s", SupportedVersions::MIN_PHP, PHP_EOL);
printf("newest tested PHP:  %s%s", SupportedVersions::NEWEST_TESTED_PHP, PHP_EOL);

// The extensions that gate optional transports. Neither is required for the REST
// surface, and reporting them here is the other half of a useful preflight: a
// runtime can be perfectly in-range and still be missing the extension that the
// feature you are about to call depends on.
printf(
    "ext-ffi (OPAQUE):   %s%s",
    extension_loaded('ffi') ? 'present' : 'absent — §23 OPAQUE login unavailable',
    PHP_EOL,
);
printf(
    "ext-grpc:           %s%s",
    extension_loaded('grpc') ? 'present' : 'absent — authz falls back to REST',
    PHP_EOL,
);

if (compareMajorMinor($running, SupportedVersions::MIN_PHP) < 0) {
    // Composer would have refused this install; reaching here means it was
    // bypassed or the vendor tree was built elsewhere.
    fprintf(
        STDERR,
        'UNSUPPORTED: PHP %s is below the %s floor. The SDK is not built against '
        . 'it and may fail to parse.%s',
        $running,
        SupportedVersions::MIN_PHP,
        PHP_EOL,
    );
    exit(1);
}

if (compareMajorMinor($running, SupportedVersions::NEWEST_TESTED_PHP) > 0) {
    // Not an error. The SDK uses no syntax beyond its floor, so a newer runtime
    // is expected to work — it simply has no green build behind it yet.
    printf(
        'UNTESTED: PHP %s is newer than %s, the newest release this SDK has a '
        . 'green build against. Expected to work, but not yet proven.%s',
        $running,
        SupportedVersions::NEWEST_TESTED_PHP,
        PHP_EOL,
    );
    exit(0);
}

printf('SUPPORTED: PHP %s is inside the tested range.%s', $running, PHP_EOL);
