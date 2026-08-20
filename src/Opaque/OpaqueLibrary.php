<?php

declare(strict_types=1);

namespace Axiam\Sdk\Opaque;

use Axiam\Sdk\Core\NetworkError;

/**
 * Loads `libaxiam_opaque_ffi` once per process, memoizing failure as well as success.
 *
 * Two independent things can be absent, and both are normal:
 *
 *  - **`ext-ffi`.** Not guaranteed on any PHP runtime, and disabled outright on some shared
 *    hosts. A consumer whose tenant does not use OPAQUE should not be obliged to have it.
 *  - **The shared library.** A Rust `cdylib` published as a per-platform asset of the AXIAM
 *    release, not a Composer package — there is no cross-language registry to put it on.
 *
 * Either absence makes {@see Opaque::available()} report `false` rather than throwing, so an
 * application chooses the password path up front instead of discovering the gap mid-login.
 * Memoizing the failure matters as much as memoizing the success: retrying the load on every
 * login is a per-request filesystem walk for a file that is not going to appear.
 */
final class OpaqueLibrary
{
    /** Overrides the search: an absolute path to the shared library. */
    public const PATH_ENV = 'AXIAM_OPAQUE_LIBRARY';

    private static ?OpaqueNativeInterface $library = null;

    private static bool $attempted = false;

    private function __construct()
    {
    }

    /** The library, or `null` when it — or `ext-ffi` — is not present. */
    public static function load(): ?OpaqueNativeInterface
    {
        if (self::$attempted) {
            return self::$library;
        }

        self::$attempted = true;
        foreach (self::candidatePaths() as $path) {
            $native = FfiOpaqueNative::open($path);
            if ($native !== null && $native->available()) {
                self::$library = $native;

                return self::$library;
            }
        }

        return null;
    }

    /**
     * Where to look, most specific first.
     *
     * The environment variable wins when set — the escape hatch for a deployment that ships the
     * artifact somewhere the loader would not look, which is the normal case for a container
     * image carrying it alongside the application rather than installing it system-wide.
     *
     * @return list<string>
     */
    public static function candidatePaths(): array
    {
        $override = getenv(self::PATH_ENV);
        if (\is_string($override) && $override !== '') {
            return [$override];
        }

        // Bare names, so the platform's own loader resolves them from its search
        // path -- PHP's FFI hands the string straight to dlopen/LoadLibrary.
        return match (\PHP_OS_FAMILY) {
            'Darwin' => ['libaxiam_opaque_ffi.dylib'],
            'Windows' => ['axiam_opaque_ffi.dll'],
            default => ['libaxiam_opaque_ffi.so'],
        };
    }

    /**
     * The library, or a refusal naming the artifact.
     *
     * Never an {@see \Axiam\Sdk\Core\AuthError}: absent is a deployment fact, and reporting it as
     * a credential failure would send a user off to reset a password that works.
     */
    public static function require(): OpaqueNativeInterface
    {
        $library = self::load();
        if ($library !== null) {
            return $library;
        }

        $reason = \extension_loaded('ffi')
            ? 'the shared library `libaxiam_opaque_ffi` could not be loaded'
            : 'this PHP runtime has no ext-ffi';

        throw NetworkError::fromMessage(
            'OPAQUE is not available: ' . $reason . '. Enable ext-ffi if it is missing, then ' .
            'download the asset for your platform from the axiam release page and either put it ' .
            'on the system library path or set ' . self::PATH_ENV . ' to its full path.'
        );
    }

    /** Installs a binding, bypassing the loader. Test-only. */
    public static function setForTests(?OpaqueNativeInterface $stub): void
    {
        self::$library = $stub;
        self::$attempted = true;
    }

    /** Forgets the memoized load. Test-only. */
    public static function resetForTests(): void
    {
        self::$library = null;
        self::$attempted = false;
    }
}
