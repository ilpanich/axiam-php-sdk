<?php

declare(strict_types=1);

/**
 * Regenerates the committed protobuf message stubs in src/Grpc/Gen/ from proto/.
 *
 * PHP is the one AXIAM SDK that does not use buf: buf's PHP plugin support never
 * covered the `php_namespace` handling this SDK depends on (D-03), so the stubs are
 * produced by a plain `protoc --php_out` and committed to the repository. Committing
 * them is what lets `composer require axiam/axiam-sdk` work with no protoc toolchain
 * on the consumer's machine, and what lets the gRPC transport stay a `suggest` rather
 * than a hard dependency.
 *
 * The relocation step below is not incidental. protoc's PHP generator derives the
 * output directory from the .proto's `php_namespace` option (Axiam\Sdk\Grpc\Gen), so
 * it ALWAYS writes to <out>/Axiam/Sdk/Grpc/Gen/** — there is no protoc flag that
 * collapses that prefix. Pointing --php_out straight at src/ would therefore produce
 * src/Axiam/Sdk/Grpc/Gen/, which is not the PSR-4 path (Axiam\Sdk\ maps to src/).
 * So: generate into build/, then lift the namespace subtree onto src/Grpc/Gen/.
 *
 * No grpc_php_plugin is required — only the message classes are generated. The
 * service client (src/Grpc/AuthzGrpcClient.php) is hand-written against
 * \Grpc\BaseStub.
 *
 * Usage: composer grpc-gen   (or: php tools/grpc-gen.php)
 */

const PROTO_FILE = 'axiam/v1/authorization.proto';
const BUILD_DIR = 'build/grpc-gen';
const NAMESPACE_PREFIX = 'Axiam/Sdk/Grpc/Gen';
const TARGET_DIR = 'src/Grpc/Gen';

chdir(dirname(__DIR__));

if (!is_file('proto/' . PROTO_FILE)) {
    fwrite(STDERR, sprintf("grpc-gen: proto/%s not found\n", PROTO_FILE));
    exit(1);
}

$protoc = trim((string) shell_exec('command -v protoc 2>/dev/null'));
if ($protoc === '') {
    fwrite(STDERR, "grpc-gen: protoc is not on PATH — install protobuf-compiler and retry\n");
    exit(1);
}

if (!is_dir(BUILD_DIR) && !mkdir(BUILD_DIR, 0o777, true) && !is_dir(BUILD_DIR)) {
    fwrite(STDERR, sprintf("grpc-gen: could not create %s\n", BUILD_DIR));
    exit(1);
}

$command = sprintf(
    '%s --proto_path=proto --php_out=%s %s 2>&1',
    escapeshellarg($protoc),
    escapeshellarg(BUILD_DIR),
    escapeshellarg(PROTO_FILE)
);

exec($command, $output, $status);
if ($status !== 0) {
    fwrite(STDERR, "grpc-gen: protoc failed:\n" . implode("\n", $output) . "\n");
    exit(1);
}

$generated = BUILD_DIR . '/' . NAMESPACE_PREFIX;
if (!is_dir($generated)) {
    fwrite(STDERR, sprintf("grpc-gen: protoc produced no %s — has php_namespace changed?\n", $generated));
    exit(1);
}

$entries = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($generated, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::SELF_FIRST
);

$copied = 0;
foreach ($entries as $entry) {
    /** @var SplFileInfo $entry */
    $target = TARGET_DIR . '/' . substr($entry->getPathname(), strlen($generated) + 1);

    if ($entry->isDir()) {
        if (!is_dir($target) && !mkdir($target, 0o777, true) && !is_dir($target)) {
            fwrite(STDERR, sprintf("grpc-gen: could not create %s\n", $target));
            exit(1);
        }
        continue;
    }

    if (!copy($entry->getPathname(), $target)) {
        fwrite(STDERR, sprintf("grpc-gen: could not write %s\n", $target));
        exit(1);
    }
    ++$copied;
}

printf("Regenerated %d stub(s) in %s from proto/%s\n", $copied, TARGET_DIR, PROTO_FILE);
printf("Review `git diff %s` before committing — protoc's output varies by compiler version.\n", TARGET_DIR);
exit(0);
