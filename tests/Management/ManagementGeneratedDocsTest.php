<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Management;

use PHPUnit\Framework\TestCase;

/**
 * R-28 (CONTRACT.md §27.4 rule 5, §29.2; contract 1.59 §34.3): the generated documentation
 * must not contradict the types it documents. Read from the committed output, which
 * `scripts/gen_management.py --check` keeps equal to what the generator writes, so a
 * template that regresses fails here.
 */
final class ManagementGeneratedDocsTest extends TestCase
{
    private static function root(): string
    {
        return \dirname(__DIR__, 2);
    }

    /**
     * The request schemas the registry marks `update_style: sparse` — the only bodies whose
     * unset members are "left unchanged".
     *
     * @return list<string>
     */
    private static function sparseUpdateSchemas(): array
    {
        $registry = json_decode((string) file_get_contents(self::root() . '/management-registry.json'), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($registry);
        $out = [];
        foreach ($registry['namespaces'] as $namespace) {
            foreach ($namespace['operations'] as $op) {
                if (($op['update_style'] ?? null) === 'sparse' && is_string($op['request_schema'] ?? null)) {
                    $out[] = ltrim($op['request_schema'], '[]');
                }
            }
        }

        return array_values(array_unique($out));
    }

    /** @return iterable<string, array{string, \ReflectionClass<object>}> */
    private static function models(): iterable
    {
        foreach (glob(self::root() . '/src/Management/Models/*.php') ?: [] as $file) {
            $name = basename($file, '.php');
            $class = 'Axiam\\Sdk\\Management\\Models\\' . $name;
            if (!class_exists($class)) {
                continue;
            }
            yield $name => [$name, new \ReflectionClass($class)];
        }
    }

    /** "Left unchanged" is said only of a sparse update body; `parse_sp_metadata`'s is not one. */
    public function testOnlyASparseUpdateBodyIsSaidToLeaveUnsetMembersUnchanged(): void
    {
        $sparse = self::sparseUpdateSchemas();
        self::assertContains('UpdateDirectoryConfig', $sparse);
        foreach (self::models() as [$name, $class]) {
            $doc = (string) $class->getDocComment();
            if (str_contains($doc, 'left unchanged') || str_contains($doc, 'SPARSE body')) {
                self::assertContains($name, $sparse, $name . ' is documented as a sparse update body, and is not one');
            }
        }
    }

    /** "Every field is required" is said only of a class whose every field is. */
    public function testAReplacementWithOptionalMembersIsNotSaidToRequireEveryField(): void
    {
        $seen = false;
        foreach (self::models() as [$name, $class]) {
            $doc = (string) $class->getDocComment();
            $constructor = $class->getConstructor();
            if ($constructor === null || !str_contains($doc, 'REPLACEMENT body')) {
                continue;
            }
            $seen = true;
            $optional = array_filter($constructor->getParameters(), static fn (\ReflectionParameter $p): bool => $p->isOptional());
            if ($optional !== []) {
                self::assertStringNotContainsString('every field is required', $doc, $name . ' has optional members');
            }
        }
        self::assertTrue($seen);
    }

    /** No generated operation repeats its request line. */
    public function testNoOperationDocRepeatsItsRequestLine(): void
    {
        foreach (glob(self::root() . '/src/Management/*Api.php') ?: [] as $file) {
            $source = (string) file_get_contents($file);
            preg_match_all('#/\*\*.*?\*/#s', $source, $blocks);
            foreach ($blocks[0] as $block) {
                preg_match_all('#^\s*\*\s*`((?:GET|POST|PUT|PATCH|DELETE) [^`]+)`\.?\s*$#m', $block, $lines);
                self::assertSame(
                    array_values(array_unique($lines[1])),
                    $lines[1],
                    basename($file) . ' documents one request line twice: ' . implode(' | ', $lines[1]),
                );
            }
        }
    }
}
