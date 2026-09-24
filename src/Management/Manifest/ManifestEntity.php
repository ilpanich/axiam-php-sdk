<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management\Manifest;

/**
 * One entity a §27.6 manifest declares must exist.
 *
 * Entities are addressed by a manifest-local `$key`, never by a server-assigned UUID.
 * That is what lets the same manifest run against a fresh tenant and an existing one and
 * mean the same thing (§27.6: a plan must be STABLE ACROSS RUNS) — a UUID does not exist
 * until the first apply, so a manifest written in terms of UUIDs could only ever describe
 * a tenant that already matched it.
 */
final class ManifestEntity
{
    /**
     * @param ManifestKind        $kind    What sort of object this is.
     * @param string              $key     Manifest-local identity, unique within its kind.
     * @param string              $name    The name the server knows it by; also how an
     *                                     existing object is matched to this declaration.
     * @param array<string,mixed> $fields  Desired field values, by wire name.
     * @param list<string>        $depends Keys of entities that must be applied first,
     *                                     beyond what {@see ManifestKind} already orders.
     * @param array<string,ManifestKind> $expectedKinds CONTRACT 1.52 N6.6 (C-12):
     *        for a `$depends` entry that names another entity BY KIND (a resource's
     *        parent, a binding's role or resource) — maps that dependency's KEY to the
     *        kind it must resolve to, so {@see ManifestValidation} can refuse a
     *        same-named entity of the WRONG kind as a dangling reference instead of
     *        silently accepting it. A `$depends` entry with no matching key here (the
     *        default, `[]`) falls back to matching any kind — the pre-N6.6 behavior,
     *        so a `ManifestEntity` built by hand (bypassing {@see ManifestBuilder}, as
     *        some tests do) keeps working exactly as before.
     */
    public function __construct(
        public readonly ManifestKind $kind,
        public readonly string $key,
        public readonly string $name,
        public readonly array $fields = [],
        public readonly array $depends = [],
        public readonly array $expectedKinds = [],
    ) {
    }

    /**
     * The fields of `$existing` that disagree with this declaration.
     *
     * Compares ONLY the fields the manifest names. A server object carries plenty this
     * manifest says nothing about — timestamps, ids, fields set by another operator — and
     * treating those as drift would make every plan report a change and every apply
     * overwrite work the manifest never claimed.
     *
     * CONTRACT 1.52 N6.5 (C-12): compared as JSON VALUES, independent of key order — a
     * `metadata` object the server echoes back with its keys in a different order than
     * this manifest declared them is NOT drift. {@see self::jsonValueEquals()} does the
     * comparison; a JSON ARRAY's element order still matters (order is significant for
     * a list, never for an object), only an object's key order is ignored.
     *
     * @param array<string,mixed> $existing The server's current object.
     * @return array<string,mixed> The drifted fields and their DESIRED values; empty when converged.
     */
    public function drift(array $existing): array
    {
        $drifted = [];
        foreach ($this->fields as $wire => $desired) {
            if (!array_key_exists($wire, $existing) || !self::jsonValueEquals($existing[$wire], $desired)) {
                $drifted[$wire] = $desired;
            }
        }

        return $drifted;
    }

    /**
     * JSON value equality (CONTRACT 1.52 N6.5, C-12): recursively equal, treating a PHP
     * list array (`array_is_list()`) as a JSON array — where element ORDER is
     * significant — and every other PHP array as a JSON object, where KEY order is not.
     * Scalars compare with `===`, so a type difference (e.g. `"1"` vs `1`) still counts
     * as drift exactly as the old `!==` comparison did; only an object's key order stops
     * mattering.
     */
    private static function jsonValueEquals(mixed $a, mixed $b): bool
    {
        if (!\is_array($a) || !\is_array($b)) {
            return $a === $b;
        }

        if (array_is_list($a) || array_is_list($b)) {
            if (!array_is_list($a) || !array_is_list($b) || \count($a) !== \count($b)) {
                return false;
            }
            foreach ($a as $index => $value) {
                if (!self::jsonValueEquals($value, $b[$index])) {
                    return false;
                }
            }

            return true;
        }

        if (\count($a) !== \count($b)) {
            return false;
        }
        foreach ($a as $key => $value) {
            if (!\array_key_exists($key, $b) || !self::jsonValueEquals($value, $b[$key])) {
                return false;
            }
        }

        return true;
    }
}
