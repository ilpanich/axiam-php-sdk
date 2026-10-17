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
     * @param list<string> $setFields CONTRACT 1.62 (§27.6.2 item 3): wire names of
     *        list-valued fields compared as a SET — the same names in another order are no
     *        drift (`network` segments' `filter_ids`). Every other list keeps its order.
     * @param string|null $segment A `network_profile`'s segment: the manifest-local KEY of
     *        the `network_segment` it belongs to. Kept apart from `$depends` on purpose — the
     *        profile's own key IS its segment's, and a dependency edge from a key to itself
     *        would be read as a cycle.
     */
    public function __construct(
        public readonly ManifestKind $kind,
        public readonly string $key,
        public readonly string $name,
        public readonly array $fields = [],
        public readonly array $depends = [],
        public readonly array $expectedKinds = [],
        public readonly array $setFields = [],
        public readonly ?string $segment = null,
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
     * CONTRACT 1.62 (§27.6.2): a field stated as PHP `null` is "none" — it drifts when the
     * server holds a value and not when the server holds none or omits the member — and a
     * field named in `$setFields` is compared as a set.
     *
     * @param array<string,mixed> $existing The server's current object.
     * @return array<string,mixed> The drifted fields and their DESIRED values; empty when converged.
     */
    public function drift(array $existing): array
    {
        $drifted = [];
        foreach ($this->fields as $wire => $desired) {
            $present = array_key_exists($wire, $existing);
            if ($desired === null) {
                if ($present && $existing[$wire] !== null) {
                    $drifted[$wire] = $desired;
                }
            } elseif (!$present) {
                $drifted[$wire] = $desired;
            } elseif (\in_array($wire, $this->setFields, true)) {
                if (!self::setEquals($existing[$wire], $desired)) {
                    $drifted[$wire] = $desired;
                }
            } elseif (!self::jsonValueEquals($existing[$wire], $desired)) {
                $drifted[$wire] = $desired;
            }
        }

        return $drifted;
    }

    /**
     * Two lists equal as SETS of exact strings: order and repetition do not count
     * (CONTRACT 1.62, §27.6.2 item 3 — `filter_ids`). Anything that is not a list of strings
     * on both sides falls back to strict value equality.
     */
    private static function setEquals(mixed $a, mixed $b): bool
    {
        if (!\is_array($a) || !\is_array($b)) {
            return $a === $b;
        }
        $normalise = static function (array $list): ?array {
            $out = [];
            foreach ($list as $value) {
                if (!\is_string($value)) {
                    return null;
                }
                $out[$value] = true;
            }
            $names = array_map('strval', array_keys($out));
            sort($names, SORT_STRING);

            return $names;
        };
        $left = $normalise($a);
        $right = $normalise($b);

        return $left === null || $right === null ? $a === $b : $left === $right;
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
