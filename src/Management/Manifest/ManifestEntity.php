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
     */
    public function __construct(
        public readonly ManifestKind $kind,
        public readonly string $key,
        public readonly string $name,
        public readonly array $fields = [],
        public readonly array $depends = [],
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
     * @param array<string,mixed> $existing The server's current object.
     * @return array<string,mixed> The drifted fields and their DESIRED values; empty when converged.
     */
    public function drift(array $existing): array
    {
        $drifted = [];
        foreach ($this->fields as $wire => $desired) {
            if (!array_key_exists($wire, $existing) || $existing[$wire] !== $desired) {
                $drifted[$wire] = $desired;
            }
        }

        return $drifted;
    }
}
