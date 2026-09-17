<?php

declare(strict_types=1);

namespace Axiam\Sdk\Mcp;

/**
 * What {@see Mcp::protectedResourceMetadata()} returns: the RFC 9728 §2 document, the
 * path it is served at, and the URL that path resolves to (CONTRACT.md §28.1).
 *
 * {@see self::$metadataUrl} exists so the guard's `resourceMetadataUrl` option
 * (CONTRACT.md §28.5) is fed from the value this class derived rather than retyped —
 * retyping is how the two come to disagree, and a challenge pointing at a document that
 * is not this resource server's is worse than no challenge at all.
 */
final class ProtectedResourceMetadata
{
    /**
     * @param array<string,mixed> $document The RFC 9728 §2 document, carrying **at most**
     *        the five members CONTRACT.md §28.2 permits, in that fixed order, and no
     *        others. Ready to `json_encode()` as-is — member order is PHP array
     *        insertion order, and `json_encode()` preserves it.
     * @param string $metadataPath The absolute path the document is served at, derived
     *        from `resource` per CONTRACT.md §28.3 — never chosen.
     * @param string $metadataUrl {@see self::$metadataPath} resolved against the
     *        resource's scheme and authority. Feed this to the guard's
     *        `resourceMetadataUrl` option.
     */
    public function __construct(
        public readonly array $document,
        public readonly string $metadataPath,
        public readonly string $metadataUrl,
    ) {
    }
}
