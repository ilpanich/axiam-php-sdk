<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management;

use Axiam\Sdk\Management\Models\ParseSamlSpMetadata;

/**
 * Local checks the generated §27 surface runs before any I/O (generator table `PRECHECKS`).
 *
 * Only where the contract requires the SDK itself to refuse: everything else is the server's
 * to validate (§27.4 rule 4's reason — a client-side copy of a server rule drifts). Nothing
 * here performs I/O.
 */
final class ManagementChecks
{
    /**
     * CONTRACT.md §29.2: `ParseSamlSpMetadata` is **exactly one** of `metadata_xml` and
     * `metadata_url`. Both or neither is a local {@see ValidationError}, raised before any
     * request — never a request the server refuses.
     *
     * @throws ValidationError when both or neither is set.
     */
    public static function parseSpMetadataExactlyOne(ParseSamlSpMetadata $body): void
    {
        $xml = $body->metadataXml !== null;
        $url = $body->metadataUrl !== null;
        if ($xml === $url) {
            $why = $xml
                ? 'set exactly one of metadata_xml and metadata_url, not both'
                : 'set exactly one of metadata_xml and metadata_url';
            throw new ValidationError(
                sprintf('saml.parse_sp_metadata: %s (CONTRACT.md §29.2)', $why),
                [new FieldError($xml ? 'metadata_xml' : 'metadata_url', $why)],
            );
        }
    }
}
