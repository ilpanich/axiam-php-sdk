<?php

declare(strict_types=1);

namespace Axiam\Sdk\Management;

use Axiam\Sdk\Management\Models\DirectoryConfig;
use Axiam\Sdk\Management\Models\SamlServiceProvider;
use Axiam\Sdk\Management\Models\SamlServiceProviderInput;
use Axiam\Sdk\Management\Models\ScimTargetInput;
use Axiam\Sdk\Management\Models\ScimTargetResponse;
use Axiam\Sdk\Management\Models\SetDirectoryConfig;
use Axiam\Sdk\Management\Models\SsfStream;
use Axiam\Sdk\Management\Models\SsfStreamInput;

/**
 * The read-modify-write form CONTRACT.md §27.4 rule 5 recommends for `replace` updates: a
 * read result turned back into the replacement body, every member carried over, so that
 * changing one field and sending the body back preserves the rest instead of resetting
 * every omitted member to its default.
 *
 * ```php
 * $sp = $client->saml()->getServiceProvider($id);
 * $body = ReadModifyWrite::samlServiceProvider($sp, ['display_name' => 'Payroll (EU)']);
 * $client->saml()->updateServiceProvider($id, $body);
 * ```
 *
 * **No secret is ever carried over**, because no read carries one: the directory's
 * `bindSecret`, a SCIM target's `credential` and an SSF stream's `authorizationHeader` come
 * back absent, which on each of those updates means "keep the stored one" — except where
 * the update moves the connection, which then requires the secret again (§30.3 rule 2,
 * §31.3 rule 2, §32.3 rule 5). Pass it explicitly in that case, as a change.
 *
 * Each helper takes the changes to make as `$changes`, keyed by the WIRE member name (the
 * same names `toArray()` renders), applied over the read before the body is rebuilt — the
 * generated bodies are immutable, so this is where a field gets changed. A secret given in
 * `$changes` (`bind_secret`, `credential`, `authorization_header`) may be given as a string
 * or as a {@see \Axiam\Sdk\Core\Sensitive}; the body holds it wrapped either way.
 */
final class ReadModifyWrite
{
    /**
     * `saml.update_service_provider`'s body from a `getServiceProvider()` result.
     *
     * @param array<string,mixed> $changes Wire members to change, applied over the read.
     */
    public static function samlServiceProvider(SamlServiceProvider $sp, array $changes = []): SamlServiceProviderInput
    {
        $body = new SamlServiceProviderInput(
            acsUrls: $sp->acsUrls,
            displayName: $sp->displayName,
            entityId: $sp->entityId,
            allowIdpInitiated: $sp->allowIdpInitiated,
            allowedGroups: $sp->allowedGroups,
            attributeMappings: $sp->attributeMappings,
            enabled: $sp->enabled,
            encryptAssertions: $sp->encryptAssertions,
            nameIdFormat: $sp->nameIdFormat,
            signResponses: $sp->signResponses,
            sloBinding: $sp->sloBinding,
            sloUrl: $sp->sloUrl,
            spEncryptionCertPem: $sp->spEncryptionCertPem,
            spSigningCertPem: $sp->spSigningCertPem,
            wantAuthnRequestsSigned: $sp->wantAuthnRequestsSigned,
        );

        return $changes === [] ? $body : SamlServiceProviderInput::fromArray(self::apply($body->jsonSerialize(), $changes));
    }

    /**
     * `ssf.update_stream`'s body from a `getStream()` result and **the changes to make to it**
     * — the change-taking form of CONTRACT.md §32.2 (contract 1.62). `authorizationHeader` and
     * `clearAuthorizationHeader` are left absent: absent keeps the stored header.
     *
     * ```php
     * $stream = $client->ssf()->getStream($id);
     * $client->ssf()->updateStream($id, ReadModifyWrite::ssfStream($stream, [
     *     'events_allowed' => [SsfEventTypes::SESSION_REVOKED],   // lower the ceiling
     * ]));
     * ```
     *
     * What the body carries, and why each point is a rule rather than a convenience:
     *
     * - **`events_requested`, as read.** An update that omits it **resets** the stream to every
     *   event of `events_allowed`, widening what the receiver narrowed, and AXIAM then sends the
     *   receiver more events about the tenant's users than it asked for. The read list goes back
     *   as it was; an `[]` (the receiver's "none") goes back as `[]` and is never omitted.
     * - **Cut to the new ceiling.** When `$changes` lowers `events_allowed` and does not name
     *   `events_requested`, the requested list becomes the entries of the read list that are in
     *   the new ceiling, in their order (a request outside the ceiling is `400`). An
     *   `events_requested` named in `$changes` is sent as given: the server judges it.
     * - **`expected_updated_at`, as read.** The `updated_at` string of the stream you read,
     *   byte for byte — not parsed and rendered again, because the comparison is of the
     *   instant and a timestamp rounded to fewer fraction digits than the server stored does
     *   not match. The update then lands only on the version you read, and a write made since
     *   (the receiver's own included) answers `409` (a {@see ConflictError}, never retried):
     *   read again and decide again. `expected_updated_at => null` in `$changes` is "none": the
     *   key is left out of the body and `null` is never sent, which replaces whatever is stored.
     *
     * **This is the form to use.** `ssfStream($stream)` with no changes is the plain converter,
     * and it sends the stream back as read. It cannot know that the caller is about to lower
     * the ceiling, so **cutting `events_requested` to the new `events_allowed` is the caller's
     * duty wherever a body is built another way** (`SsfStreamInput::fromArray()` over a
     * hand-edited array, a constructor call): a requested list left outside the new ceiling is
     * `400`, and one left out altogether resets the stream (the three meanings of
     * `events_requested`, §32.2; an update conditional on the version read is `409` once the
     * stream changes under it).
     *
     * @param array<string,mixed> $changes Wire members to change, applied over the read.
     */
    public static function ssfStream(SsfStream $stream, array $changes = []): SsfStreamInput
    {
        $body = new SsfStreamInput(
            audience: $stream->audience,
            deliveryMethod: $stream->deliveryMethod,
            eventsAllowed: $stream->eventsAllowed,
            receiverClientId: $stream->receiverClientId,
            description: $stream->description,
            endpointUrl: $stream->endpointUrl,
            eventsRequested: $stream->eventsRequested,
            expectedUpdatedAt: $stream->updatedAt,
            status: $stream->status,
            statusReason: $stream->statusReason,
            subjectFormat: $stream->subjectFormat,
        );

        if ($changes === []) {
            return $body;
        }
        $merged = self::apply($body->jsonSerialize(), $changes);
        if (array_key_exists('events_allowed', $changes) && !array_key_exists('events_requested', $changes)) {
            $ceiling = array_map(
                static fn (mixed $v): string => $v instanceof \BackedEnum ? (string) $v->value : (string) $v,
                (array) $changes['events_allowed'],
            );
            $merged['events_requested'] = array_values(array_filter(
                (array) ($merged['events_requested'] ?? []),
                static fn (mixed $v): bool => in_array((string) $v, $ceiling, true),
            ));
        }

        return SsfStreamInput::fromArray($merged);
    }

    /**
     * `scim_targets.update`'s body from a `get()` result. `credential` is left absent:
     * absent keeps the stored one, unless the write moves its URL (§31.3 rule 2).
     * `expected_updated_at` is the read's `updated_at`, so the replacement lands only on the
     * version that was read and an edit made since answers `409` instead of being overwritten
     * (§31.3 rule 4, contract 1.60); reload and retry. Pass `expected_updated_at` in `$changes`
     * to send another value.
     *
     * @param array<string,mixed> $changes Wire members to change, applied over the read.
     */
    public static function scimTarget(ScimTargetResponse $target, array $changes = []): ScimTargetInput
    {
        $body = new ScimTargetInput(
            auth: $target->auth,
            baseUrl: $target->baseUrl,
            name: $target->name,
            scope: $target->scope,
            deprovision: $target->deprovision,
            enabled: $target->enabled,
            expectedUpdatedAt: $target->updatedAt,
            pushGroups: $target->pushGroups,
            userNameFrom: $target->userNameFrom,
        );

        return $changes === [] ? $body : ScimTargetInput::fromArray(self::apply($body->jsonSerialize(), $changes));
    }

    /**
     * `directory.set`'s body from a `get()` result. `bindSecret` is left absent: absent keeps
     * the stored secret, unless the write moves the connection (§30.3 rule 2).
     *
     * @param array<string,mixed> $changes Wire members to change, applied over the read.
     */
    public static function directoryConfig(DirectoryConfig $config, array $changes = []): SetDirectoryConfig
    {
        $body = new SetDirectoryConfig(
            baseDn: $config->baseDn,
            bindDn: $config->bindDn,
            enabled: $config->enabled,
            kind: $config->kind,
            startTls: $config->startTls,
            url: $config->url,
            userFilter: $config->userFilter,
            groupBaseDn: $config->groupBaseDn,
            groupFilter: $config->groupFilter,
            groupMappings: $config->groupMappings,
            groupMemberAttribute: $config->groupMemberAttribute,
            groupNestingDepth: $config->groupNestingDepth,
            jitProvisioning: $config->jitProvisioning,
            syncIntervalSecs: $config->syncIntervalSecs,
            trustAnchorsPem: $config->trustAnchorsPem,
            userAttributeMap: $config->userAttributeMap,
        );

        return $changes === [] ? $body : SetDirectoryConfig::fromArray(self::apply($body->jsonSerialize(), $changes));
    }

    /**
     * `$changes` over `$read`, with any {@see \Axiam\Sdk\Core\Sensitive} change unwrapped so
     * the body's decoder re-wraps the real value (a cast of the wrapper would be the literal
     * `[SENSITIVE]`).
     *
     * @param array<string,mixed> $read
     * @param array<string,mixed> $changes
     * @return array<string,mixed>
     */
    private static function apply(array $read, array $changes): array
    {
        foreach ($changes as $key => $value) {
            $read[$key] = $value instanceof \Axiam\Sdk\Core\Sensitive ? $value->reveal() : $value;
        }

        return $read;
    }
}
