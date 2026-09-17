<?php

declare(strict_types=1);

namespace Axiam\Sdk\Mcp;

use Axiam\Sdk\Management\FieldError;
use Axiam\Sdk\Management\ValidationError;
use Symfony\Component\HttpFoundation\JsonResponse;

/**
 * MCP resource-server helpers (CONTRACT.md §28, RFC 9728 + RFC 6750) — the ONE §28
 * implementation both {@see \Axiam\Sdk\Laravel\AxiamMiddleware} and
 * {@see \Axiam\Sdk\Symfony\AxiamAuthSubscriber} are built on, mirroring how this SDK
 * never duplicates a security-critical decision across its two framework bridges (D-02).
 *
 * §28.0: this SDK implements the RESOURCE SERVER's half and nothing else. AXIAM is the
 * authorization server and implements none of §28; the MCP client's half (parsing a
 * challenge, fetching a document, deciding whether to trust the authorization server it
 * names) is deliberately not in this contract version, for the same reason §20.3 stops
 * at parsing a UMA challenge and goes no further.
 *
 * **No operation here performs network I/O**, so §16 (retry) and §9 (single-flight
 * refresh) do not apply and nothing in this class touches the SDK client's own session.
 * Both operations are pure local computation, like {@see \Axiam\Sdk\Oidc\UmaChallenge::parse()}.
 *
 * **Nothing here is a source of truth about a token.** The document is a claim a
 * resource server publishes about itself; the challenge is a hint it gives a caller that
 * already failed. Whether a request is authorized stays §10's and §11's decision,
 * unchanged and unreachable from here.
 */
final class Mcp
{
    /**
     * RFC 9728 §3.1's well-known prefix — the segment inserted between a resource's
     * authority and its path to reach the document that describes it.
     */
    public const PROTECTED_RESOURCE_METADATA_PREFIX = '/.well-known/oauth-protected-resource';

    /**
     * The three hosts CONTRACT.md §28.2 rule 2 lets an `http` URL use, and the only
     * ones — AXIAM's RFC 8252 §7.3 loopback hosts, reused verbatim. There is
     * deliberately no flag, environment variable or debug build that widens this: a
     * resource server reachable over plaintext on a routable host publishes an
     * identifier an attacker can impersonate.
     *
     * @var list<string>
     */
    private const LOOPBACK_HOSTS = ['127.0.0.1', '[::1]', 'localhost'];

    /** `scheme://authority[path][?query][#fragment]`, matched against the caller's string exactly as given — never `parse_url()`, which normalises. */
    private const ABSOLUTE_URI = '/^([A-Za-z][A-Za-z0-9+.\-]*):\/\/([^\/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/s';

    private function __construct()
    {
    }

    /**
     * `protectedResourceMetadata(...)` (CONTRACT.md §28.1) — build and validate the RFC
     * 9728 protected-resource metadata document this server publishes about itself, and
     * derive the path and URL it is served at.
     *
     * **Validation happens here and it refuses; it never repairs.** Every §28.2 rule is
     * checked before any route exists and before any request is served, and a violation
     * throws {@see ValidationError}. Nothing is normalised, trimmed, lowercased or
     * re-encoded to make it pass: a value that needs adjusting is a configuration
     * mistake an operator fixes in one line, and a helper that quietly fixed it would
     * publish a document describing a resource server that does not exist.
     *
     * **Nothing in the document may come from a request** (§28.2 rule 8). Both
     * `$resource` and `$authorizationServers` are configuration; this method offers no
     * way to build either from a `Host` header, the `Forwarded`/`X-Forwarded-*` family
     * or a request URL, because a document assembled from the request is a document an
     * attacker can point at an authorization server of their choosing — the whole
     * handshake redirected with one header.
     *
     * @param string $resource Absolute URI with a scheme and an authority, no query and
     *        no fragment. `https`, or `http` only on `127.0.0.1`, `[::1]` or
     *        `localhost`. A trailing slash is significant.
     * @param list<string> $authorizationServers The issuer identifiers of the
     *        authorization servers guarding this resource — at least one, each
     *        verbatim, no query, no fragment, no duplicates.
     * @param list<string> $scopesSupported The scope tokens this resource server
     *        understands. Order is preserved, duplicates are refused, and an empty list
     *        omits the member from the document.
     * @param list<string> $bearerMethodsSupported Defaults to `['header']`, the only
     *        accepted value in this contract version.
     * @param string|null $resourceDocumentation Optional documentation page for a
     *        human. May carry a query and a fragment; omitted from the document when
     *        `null`.
     *
     * @throws ValidationError When any CONTRACT.md §28.2 rule is violated.
     */
    public static function protectedResourceMetadata(
        string $resource,
        array $authorizationServers,
        array $scopesSupported = [],
        array $bearerMethodsSupported = ['header'],
        ?string $resourceDocumentation = null,
    ): ProtectedResourceMetadata {
        $op = 'resource';

        // Rule 1 + rule 2.
        $parsedResource = self::requireAbsoluteUri($op, 'resource', $resource, allowQuery: false, allowFragment: false);

        // Rule 3 + rule 4: at least one entry, each an issuer verbatim, no duplicates.
        if ($authorizationServers === []) {
            self::refuse(
                'authorization_servers',
                'must name at least one authorization server — a document that names none answers none of the question the client asked',
            );
        }
        $seenServers = [];
        $normalizedServers = [];
        foreach ($authorizationServers as $entry) {
            self::requireAbsoluteUri($op, 'authorization_servers', $entry, allowQuery: false, allowFragment: false);
            if (isset($seenServers[$entry])) {
                self::refuse('authorization_servers', sprintf('duplicate entry %s', self::quote($entry)));
            }
            $seenServers[$entry] = true;
            $normalizedServers[] = $entry;
        }

        // Rule 5: NQCHAR tokens, order preserved, duplicates refused, empty omits.
        $seenScopes = [];
        $normalizedScopes = [];
        foreach ($scopesSupported as $scope) {
            if (!self::isAll($scope, self::isNqchar(...)) || $scope === '') {
                self::refuse(
                    'scopes_supported',
                    sprintf(
                        "%s is not a scope token — one or more NQCHAR (no space, no '\"', no '\\\\', no control character, no non-ASCII)",
                        self::quote($scope),
                    ),
                );
            }
            if (isset($seenScopes[$scope])) {
                self::refuse('scopes_supported', sprintf('duplicate scope %s', self::quote($scope)));
            }
            $seenScopes[$scope] = true;
            $normalizedScopes[] = $scope;
        }

        // Rule 6: exactly ["header"].
        if ($bearerMethodsSupported !== ['header']) {
            self::refuse(
                'bearer_methods_supported',
                sprintf(
                    "must be exactly [\"header\"] in this contract version — §10's guard reads a bearer credential from the Authorization header alone, so %s would describe behaviour this SDK does not have",
                    self::quoteList($bearerMethodsSupported),
                ),
            );
        }

        // Rule 7: absolute URL, query and fragment permitted, omitted when absent.
        if ($resourceDocumentation !== null) {
            self::requireAbsoluteUri($op, 'resource_documentation', $resourceDocumentation, allowQuery: true, allowFragment: true);
        }

        // §28.2 fixes the member order. PHP array insertion order IS `json_encode()`
        // order, so the conditional inserts below sit exactly where an omitted member
        // belongs — never emitted as `null`.
        $document = ['resource' => $resource, 'authorization_servers' => $normalizedServers];
        if ($normalizedScopes !== []) {
            $document['scopes_supported'] = $normalizedScopes;
        }
        $document['bearer_methods_supported'] = ['header'];
        if ($resourceDocumentation !== null) {
            $document['resource_documentation'] = $resourceDocumentation;
        }

        $metadataPath = self::deriveMetadataPath($parsedResource['path']);

        return new ProtectedResourceMetadata(
            document: $document,
            metadataPath: $metadataPath,
            metadataUrl: sprintf('%s://%s%s', $parsedResource['scheme'], $parsedResource['authority'], $metadataPath),
        );
    }

    /**
     * CONTRACT.md §28.3's derivation: RFC 9728 §3.1 inserts the well-known segment
     * between the authority and the path. An empty path and a bare `/` both reach the
     * root form; anything else is appended, **trailing slash included** — it is part of
     * the identifier a client compares, and two resources that differ only by it are two
     * resources.
     */
    public static function deriveMetadataPath(string $resourcePath): string
    {
        if ($resourcePath === '' || $resourcePath === '/') {
            return self::PROTECTED_RESOURCE_METADATA_PREFIX;
        }

        return self::PROTECTED_RESOURCE_METADATA_PREFIX . $resourcePath;
    }

    /**
     * The path component of an already-validated absolute URL — query and fragment
     * stripped, an absent path normalised to `/`. Used by
     * {@see McpGuardOptions::build()} to derive the path a §10 guard exempts from
     * authentication (CONTRACT.md §28.3 rule 2) from the `resourceMetadataUrl` option it
     * was given, without parsing the URL a second time with different rules.
     */
    public static function pathOf(string $absoluteUrl): string
    {
        if (preg_match(self::ABSOLUTE_URI, $absoluteUrl, $m) !== 1) {
            self::refuse('resourceMetadataUrl', sprintf('must be an absolute URI, not %s', self::quote($absoluteUrl)));
        }

        return $m[3] === '' ? '/' : $m[3];
    }

    /**
     * `bearerChallenge(...)` (CONTRACT.md §28.4) — build the **value** of a
     * `WWW-Authenticate` header, never the whole header line and never a map. The caller
     * sets the header.
     *
     * Parameters appear in a fixed order — `error`, `error_description`, `scope`,
     * `resource_metadata` — separated by exactly `, `. `resource_metadata` is always
     * present; the other three are omitted when not given.
     *
     * **Every value is quoted and no value is ever escaped.** RFC 6750 §3 restricts each
     * parameter to a character set that cannot contain `"` or `\`, so a value needing an
     * escape is a value that does not belong in a challenge: this method refuses it
     * rather than escaping, truncating or stripping it. A challenge is built from the
     * code's own constants and a route's own configuration, so an invalid one is a
     * programming error, not a runtime condition to degrade around.
     *
     * @param string $resourceMetadataUrl The document's URL — the one parameter that is
     *        always present. May carry a query and a fragment.
     * @param string|null $error One of {@see BearerChallengeError}'s three constants, or
     *        `null` when the request carried no authentication information at all.
     * @param string|null $errorDescription A human-readable description, for an
     *        application building **its own** challenge for its own `400`. This SDK's
     *        own guards never set it — every reason a token is rejected collapses to
     *        `invalid_token`, indistinguishably (CONTRACT.md §28.4), because every
     *        distinction a 401 draws for an unauthenticated stranger is an oracle.
     * @param string|null $scope The scope the route asked for, verbatim — one or more
     *        tokens joined by a single space.
     *
     * @throws ValidationError When any parameter is outside RFC 6750's syntax.
     */
    public static function bearerChallenge(
        string $resourceMetadataUrl,
        ?string $error = null,
        ?string $errorDescription = null,
        ?string $scope = null,
    ): string {
        $params = [];

        if ($error !== null) {
            if (!in_array($error, [
                BearerChallengeError::INVALID_REQUEST,
                BearerChallengeError::INVALID_TOKEN,
                BearerChallengeError::INSUFFICIENT_SCOPE,
            ], true)) {
                self::refuse(
                    'error',
                    sprintf(
                        'must be one of invalid_request, invalid_token, insufficient_scope — RFC 6750 §3.1 defines no others, and %s is not among them',
                        self::quote($error),
                    ),
                );
            }
            $params[] = sprintf('error="%s"', $error);
        }

        if ($errorDescription !== null) {
            if ($errorDescription === '' || !self::isAll($errorDescription, self::isNqschar(...))) {
                self::refuse(
                    'error_description',
                    'must be one or more NQSCHAR (no \'"\', no \'\\\', no control character, no non-ASCII) — a value needing an escape does not belong in a challenge',
                );
            }
            $params[] = sprintf('error_description="%s"', $errorDescription);
        }

        if ($scope !== null) {
            if ($scope === '') {
                self::refuse('scope', 'must be one or more scope tokens joined by a single space');
            }
            foreach (explode(' ', $scope) as $token) {
                if ($token === '' || !self::isAll($token, self::isNqchar(...))) {
                    self::refuse(
                        'scope',
                        sprintf(
                            '%s is not a space-joined list of scope tokens — no leading, trailing or doubled space, and no empty token',
                            self::quote($scope),
                        ),
                    );
                }
            }
            $params[] = sprintf('scope="%s"', $scope);
        }

        self::requireAbsoluteUri('bearer_challenge', 'resource_metadata', $resourceMetadataUrl, allowQuery: true, allowFragment: true);
        if (!self::isAll($resourceMetadataUrl, self::isNqchar(...))) {
            self::refuse(
                'resource_metadata',
                'must carry no \'"\', no \'\\\', no space and no control character — a correctly encoded URL cannot, so one that does has not been encoded',
            );
        }
        $params[] = sprintf('resource_metadata="%s"', $resourceMetadataUrl);

        return 'Bearer ' . implode(', ', $params);
    }

    /**
     * The CONTRACT.md §28.3 response for the metadata document, ready to return from a
     * route/controller: `200`, `application/json`, the document body, and the caching /
     * CORS headers §28.3 rules 5–6 name. Shared by
     * {@see \Axiam\Sdk\Laravel\AxiamServiceProvider}'s `Route::serveProtectedResourceMetadata`
     * macro and {@see \Axiam\Sdk\Symfony\ProtectedResourceMetadataController} so the two
     * framework surfaces cannot drift on the response shape.
     */
    public static function toJsonResponse(ProtectedResourceMetadata $metadata): JsonResponse
    {
        $response = new JsonResponse($metadata->document, 200);
        $response->headers->set('Cache-Control', 'public, max-age=3600');
        $response->headers->set('Access-Control-Allow-Origin', '*');

        return $response;
    }

    /**
     * CONTRACT.md §28.5 rule 3: where this SDK can see BOTH a §10 guard's §28
     * configuration and the document about to be published for it, it MUST refuse a
     * mismatch at startup rather than publish a document the guard disagrees with.
     *
     * Called by `Route::serveProtectedResourceMetadata()` (Laravel,
     * {@see \Axiam\Sdk\Laravel\AxiamServiceProvider}) and
     * {@see \Axiam\Sdk\Symfony\ProtectedResourceMetadataController} whenever the
     * integrator passes the guard alongside the document. Passing no guard is how an
     * integrator whose guard runs in a SEPARATE process opts out — nothing can be
     * checked there, and nothing is.
     *
     * Both comparisons are simple string equality (RFC 3986 §6.2.1): no normalisation,
     * no case folding, no trailing-slash tolerance. The two strings are deliberately
     * DIFFERENT ones — the resource and the metadata URL — so each is compared against
     * its own counterpart, never against the other.
     *
     * @throws ValidationError When the guard's `resourceMetadataUrl` is not exactly the
     *         document's `metadataUrl`, or its expected audience is not exactly the
     *         document's `resource`.
     */
    public static function checkGuardAgreement(ProtectedResourceMetadata $metadata, McpGuardOptions $guard, ?string $guardExpectedAudience): void
    {
        if ($guard->resourceMetadataUrl !== $metadata->metadataUrl) {
            self::refuse(
                'resourceMetadataUrl',
                sprintf(
                    'is %s but this document is published at %s — the challenge would point at a document that is not this resource server\'s',
                    self::quote($guard->resourceMetadataUrl),
                    self::quote($metadata->metadataUrl),
                ),
            );
        }
        $resource = $metadata->document['resource'] ?? null;
        if ($guardExpectedAudience !== $resource) {
            self::refuse(
                'expectedAudience',
                sprintf(
                    'is %s but this document announces %s — the document would announce one identifier while the guard checked aud against another, so every token the flow produced would be refused',
                    self::quote((string) $guardExpectedAudience),
                    self::quote((string) $resource),
                ),
            );
        }
    }

    /**
     * §28.2/§28.4's refusal: always {@see ValidationError}, never a new type
     * (CONTRACT.md §28.6 — "§28's refusals are ValidationError; no new type").
     */
    private static function refuse(string $field, string $message): never
    {
        throw new ValidationError(
            sprintf('%s: %s (CONTRACT.md §28)', $field, $message),
            [new FieldError($field, $message)],
        );
    }

    /** `NQCHAR` (RFC 6749 Appendix A): `%x21` / `%x23`-`%x5B` / `%x5D`-`%x7E`. No space, no `"`, no `\`, no control, no non-ASCII. */
    private static function isNqchar(string $byte): bool
    {
        $code = ord($byte);

        return $code === 0x21 || ($code >= 0x23 && $code <= 0x5B) || ($code >= 0x5D && $code <= 0x7E);
    }

    /** `NQSCHAR`: `NQCHAR` plus the space (`%x20`). */
    private static function isNqschar(string $byte): bool
    {
        return $byte === ' ' || self::isNqchar($byte);
    }

    /** @param callable(string): bool $predicate */
    private static function isAll(string $value, callable $predicate): bool
    {
        $length = strlen($value);
        for ($i = 0; $i < $length; $i++) {
            if (!$predicate($value[$i])) {
                return false;
            }
        }

        return true;
    }

    /**
     * §28.2 rules 1/2/7 and §28.4's `resource_metadata`, applied to one member. Returns
     * the parsed pieces so a caller that needs the path (§28.3) does not parse twice.
     *
     * @return array{scheme: string, authority: string, path: string}
     */
    private static function requireAbsoluteUri(
        string $op,
        string $field,
        string $raw,
        bool $allowQuery,
        bool $allowFragment,
    ): array {
        if ($raw === '') {
            self::refuse($field, 'must be a non-empty absolute URI');
        }

        if (preg_match(self::ABSOLUTE_URI, $raw, $m) !== 1 || $m[2] === '') {
            self::refuse(
                $field,
                sprintf('must be an absolute URI with a scheme and an authority, not %s', self::quote($raw)),
            );
        }

        $scheme = $m[1];
        $authority = $m[2];
        $path = $m[3];
        // Each group's pattern (`\?[^#]*`, `#.*`) requires at least its leading
        // character, so a PARTICIPATING group is never an empty string — `isset()`
        // alone is "did the input carry a query/fragment at all", exactly §28.2 rule 1
        // asks ("even an empty one").
        $hasQuery = isset($m[4]);
        $hasFragment = isset($m[5]);

        if ($hasQuery && !$allowQuery) {
            self::refuse($field, 'must carry no query — §28.3 derives the metadata path from it');
        }
        if ($hasFragment && !$allowFragment) {
            self::refuse($field, 'must carry no fragment');
        }

        $lowerScheme = strtolower($scheme);
        if ($lowerScheme === 'https') {
            return ['scheme' => $scheme, 'authority' => $authority, 'path' => $path];
        }
        if ($lowerScheme === 'http' && in_array(strtolower(self::hostOf($authority)), self::LOOPBACK_HOSTS, true)) {
            return ['scheme' => $scheme, 'authority' => $authority, 'path' => $path];
        }

        self::refuse(
            $field,
            sprintf(
                'must use https — http is accepted only on 127.0.0.1, [::1] or localhost, and %s is neither',
                self::quote($raw),
            ),
        );
    }

    /**
     * The host inside an authority: `userinfo@` stripped, port stripped, an IPv6
     * literal's brackets kept (so `[::1]` compares as §28.2 rule 2 spells it).
     *
     * Stripping `userinfo` is what makes `http://localhost@evil.example.com/` a refusal
     * rather than a loopback pass — the host there is `evil.example.com`.
     */
    private static function hostOf(string $authority): string
    {
        $at = strrpos($authority, '@');
        $hostport = $at !== false ? substr($authority, $at + 1) : $authority;
        if (str_starts_with($hostport, '[')) {
            $close = strpos($hostport, ']');

            return $close === false ? $hostport : substr($hostport, 0, $close + 1);
        }
        $colon = strpos($hostport, ':');

        return $colon === false ? $hostport : substr($hostport, 0, $colon);
    }

    private static function quote(string $value): string
    {
        return json_encode($value, JSON_UNESCAPED_SLASHES) ?: '""';
    }

    /** @param list<mixed> $values */
    private static function quoteList(array $values): string
    {
        return json_encode($values, JSON_UNESCAPED_SLASHES) ?: '[]';
    }
}
