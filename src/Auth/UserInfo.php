<?php

declare(strict_types=1);

namespace Axiam\Sdk\Auth;

/**
 * Result of `AxiamClient::getUserInfo()` (CONTRACT.md §1.1, contract 1.3).
 *
 * A readonly DTO — the typed value object the gRPC-only `get_user_info` operation returns,
 * mirroring the shape of {@see LoginResult} (D-09: a typed record, never a raw
 * array/stdClass or the wire `GetUserInfoResponse` message leaking out of the SDK).
 *
 * `$sub`, `$tenantId`, and `$orgId` are ALWAYS populated. `$email` is non-null only when the
 * access token carried the "email" scope, and `$preferredUsername` only with the "profile"
 * scope — the server gates these exactly as the REST `/oauth2/userinfo` endpoint does
 * (§1.1.5); an absent optional claim is surfaced here as `null` (never an empty string).
 *
 * None of these fields is token-carrying, so — unlike {@see LoginResult::$challengeToken}
 * — none is wrapped in {@see \Axiam\Sdk\Core\Sensitive} (§7 applies only to secret token
 * material, which an identity claim set is not).
 */
final readonly class UserInfo
{
    public function __construct(
        public string $sub,
        public string $tenantId,
        public string $orgId,
        public ?string $email = null,
        public ?string $preferredUsername = null,
    ) {
    }
}
