<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests\Management;

use Axiam\Sdk\Management\Models\AssignRoleToUserRequest;
use Axiam\Sdk\Management\Models\Certificate;
use Axiam\Sdk\Management\Models\CertificateType;
use Axiam\Sdk\Management\Models\RoleAssignment;
use Axiam\Sdk\Management\Models\RoleGroupAssignment;
use Axiam\Sdk\Management\Models\SubjectAltName;
use Axiam\Sdk\Management\Models\SubjectAltNameDns;
use Axiam\Sdk\Management\Models\SubjectAltNameIp;
use PHPUnit\Framework\TestCase;

/**
 * Pins the two generator defects the contract 1.51 re-vendor exposed, and the
 * open-decoding rule the re-vendor's new enum value re-tests (CONTRACT.md §27.13,
 * §27.11 rule 1) — mirroring `ilpanich/axiam-rust-sdk`'s `tests/contract_151_models_test.rs`
 * (C-1's EXECUTED item 2 names both defects; PHP's generator, `scripts/gen_management.py`,
 * had them independently and is fixed the same way here).
 */
final class Contract151ModelsTest extends TestCase
{
    // -----------------------------------------------------------------
    // Generator defect 1: SubjectAltName is an externally tagged oneOf.
    //
    // The buggy generator emitted a struct with no fields, which serialized as `{}` —
    // it compiled, it sent, and the server refused it. It MUST serialize as
    // `{"dns": …}` or `{"ip": …}`, never `{}` or `[]` (PHP's `json_encode([])` is `[]`,
    // not `{}` — a second way to fail this the Rust port never had to check).
    // -----------------------------------------------------------------

    public function testSubjectAltNameDnsSerializesAsDnsKeyedObjectNeverEmpty(): void
    {
        $name = new SubjectAltNameDns('api.lakeside.internal');

        $wire = $name->toArray();

        self::assertSame(['dns' => 'api.lakeside.internal'], $wire);
        self::assertNotSame([], $wire, 'must not serialize as {} / []');
        $json = json_encode($wire);
        self::assertIsString($json);
        self::assertJsonStringEqualsJsonString('{"dns":"api.lakeside.internal"}', $json);
    }

    public function testSubjectAltNameIpSerializesAsIpKeyedObjectNeverEmpty(): void
    {
        $name = new SubjectAltNameIp('10.0.0.5');

        $wire = $name->toArray();

        self::assertSame(['ip' => '10.0.0.5'], $wire);
        $json = json_encode($wire);
        self::assertIsString($json);
        self::assertJsonStringEqualsJsonString('{"ip":"10.0.0.5"}', $json);
    }

    public function testSubjectAltNameDecodesEachArmByItsKey(): void
    {
        $dns = SubjectAltName::fromArray(['dns' => 'api.lakeside.internal']);
        $ip = SubjectAltName::fromArray(['ip' => '10.0.0.5']);

        self::assertInstanceOf(SubjectAltNameDns::class, $dns);
        self::assertSame('api.lakeside.internal', $dns->dns);
        self::assertInstanceOf(SubjectAltNameIp::class, $ip);
        self::assertSame('10.0.0.5', $ip->ip);
    }

    public function testSubjectAltNameRefusesAnObjectNamingNeitherArm(): void
    {
        $this->expectException(\Axiam\Sdk\Core\AxiamException::class);
        SubjectAltName::fromArray(['uri' => 'https://example.test']);
    }

    /**
     * A list of names round-trips through the real request models, exactly as a caller
     * would build one — never `{}`/`[]` for any entry, on the wire that ManagementTransport
     * actually sends (§27.13 S-7 rule 1).
     */
    public function testSubjectAltNamesListOnACreateCertificateRequestSerializesNamedArms(): void
    {
        $request = new \Axiam\Sdk\Management\Models\CreateCertificateRequest(
            certType: CertificateType::Server,
            issuerCaId: '55555555-5555-4555-8555-555555555555',
            keyAlgorithm: \Axiam\Sdk\Management\Models\KeyAlgorithm::Ed25519,
            subject: 'CN=api.lakeside.internal',
            validityDays: 90,
            subjectAltNames: [
                new SubjectAltNameDns('api.lakeside.internal'),
                new SubjectAltNameIp('10.0.0.5'),
            ],
        );

        $wire = $request->toArray();

        self::assertSame(
            [['dns' => 'api.lakeside.internal'], ['ip' => '10.0.0.5']],
            $wire['subject_alt_names'],
        );
    }

    // -----------------------------------------------------------------
    // Generator defect 2: a required `inherit` on the role-side listings must not
    // fail the whole listing against a server older than contract 1.51.
    // -----------------------------------------------------------------

    public function testRoleGroupAssignmentDefaultsInheritToTrueWhenAbsent(): void
    {
        $assignment = RoleGroupAssignment::fromArray([
            'group' => self::groupWire(),
            // 'inherit' omitted — a pre-1.51 server.
        ]);

        self::assertTrue($assignment->inherit, 'absence means true (§27.13 S-10 rule 3)');
    }

    public function testRoleGroupAssignmentReadsAnExplicitFalse(): void
    {
        $assignment = RoleGroupAssignment::fromArray([
            'group' => self::groupWire(),
            'inherit' => false,
        ]);

        self::assertFalse($assignment->inherit);
    }

    /** The subject-side listing is genuinely optional: absent stays `null`, not `true`. */
    public function testRoleAssignmentSubjectSideLeavesInheritNullWhenAbsent(): void
    {
        $assignment = RoleAssignment::fromArray([
            'role' => self::roleWire(),
        ]);

        self::assertNull(
            $assignment->inherit,
            'the subject-side field is OPTIONAL on the wire; a caller reads null as true '
            . '(§27.13 S-10 rule 3) — this model must not invent a default the schema does not '
            . 'require',
        );
    }

    /** `inherit: false` still reaches the wire on an assign request (unchanged by the fix). */
    public function testAssignRoleToUserRequestStillSendsAnExplicitFalse(): void
    {
        $request = new AssignRoleToUserRequest('11111111-1111-4111-8111-111111111111', inherit: false);

        self::assertSame(false, $request->toArray()['inherit']);
    }

    /** And omits the key entirely when not stated — an inheritable body stays byte-for-byte. */
    public function testAssignRoleToUserRequestOmitsInheritWhenUnset(): void
    {
        $request = new AssignRoleToUserRequest('11111111-1111-4111-8111-111111111111');

        self::assertArrayNotHasKey('inherit', $request->toArray());
    }

    // -----------------------------------------------------------------
    // §27.13 S-7 rule 2 / §27.11 rule 1: an unknown cert_type decodes openly.
    // Already correct before this port (CertificateType::fromWire() never throws);
    // pinned here so a regression is caught rather than merely hoped against.
    // -----------------------------------------------------------------

    public function testCertificatesListDecodesAnUnrecognisedCertTypeAsUnknownNotAFailure(): void
    {
        $certificate = Certificate::fromArray(self::certificateWire('QuantumMesh'));

        self::assertSame(CertificateType::Unknown, $certificate->certType);
    }

    public function testCertificateTypeDecodesTheNewServerValue(): void
    {
        self::assertSame(CertificateType::Server, CertificateType::fromWire('Server'));

        $certificate = Certificate::fromArray(self::certificateWire('Server'));
        self::assertSame(CertificateType::Server, $certificate->certType);
    }

    /** @return array<string,mixed> */
    private static function groupWire(): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'description' => '',
            'id' => '22222222-2222-4222-8222-222222222222',
            'metadata' => null,
            'name' => 'engineers',
            'tenant_id' => '11111111-1111-4111-8111-111111111111',
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    /** @return array<string,mixed> */
    private static function roleWire(): array
    {
        return [
            'created_at' => '2026-08-26T00:00:00Z',
            'description' => '',
            'id' => '33333333-3333-4333-8333-333333333333',
            'is_global' => false,
            'name' => 'auditor',
            'tenant_id' => '11111111-1111-4111-8111-111111111111',
            'updated_at' => '2026-08-26T00:00:00Z',
        ];
    }

    /** @return array<string,mixed> */
    private static function certificateWire(string $certType): array
    {
        return [
            'cert_type' => $certType,
            'created_at' => '2026-08-26T00:00:00Z',
            'fingerprint' => 'aa:bb:cc',
            'id' => '44444444-4444-4444-8444-444444444444',
            'issuer_ca_id' => '55555555-5555-4555-8555-555555555555',
            'key_algorithm' => 'Ed25519',
            'metadata' => null,
            'not_after' => '2027-08-26T00:00:00Z',
            'not_before' => '2026-08-26T00:00:00Z',
            'public_cert_pem' => '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----',
            'status' => 'Active',
            'subject' => 'CN=device-1',
            'tenant_id' => '11111111-1111-4111-8111-111111111111',
        ];
    }
}
