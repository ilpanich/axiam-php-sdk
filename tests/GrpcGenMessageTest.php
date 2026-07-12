<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Grpc\Gen\BatchCheckAccessRequest;
use Axiam\Sdk\Grpc\Gen\BatchCheckAccessResponse;
use Axiam\Sdk\Grpc\Gen\CheckAccessRequest;
use Axiam\Sdk\Grpc\Gen\CheckAccessResponse;
use Axiam\Sdk\Grpc\Gen\Metadata\Authorization;
use PHPUnit\Framework\TestCase;

/**
 * Exercises the committed `src/Grpc/Gen/*` protobuf message stubs directly through the
 * pure-PHP `google/protobuf` runtime (a require-dev dependency; the same
 * `Google\Protobuf\Internal\Message` base class the stubs `extend`). These generated
 * getters/setters are the wire contract {@see \Axiam\Sdk\Grpc\AuthzGrpcClient} builds
 * requests from and reads responses into, so they are unit-testable on their own without
 * the `ext-grpc` PECL extension (which only the transport client — never these plain
 * message DTOs — requires). Instantiating any message also runs
 * {@see Authorization::initOnce()} (the generated descriptor registration).
 */
final class GrpcGenMessageTest extends TestCase
{
    public function testCheckAccessRequestRoundTripsEveryField(): void
    {
        $req = new CheckAccessRequest();
        self::assertSame('', $req->getTenantId());
        self::assertSame('', $req->getSubjectId());
        self::assertSame('', $req->getAction());
        self::assertSame('', $req->getResourceId());
        self::assertFalse($req->hasScope());

        $req->setTenantId('tenant-1');
        $req->setSubjectId('subject-1');
        $req->setAction('read');
        $req->setResourceId('resource-1');
        $req->setScope('sub-scope');

        self::assertSame('tenant-1', $req->getTenantId());
        self::assertSame('subject-1', $req->getSubjectId());
        self::assertSame('read', $req->getAction());
        self::assertSame('resource-1', $req->getResourceId());
        self::assertTrue($req->hasScope());
        self::assertSame('sub-scope', $req->getScope());
    }

    public function testCheckAccessRequestClearScopeResetsPresence(): void
    {
        $req = new CheckAccessRequest();
        $req->setScope('temporary');
        self::assertTrue($req->hasScope());

        $req->clearScope();

        self::assertFalse($req->hasScope());
        self::assertSame('', $req->getScope());
    }

    public function testCheckAccessRequestConstructsFromDataArray(): void
    {
        $req = new CheckAccessRequest([
            'tenant_id' => 'tenant-2',
            'subject_id' => 'subject-2',
            'action' => 'write',
            'resource_id' => 'resource-2',
            'scope' => 'scoped',
        ]);

        self::assertSame('tenant-2', $req->getTenantId());
        self::assertSame('subject-2', $req->getSubjectId());
        self::assertSame('write', $req->getAction());
        self::assertSame('resource-2', $req->getResourceId());
        self::assertSame('scoped', $req->getScope());
    }

    public function testCheckAccessResponseRoundTripsAllowedAndDenyReason(): void
    {
        $res = new CheckAccessResponse();
        self::assertFalse($res->getAllowed());
        self::assertSame('', $res->getDenyReason());

        $res->setAllowed(true);
        $res->setDenyReason('');
        self::assertTrue($res->getAllowed());
        self::assertSame('', $res->getDenyReason());

        $res->setAllowed(false);
        $res->setDenyReason('no matching grant');
        self::assertFalse($res->getAllowed());
        self::assertSame('no matching grant', $res->getDenyReason());
    }

    public function testBatchCheckAccessRequestHoldsRepeatedCheckRequests(): void
    {
        $batch = new BatchCheckAccessRequest();
        $batch->setRequests([
            new CheckAccessRequest(['action' => 'read', 'resource_id' => 'r1']),
            new CheckAccessRequest(['action' => 'write', 'resource_id' => 'r2']),
        ]);

        $requests = $batch->getRequests();
        self::assertCount(2, $requests);

        $actions = [];
        foreach ($requests as $item) {
            $actions[] = $item->getAction();
        }
        self::assertSame(['read', 'write'], $actions);
    }

    public function testBatchCheckAccessResponsePreservesResultOrder(): void
    {
        $batch = new BatchCheckAccessResponse();
        $batch->setResults([
            new CheckAccessResponse(['allowed' => true]),
            new CheckAccessResponse(['allowed' => false, 'deny_reason' => 'denied']),
        ]);

        $allowed = [];
        foreach ($batch->getResults() as $result) {
            $allowed[] = $result->getAllowed();
        }
        self::assertSame([true, false], $allowed);
    }

    public function testAuthorizationDescriptorInitialisesOnce(): void
    {
        // Constructing any message above already triggered initOnce(); calling it again
        // must be idempotent (the generated $is_initialized guard) and never re-register.
        Authorization::initOnce();
        Authorization::initOnce();

        self::assertTrue(Authorization::$is_initialized);
    }
}
