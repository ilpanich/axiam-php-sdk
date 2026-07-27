<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\Sensitive;
use Axiam\Sdk\Oidc\MemoryOidcStateStore;
use Axiam\Sdk\Oidc\OidcStateEntry;
use PHPUnit\Framework\TestCase;

/**
 * {@see MemoryOidcStateStore} (CONTRACT.md §12.3 rule 1): single-use `consume()`, a
 * 10-minute TTL ceiling (clamped, never exceedable by a caller), and per-instance (never
 * static/process-global) state.
 */
final class OidcStateStoreTest extends TestCase
{
    private function entry(string $state = 'state-1', ?string $returnTo = null): OidcStateEntry
    {
        return new OidcStateEntry(
            state: $state,
            nonce: 'nonce-1',
            codeVerifier: new Sensitive('verifier-1'),
            redirectUri: 'https://app.test/callback',
            returnTo: $returnTo,
        );
    }

    public function testSaveThenConsumeReturnsTheEntry(): void
    {
        $store = new MemoryOidcStateStore();
        $store->save($this->entry('state-1', '/dashboard'));

        $consumed = $store->consume('state-1');

        self::assertNotNull($consumed);
        self::assertSame('state-1', $consumed->state);
        self::assertSame('nonce-1', $consumed->nonce);
        self::assertSame('verifier-1', $consumed->codeVerifier->reveal());
        self::assertSame('/dashboard', $consumed->returnTo);
    }

    public function testConsumeIsSingleUse(): void
    {
        $store = new MemoryOidcStateStore();
        $store->save($this->entry('state-1'));

        self::assertNotNull($store->consume('state-1'));
        self::assertNull($store->consume('state-1'), 'a second consume() of the same state must return null');
    }

    public function testConsumeOfUnknownStateReturnsNull(): void
    {
        $store = new MemoryOidcStateStore();

        self::assertNull($store->consume('never-saved'));
    }

    public function testTtlExpiryMakesAnEntryUnconsumable(): void
    {
        // A 0-second TTL means "already expired" the instant it's saved.
        $store = new MemoryOidcStateStore(ttlSeconds: 0);
        $store->save($this->entry('state-1'));

        // Straddle a real clock tick so `expiresAt <= time()` is unambiguously true.
        sleep(1);

        self::assertNull($store->consume('state-1'));
    }

    public function testTtlIsClampedToTenMinutesMaximum(): void
    {
        self::assertSame(600, MemoryOidcStateStore::TTL_SECONDS);

        // An over-long requested TTL is silently clamped to the 600s ceiling (§12.3
        // rule 1) rather than honoured — a store built with one still behaves exactly
        // like the default store for a not-yet-expired entry.
        $store = new MemoryOidcStateStore(ttlSeconds: 999_999);
        $store->save($this->entry('state-1'));

        self::assertNotNull($store->consume('state-1'), 'not yet expired under the clamped (600s) ceiling');
    }

    public function testSizeReflectsUnexpiredEntriesAndSweepsOnAccess(): void
    {
        $store = new MemoryOidcStateStore();
        self::assertSame(0, $store->size());

        $store->save($this->entry('a'));
        $store->save($this->entry('b'));
        self::assertSame(2, $store->size());

        $store->consume('a');
        self::assertSame(1, $store->size());
    }

    public function testSweepDropsExpiredEntriesOnTheNextSaveOrSizeCall(): void
    {
        // A 0-second-TTL entry parked alongside a normal one: a subsequent size()
        // call must sweep the expired one away entirely (not just refuse to return
        // it), proving the lazy housekeeping loop itself runs.
        $store = new MemoryOidcStateStore(ttlSeconds: 0);
        $store->save($this->entry('expires-fast'));
        sleep(1);

        self::assertSame(0, $store->size(), 'size() must sweep the expired entry, not merely skip it');
    }

    public function testEachStoreInstanceIsIndependent(): void
    {
        $storeA = new MemoryOidcStateStore();
        $storeB = new MemoryOidcStateStore();

        $storeA->save($this->entry('shared-state-name'));

        self::assertNull($storeB->consume('shared-state-name'), 'state stores must never share state across instances');
        self::assertNotNull($storeA->consume('shared-state-name'));
    }
}
