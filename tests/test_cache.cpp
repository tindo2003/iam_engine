#include <gtest/gtest.h>

#include <chrono>

#include "iam/cache.hpp"

using namespace iam;
using std::chrono::milliseconds;

namespace {

constexpr milliseconds kTtl{5000};
constexpr milliseconds kBucket{1000};

// Snap a real clock reading to a bucket boundary so no test depends on
// where wall-clock time happens to land when it runs.
Snapshot bucketAlignedNow() {
    return quantize(std::chrono::steady_clock::now(), kBucket);
}

const CacheKey kAlice{"alice", "db:read", "urn:table:users"};

} // namespace

TEST(Quantize, RoundsDownWithinABucket) {
    const Snapshot base = bucketAlignedNow();
    EXPECT_EQ(quantize(base, kBucket), base);
    EXPECT_EQ(quantize(base + milliseconds(1), kBucket), base);
    EXPECT_EQ(quantize(base + milliseconds(999), kBucket), base);
}

TEST(Quantize, CrossingABoundaryStartsTheNextBucket) {
    const Snapshot base = bucketAlignedNow();
    EXPECT_EQ(quantize(base + kBucket, kBucket), base + kBucket);
    EXPECT_EQ(quantize(base + kBucket + milliseconds(1), kBucket), base + kBucket);
}

TEST(Quantize, ZeroBucketDisablesQuantization) {
    const Snapshot t = std::chrono::steady_clock::now();
    EXPECT_EQ(quantize(t, milliseconds{0}), t);
}

TEST(DecisionCache, MissWhenEmpty) {
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);

    EXPECT_FALSE(cache.get(kAlice, now).has_value());
}

TEST(DecisionCache, HitOnExactSnapshot) {
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);

    cache.put(kAlice, now, true);
    const auto result = cache.get(kAlice, now);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);
}

TEST(DecisionCache, MissOnADifferentSnapshot) {
    // The heart of the snapshot-keyed design: the same identity at another
    // snapshot is a different key entirely, not a stale entry to be
    // freshness-checked.
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);

    cache.put(kAlice, now, true);
    EXPECT_FALSE(cache.get(kAlice, now + kBucket).has_value());
}

TEST(DecisionCache, SnapshotsCoexistForOneIdentity) {
    // Capacity the old one-mutable-entry-per-identity design did not have:
    // answers for several snapshots live side by side, none overwriting
    // another.
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);

    cache.put(kAlice, now, true);
    cache.put(kAlice, now + kBucket, false);

    EXPECT_TRUE(*cache.get(kAlice, now));
    EXPECT_FALSE(*cache.get(kAlice, now + kBucket));
    EXPECT_EQ(cache.size(), 2u);
}

TEST(DecisionCache, HitStaysValidLongAfterItWasComputed) {
    // No TTL-style freshness check on reads: an answer computed at
    // snapshot S is correct for S permanently. Only retention (eviction)
    // can take it away, and eviction only runs on put.
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);
    const Snapshot when = now;

    cache.put(kAlice, when, true);
    now += kTtl * 100; // absurdly far past the retention window

    EXPECT_TRUE(cache.get(kAlice, when).has_value());
}

TEST(DecisionCache, DifferentIdentitiesDoNotCollide) {
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);

    cache.put(CacheKey{"alice", "db:read", "urn:table:users"}, now, true);
    cache.put(CacheKey{"alice", "db:delete", "urn:table:users"}, now, false);

    EXPECT_TRUE(*cache.get(CacheKey{"alice", "db:read", "urn:table:users"}, now));
    EXPECT_FALSE(*cache.get(CacheKey{"alice", "db:delete", "urn:table:users"}, now));
}

TEST(DecisionCache, EvictsSnapshotsOlderThanTtl) {
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);
    const Snapshot old = now;

    cache.put(kAlice, old, true);
    ASSERT_TRUE(cache.get(kAlice, old).has_value());

    // Writing a fresh snapshot is what triggers the sweep for this identity.
    now += kTtl + kBucket;
    cache.put(kAlice, now, false);

    EXPECT_FALSE(cache.get(kAlice, old).has_value()); // reclaimed for capacity
    EXPECT_TRUE(cache.get(kAlice, now).has_value());  // still retained
    EXPECT_EQ(cache.size(), 1u);
}

TEST(DecisionCache, RetainsSnapshotsWithinTtl) {
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);
    const Snapshot recent = now;

    cache.put(kAlice, recent, true);
    now += kBucket; // comfortably inside the retention window
    cache.put(kAlice, now, false);

    EXPECT_TRUE(cache.get(kAlice, recent).has_value());
    EXPECT_EQ(cache.size(), 2u);
}
