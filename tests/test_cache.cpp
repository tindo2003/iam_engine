#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

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

    cache.put(kAlice, now, Decision::Allow);
    const auto result = cache.get(kAlice, now);
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, Decision::Allow);
}

TEST(DecisionCache, MissOnADifferentSnapshot) {
    // The heart of the snapshot-keyed design: the same identity at another
    // snapshot is a different key entirely, not a stale entry to be
    // freshness-checked.
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);

    cache.put(kAlice, now, Decision::Allow);
    EXPECT_FALSE(cache.get(kAlice, now + kBucket).has_value());
}

TEST(DecisionCache, SnapshotsCoexistForOneIdentity) {
    // Capacity the old one-mutable-entry-per-identity design did not have:
    // answers for several snapshots live side by side, none overwriting
    // another.
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);

    cache.put(kAlice, now, Decision::Allow);
    cache.put(kAlice, now + kBucket, Decision::Deny);

    EXPECT_EQ(*cache.get(kAlice, now), Decision::Allow);
    EXPECT_EQ(*cache.get(kAlice, now + kBucket), Decision::Deny);
    EXPECT_EQ(cache.size(), 2u);
}

TEST(DecisionCache, HitStaysValidLongAfterItWasComputed) {
    // No TTL-style freshness check on reads: an answer computed at
    // snapshot S is correct for S permanently. Only retention (eviction)
    // can take it away, and eviction only runs on put.
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);
    const Snapshot when = now;

    cache.put(kAlice, when, Decision::Allow);
    now += kTtl * 100; // absurdly far past the retention window

    EXPECT_TRUE(cache.get(kAlice, when).has_value());
}

TEST(DecisionCache, DifferentIdentitiesDoNotCollide) {
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);

    cache.put(CacheKey{"alice", "db:read", "urn:table:users"}, now, Decision::Allow);
    cache.put(CacheKey{"alice", "db:delete", "urn:table:users"}, now, Decision::Deny);

    EXPECT_EQ(*cache.get(CacheKey{"alice", "db:read", "urn:table:users"}, now), Decision::Allow);
    EXPECT_EQ(*cache.get(CacheKey{"alice", "db:delete", "urn:table:users"}, now), Decision::Deny);
}

TEST(DecisionCache, EvictsSnapshotsOlderThanTtl) {
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);
    const Snapshot old = now;

    cache.put(kAlice, old, Decision::Allow);
    ASSERT_TRUE(cache.get(kAlice, old).has_value());

    // Writing a fresh snapshot is what triggers the sweep for this identity.
    now += kTtl + kBucket;
    cache.put(kAlice, now, Decision::Deny);

    EXPECT_FALSE(cache.get(kAlice, old).has_value()); // reclaimed for capacity
    EXPECT_TRUE(cache.get(kAlice, now).has_value());  // still retained
    EXPECT_EQ(cache.size(), 1u);
}

TEST(DecisionCache, RetainsSnapshotsWithinTtl) {
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);
    const Snapshot recent = now;

    cache.put(kAlice, recent, Decision::Allow);
    now += kBucket; // comfortably inside the retention window
    cache.put(kAlice, now, Decision::Deny);

    EXPECT_TRUE(cache.get(kAlice, recent).has_value());
    EXPECT_EQ(cache.size(), 2u);
}

// --- Concurrency --------------------------------------------------------

TEST(DecisionCache, ConcurrentCallersForOneKeyComputeItOnlyOnce) {
    // Thread safety alone would let all N threads miss, all compute, and
    // all store the same answer -- correct, but N times the work. This is
    // the property singleflight adds on top.
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);
    const CacheKey key{"alice", "db:read", "urn:table:users"};

    std::atomic<int> computeCalls{0};
    std::mutex mu;
    std::condition_variable cv;
    bool release = false;

    // Holds the flight open so later arrivals really do pile up behind it
    // rather than finding a finished answer.
    auto compute = [&] {
        ++computeCalls;
        std::unique_lock<std::mutex> lock(mu);
        cv.wait(lock, [&] { return release; });
        return Decision::Allow;
    };

    constexpr int kThreads = 16;
    std::vector<std::thread> threads;
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&] { cache.getOrCompute(key, now, compute); });
    }

    // Wait for the others to queue up, but bounded -- releasing early only
    // makes them cache hits instead, which the assertion tolerates.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (cache.coalesced() < kThreads - 1 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::yield();
    }

    {
        std::lock_guard<std::mutex> lock(mu);
        release = true;
    }
    cv.notify_all();
    for (std::thread& t : threads) {
        t.join();
    }

    EXPECT_EQ(computeCalls.load(), 1);
    EXPECT_EQ(cache.coalesced(), kThreads - 1);
    EXPECT_EQ(cache.size(), 1u);
}

TEST(DecisionCache, ADifferentKeyIsNotBlockedByAnInFlightOne) {
    // Coalescing must dedupe one key, not serialise the whole cache.
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);

    std::mutex mu;
    std::condition_variable cv;
    bool release = false;

    std::thread blocker([&] {
        cache.getOrCompute(CacheKey{"alice", "db:read", "a"}, now, [&] {
            std::unique_lock<std::mutex> lock(mu);
            cv.wait(lock, [&] { return release; });
            return Decision::Allow;
        });
    });

    // Must not need the blocked flight to finish first.
    const Decision other =
        cache.getOrCompute(CacheKey{"bob", "db:read", "b"}, now, [] { return Decision::Deny; });
    EXPECT_EQ(other, Decision::Deny);

    {
        std::lock_guard<std::mutex> lock(mu);
        release = true;
    }
    cv.notify_all();
    blocker.join();
}

TEST(DecisionCache, ConcurrentMixedTrafficStaysConsistent) {
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);

    constexpr int kThreads = 8;
    constexpr int kKeys = 64;
    constexpr int kIterations = 500;

    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < kIterations; ++i) {
                const CacheKey key{"user" + std::to_string((t * 7 + i) % kKeys), "db:read", "res"};
                const Decision got =
                    cache.getOrCompute(key, now, [] { return Decision::Allow; });
                // Every key resolves to Allow here, so any other value
                // would mean an entry was torn or mismatched.
                EXPECT_EQ(got, Decision::Allow);
            }
        });
    }
    for (std::thread& t : threads) {
        t.join();
    }

    EXPECT_EQ(cache.size(), static_cast<size_t>(kKeys));
}
