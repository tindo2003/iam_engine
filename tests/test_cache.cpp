#include <gtest/gtest.h>

#include <chrono>

#include "iam/cache.hpp"

using namespace iam;

namespace {

constexpr PolicyVersion kCacheEntryPolicyVersion = 1;

} // namespace

TEST(DecisionCache, MissWhenEmpty) {
    auto now = std::chrono::steady_clock::now();
    DecisionCache cache(std::chrono::milliseconds(1000), [&now] { return now; });
    const CacheKey key{"alice", "db:read", "urn:table:users"};

    EXPECT_FALSE(cache.get(key).has_value());
}

TEST(DecisionCache, HitWithinTtl) {
    auto now = std::chrono::steady_clock::now();
    DecisionCache cache(std::chrono::milliseconds(1000), [&now] { return now; });
    const CacheKey key{"alice", "db:read", "urn:table:users"};

    cache.put(key, true, kCacheEntryPolicyVersion);
    const auto result = cache.get(key);
    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(*result);
}

TEST(DecisionCache, MissAfterTtlExpires) {
    auto now = std::chrono::steady_clock::now();
    DecisionCache cache(std::chrono::milliseconds(1000), [&now] { return now; });
    const CacheKey key{"alice", "db:read", "urn:table:users"};

    cache.put(key, true, kCacheEntryPolicyVersion);
    now += std::chrono::milliseconds(1500); // fake clock advances past the TTL
    EXPECT_FALSE(cache.get(key).has_value());
}

TEST(DecisionCache, DifferentKeysDoNotCollide) {
    auto now = std::chrono::steady_clock::now();
    DecisionCache cache(std::chrono::milliseconds(1000), [&now] { return now; });

    cache.put(CacheKey{"alice", "db:read", "urn:table:users"}, true, kCacheEntryPolicyVersion);
    cache.put(CacheKey{"alice", "db:delete", "urn:table:users"}, false, kCacheEntryPolicyVersion);

    EXPECT_TRUE(*cache.get(CacheKey{"alice", "db:read", "urn:table:users"}));
    EXPECT_FALSE(*cache.get(CacheKey{"alice", "db:delete", "urn:table:users"}));
}

TEST(DecisionCache, HitWhenVersionAtOrAboveMinimum) {
    auto now = std::chrono::steady_clock::now();
    DecisionCache cache(std::chrono::milliseconds(1000), [&now] { return now; });

    cache.put(CacheKey{"alice", "db:read", "urn:table:users"}, true, kCacheEntryPolicyVersion);
    // Requesting a floor below the entry's own version: still a hit.
    EXPECT_TRUE(*cache.get(CacheKey{"alice", "db:read", "urn:table:users"}, kCacheEntryPolicyVersion - 1));
}

TEST(DecisionCache, MissWhenVersionBelowMinimum) {
    auto now = std::chrono::steady_clock::now();
    DecisionCache cache(std::chrono::milliseconds(1000), [&now] { return now; });

    cache.put(CacheKey{"alice", "db:read", "urn:table:users"}, true, kCacheEntryPolicyVersion);
    // Requesting a floor above the entry's own version: a miss, even
    // though the entry is still well within its TTL window.
    EXPECT_FALSE(cache.get(CacheKey{"alice", "db:read", "urn:table:users"}, kCacheEntryPolicyVersion + 1).has_value());
}