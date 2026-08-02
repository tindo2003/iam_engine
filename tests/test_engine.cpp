#include <gtest/gtest.h>

#include <chrono>

#include "iam/cache.hpp"
#include "iam/engine.hpp"
#include "iam/policy.hpp"

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

class PolicyEngineTest : public ::testing::Test {
protected:
    Policy allowDenyPolicy() {
        return Policy::fromJsonString(R"({
            "Statement": [
                {"Effect": "Allow", "Action": ["db:read", "db:write"], "Resource": ["urn:table:users"]},
                {"Effect": "Deny", "Action": ["db:delete"], "Resource": ["*"]}
            ]
        })");
    }

    // allowDenyPolicy() genuinely allows this one, so any test that gets
    // back `false` for it must have read a poisoned cache entry.
    const Request allowedRequest{"alice", "db:read", "urn:table:users"};

    CacheKey keyFor(const Request& request) const {
        return CacheKey{request.principal, request.action, request.resource};
    }
};

} // namespace

TEST_F(PolicyEngineTest, DefaultDenyWithNoPolicies) {
    const std::vector<Policy> policies;
    const Request request{"alice", "db:read", "urn:table:users"};
    EXPECT_FALSE(PolicyEngine::evaluate(policies, request));
}

TEST_F(PolicyEngineTest, ExplicitAllow) {
    const std::vector<Policy> policies{allowDenyPolicy()};
    const Request request{"alice", "db:read", "urn:table:users"};
    EXPECT_TRUE(PolicyEngine::evaluate(policies, request));
}

TEST_F(PolicyEngineTest, NoMatchingStatementIsDenied) {
    const std::vector<Policy> policies{allowDenyPolicy()};
    const Request request{"alice", "db:read", "urn:table:orders"};
    EXPECT_FALSE(PolicyEngine::evaluate(policies, request));
}

TEST_F(PolicyEngineTest, ExplicitDenyOverridesAllow) {
    // db:delete matches the wildcard Deny statement even though the
    // resource also matches an Allow-eligible table.
    const std::vector<Policy> policies{allowDenyPolicy()};
    const Request request{"alice", "db:delete", "urn:table:users"};
    EXPECT_FALSE(PolicyEngine::evaluate(policies, request));
}

TEST_F(PolicyEngineTest, WildcardActionMatch) {
    const Policy policy = Policy::fromJsonString(R"({
        "Statement": [
            {"Effect": "Allow", "Action": ["db:*"], "Resource": ["*"]}
        ]
    })");
    const std::vector<Policy> policies{policy};
    EXPECT_TRUE(PolicyEngine::evaluate(policies, Request{"alice", "db:read", "anything"}));
    EXPECT_TRUE(PolicyEngine::evaluate(policies, Request{"alice", "db:delete", "anything"}));
    EXPECT_FALSE(PolicyEngine::evaluate(policies, Request{"alice", "s3:read", "anything"}));
}

TEST_F(PolicyEngineTest, DenyFromADifferentPolicyStillWins) {
    // Simulates two separately-attached policies (e.g. a user policy and
    // a group policy) where one allows broadly and the other denies narrowly.
    const Policy allowAll = Policy::fromJsonString(R"({
        "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}]
    })");
    const Policy denyDelete = Policy::fromJsonString(R"({
        "Statement": [{"Effect": "Deny", "Action": ["db:delete"], "Resource": ["*"]}]
    })");
    const std::vector<Policy> policies{allowAll, denyDelete};

    EXPECT_TRUE(PolicyEngine::evaluate(policies, Request{"alice", "db:read", "x"}));
    EXPECT_FALSE(PolicyEngine::evaluate(policies, Request{"alice", "db:delete", "x"}));
}

// --- selectSnapshot: pure, no cache involved ---------------------------

TEST_F(PolicyEngineTest, SelectSnapshotMinimizeLatencyQuantizesToTheBucket) {
    const Snapshot base = bucketAlignedNow();
    const Snapshot now = base + milliseconds(750);

    EXPECT_EQ(PolicyEngine::selectSnapshot(Consistency::MinimizeLatency, Snapshot{}, now, kBucket), base);
}

TEST_F(PolicyEngineTest, SelectSnapshotFullyConsistentUsesTheExactInstant) {
    const Snapshot base = bucketAlignedNow();
    const Snapshot now = base + milliseconds(750);

    // Unquantized on purpose: that is what stops it from ever colliding
    // with the shared bucket entry.
    EXPECT_EQ(PolicyEngine::selectSnapshot(Consistency::FullyConsistent, Snapshot{}, now, kBucket), now);
}

TEST_F(PolicyEngineTest, SelectSnapshotAtLeastAsFreshSharesTheBucketWhenTokenIsOlder) {
    const Snapshot base = bucketAlignedNow();
    const Snapshot now = base + milliseconds(750);
    const Snapshot staleToken = base - kBucket;

    // The current bucket already satisfies this token, so the request
    // lands on the same entry MinimizeLatency traffic uses.
    EXPECT_EQ(PolicyEngine::selectSnapshot(Consistency::AtLeastAsFresh, staleToken, now, kBucket), base);
}

TEST_F(PolicyEngineTest, SelectSnapshotAtLeastAsFreshUsesTheTokenWhenItIsFresher) {
    const Snapshot base = bucketAlignedNow();
    const Snapshot now = base + milliseconds(750);
    const Snapshot freshToken = base + milliseconds(500);

    // Token demands newer than the bucket start -> private snapshot, no
    // sharing. That cost is the price of the stronger guarantee.
    EXPECT_EQ(PolicyEngine::selectSnapshot(Consistency::AtLeastAsFresh, freshToken, now, kBucket), freshToken);
}

// --- evaluateCached ----------------------------------------------------

TEST_F(PolicyEngineTest, EvaluateCachedMinimizeLatencyUsesCacheOnHit) {
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);
    const std::vector<Policy> policies{allowDenyPolicy()};

    // Poison the shared bucket with the wrong answer; a real evaluate()
    // would say true here, so getting false proves the cache was read.
    cache.put(keyFor(allowedRequest), now, Decision::Deny);

    EXPECT_FALSE(PolicyEngine::evaluateCached(cache, policies, allowedRequest, Consistency::MinimizeLatency));
}

TEST_F(PolicyEngineTest, EvaluateCachedFullyConsistentCannotHitTheSharedBucket) {
    // There is no cache-bypass branch any more: FullyConsistent simply
    // selects an exact instant, which is a different key from the bucket.
    const Snapshot base = bucketAlignedNow();
    auto now = base + milliseconds(750);
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);
    const std::vector<Policy> policies{allowDenyPolicy()};

    cache.put(keyFor(allowedRequest), base, Decision::Deny);

    EXPECT_TRUE(PolicyEngine::evaluateCached(cache, policies, allowedRequest, Consistency::FullyConsistent));
}

TEST_F(PolicyEngineTest, EvaluateCachedAtLeastAsFreshSharesTheMinimizeLatencyBucket) {
    const Snapshot base = bucketAlignedNow();
    auto now = base + milliseconds(750);
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);
    const std::vector<Policy> policies{allowDenyPolicy()};

    cache.put(keyFor(allowedRequest), base, Decision::Deny);

    // Old token -> satisfied by the bucket -> reuses that very entry.
    EXPECT_FALSE(PolicyEngine::evaluateCached(
        cache, policies, allowedRequest, Consistency::AtLeastAsFresh, base - kBucket));
}

TEST_F(PolicyEngineTest, EvaluateCachedAtLeastAsFreshMissesWhenTokenIsFresherThanTheBucket) {
    const Snapshot base = bucketAlignedNow();
    auto now = base + milliseconds(750);
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);
    const std::vector<Policy> policies{allowDenyPolicy()};

    cache.put(keyFor(allowedRequest), base, Decision::Deny);

    // Token newer than the bucket start -> different key -> real evaluation.
    EXPECT_TRUE(PolicyEngine::evaluateCached(
        cache, policies, allowedRequest, Consistency::AtLeastAsFresh, base + milliseconds(500)));
}

TEST_F(PolicyEngineTest, EvaluateCachedPopulatesTheCacheForTheNextCaller) {
    auto now = bucketAlignedNow();
    DecisionCache cache(kTtl, [&now] { return now; }, kBucket);
    const std::vector<Policy> policies{allowDenyPolicy()};

    ASSERT_EQ(cache.size(), 0u);
    EXPECT_TRUE(PolicyEngine::evaluateCached(cache, policies, allowedRequest));
    EXPECT_EQ(cache.size(), 1u);

    // Second call at the same bucket now hits rather than re-evaluating.
    const auto cached = cache.get(keyFor(allowedRequest), now);
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(*cached, Decision::Allow);
}
