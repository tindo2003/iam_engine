#include <gtest/gtest.h>

#include <chrono>

#include "iam/cache.hpp"
#include "iam/engine.hpp"
#include "iam/policy.hpp"

using namespace iam;

namespace {

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

TEST_F(PolicyEngineTest, EvaluateCachedFullyConsistentBypassesCache) {
    auto now = std::chrono::steady_clock::now();
    DecisionCache cache(std::chrono::milliseconds(60'000), [&now] { return now; });
    const std::vector<Policy> policies{allowDenyPolicy()};
    const Request request{"alice", "db:read", "urn:table:users"};

    // Poison the cache with a wrong cached answer -- proves FullyConsistent
    // genuinely ignores it rather than just happening to agree.
    cache.put(CacheKey{request.principal, request.action, request.resource}, false, /*version=*/1);

    EXPECT_TRUE(PolicyEngine::evaluateCached(cache, policies, request, Consistency::FullyConsistent));
}

TEST_F(PolicyEngineTest, EvaluateCachedMinimizeLatencyUsesCacheOnHit) {
    auto now = std::chrono::steady_clock::now();
    DecisionCache cache(std::chrono::milliseconds(60'000), [&now] { return now; });
    const std::vector<Policy> policies{allowDenyPolicy()};
    const Request request{"alice", "db:read", "urn:table:users"};

    // Seed a wrong cached answer directly, bypassing evaluate() -- if
    // MinimizeLatency reads the cache like it should, it returns this
    // (wrong) cached value instead of recomputing the real one.
    cache.put(CacheKey{request.principal, request.action, request.resource}, false, /*version=*/1);

    EXPECT_FALSE(PolicyEngine::evaluateCached(cache, policies, request, Consistency::MinimizeLatency));
}

// AtLeastAsFresh
// I put policy_version = 1, I get min_version = 2 -> cache miss, i evaluate again 
    // the cache at version 1 contains true 
// I put policy_version = 3, I get min_version = 2, and time passed till less than ttl -> cache hit, i get value from the cache 
// I put policy_version = 3, i get min_version = 2, and time passed greater than ttl -> cache miss, i evaluate again
TEST_F(PolicyEngineTest, EvaluateCachedAtLeastAsFreshReevaluatesOnVersionMiss) {
    auto now = std::chrono::steady_clock::now();
    DecisionCache cache(std::chrono::milliseconds(60'000), [&now] { return now; });
    // empty policies, auto deny for all requests
    const std::vector<Policy> policies; 
    const Request request{"alice", "db:read", "urn:table:users"};
    
    cache.put(CacheKey{request.principal, request.action, request.resource}, true, /*version=*/1);
    EXPECT_FALSE(PolicyEngine::evaluateCached(cache, policies, request, Consistency::AtLeastAsFresh, /*policy_version=*/2));    
}

TEST_F(PolicyEngineTest, EvaluateCachedAtLeastAsFreshCacheHit) {
    auto now = std::chrono::steady_clock::now();
    DecisionCache cache(std::chrono::milliseconds(1000), [&now] { return now; });
    // empty policies, auto deny for all requests
    const std::vector<Policy> policies; 
    const Request request{"alice", "db:read", "urn:table:users"}; 

    cache.put(CacheKey{request.principal, request.action, request.resource}, true, /*version=*/2);
    // cache hits because version is less (1 < 2) and time passed is less than ttl
    now += std::chrono::milliseconds(900);
    EXPECT_TRUE(PolicyEngine::evaluateCached(cache, policies, request, Consistency::AtLeastAsFresh, /*policy_version=*/1)); 
}

TEST_F(PolicyEngineTest, EvaluateCachedAtLeastAsFreshReevaluatesOnTtlMiss) {
    auto now = std::chrono::steady_clock::now();
    DecisionCache cache(std::chrono::milliseconds(1000), [&now] { return now; });
    // empty policies, auto deny for all requests
    const std::vector<Policy> policies; 
    const Request request{"alice", "db:read", "urn:table:users"}; 

    cache.put(CacheKey{request.principal, request.action, request.resource}, true, /*version=*/2);
    // cache miss time passed is greater than ttl
    now += std::chrono::milliseconds(1100);
    EXPECT_FALSE(PolicyEngine::evaluateCached(cache, policies, request, Consistency::AtLeastAsFresh, /*policy_version=*/1));
}