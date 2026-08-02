#include <gtest/gtest.h>

#include <chrono>

#include "iam/cache.hpp"
#include "iam/engine.hpp"
#include "iam/policy.hpp"
#include "iam/roles.hpp"

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

// The request most tests use. allowDenyPolicy() genuinely allows it, so
// any test that gets back `false` for it must have read a poisoned cache
// entry rather than evaluated for real.
const Request kRead{"alice", "db:read", "urn:table:users"};

// Single-statement policy builders, for tests that need a role to say
// exactly one thing.
Policy allow(const std::string& action, const std::string& resource) {
    return Policy::fromJsonString(
        R"({"Statement": [{"Effect": "Allow", "Action": [")" + action +
        R"("], "Resource": [")" + resource + R"("]}]})");
}

Policy deny(const std::string& action, const std::string& resource) {
    return Policy::fromJsonString(
        R"({"Statement": [{"Effect": "Deny", "Action": [")" + action +
        R"("], "Resource": [")" + resource + R"("]}]})");
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

// --- evaluateRbac (public) ---------------------------------------------

TEST(EvaluateRbac, DefaultDenyForAnUnknownPrincipal) {
    RoleGraph graph;
    EXPECT_FALSE(PolicyEngine::evaluateRbac(graph, kRead));
}

TEST(EvaluateRbac, AllowsViaADirectRole) {
    RoleGraph graph;
    graph.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    graph.assign("alice", "engineer");

    EXPECT_TRUE(PolicyEngine::evaluateRbac(graph, kRead));
}

TEST(EvaluateRbac, AllowsViaAnInheritedRole) {
    RoleGraph graph;
    graph.addRole(Role{"employee", {allow("db:read", "urn:table:users")}, {}});
    graph.addRole(Role{"engineer", {}, {"employee"}});
    graph.assign("alice", "engineer");

    EXPECT_TRUE(PolicyEngine::evaluateRbac(graph, kRead));
}

TEST(EvaluateRbac, DenyBeatsAllowWithinOneRole) {
    RoleGraph graph;
    graph.addRole(Role{"engineer",
                       {allow("db:read", "urn:table:users"), deny("db:read", "urn:table:users")},
                       {}});
    graph.assign("alice", "engineer");

    EXPECT_FALSE(PolicyEngine::evaluateRbac(graph, kRead));
}

TEST(EvaluateRbac, DenyInOneRoleBeatsAllowInAnother) {
    // The trap: whichever order effectiveRoles() happens to return these
    // in, the Deny has to win. Returning true on the first Allow fails
    // this roughly half the time.
    RoleGraph graph;
    graph.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    graph.addRole(Role{"suspended", {deny("db:read", "urn:table:users")}, {}});
    graph.assign("alice", "engineer");
    graph.assign("alice", "suspended");

    EXPECT_FALSE(PolicyEngine::evaluateRbac(graph, kRead));
}

TEST(EvaluateRbac, DenyFromAnInheritedRoleAlsoWins) {
    RoleGraph graph;
    graph.addRole(Role{"probation", {deny("db:read", "urn:table:users")}, {}});
    graph.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {"probation"}});
    graph.assign("alice", "engineer");

    EXPECT_FALSE(PolicyEngine::evaluateRbac(graph, kRead));
}

TEST(EvaluateRbac, DeniedWhenEveryRoleIsUndecided) {
    // A role that matches nothing must not be read as a grant -- but it
    // must not veto either. Global default-deny is what makes this false.
    RoleGraph graph;
    graph.addRole(Role{"engineer", {allow("db:write", "urn:table:orders")}, {}});
    graph.assign("alice", "engineer");

    EXPECT_FALSE(PolicyEngine::evaluateRbac(graph, kRead));
}

// --- Both layers together ----------------------------------------------

TEST(RbacCached, PopulatesBothLayers) {
    auto now = bucketAlignedNow();
    DecisionCache checkCache(kTtl, [&now] { return now; }, kBucket);
    DecisionCache subproblemCache(kTtl, [&now] { return now; }, kBucket);
    RoleGraph graph;
    graph.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    graph.assign("alice", "engineer");

    EXPECT_TRUE(PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph, kRead));
    EXPECT_EQ(checkCache.size(), 1u); // alice's whole-check answer
    EXPECT_EQ(subproblemCache.size(), 1u);  // the engineer subproblem
}

TEST(RbacCached, SecondPrincipalReusesTheRoleWork) {
    auto now = bucketAlignedNow();
    DecisionCache checkCache(kTtl, [&now] { return now; }, kBucket);
    DecisionCache subproblemCache(kTtl, [&now] { return now; }, kBucket);
    RoleGraph graph;
    graph.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    graph.assign("alice", "engineer");
    graph.assign("bob", "engineer");

    PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph,
                                     Request{"alice", "db:read", "urn:table:users"});
    PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph,
                                     Request{"bob", "db:read", "urn:table:users"});

    EXPECT_EQ(checkCache.size(), 2u); // two distinct principals, two answers
    EXPECT_EQ(subproblemCache.size(), 1u);  // but only ONE role evaluation between them
}

TEST(RbacCached, RepeatRequestHitsTheWholeCheckLayer) {
    auto now = bucketAlignedNow();
    DecisionCache checkCache(kTtl, [&now] { return now; }, kBucket);
    DecisionCache subproblemCache(kTtl, [&now] { return now; }, kBucket);
    RoleGraph graph;
    graph.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    graph.assign("alice", "engineer");

    // Poison layer 1 only. If it is consulted first, the role layer is
    // never reached and stays empty.
    checkCache.put(CacheKey{"alice", "db:read", "urn:table:users"}, now, Decision::Deny);

    EXPECT_FALSE(PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph, kRead));
    EXPECT_EQ(subproblemCache.size(), 0u);
}

TEST(RbacCached, StillHonoursDenyAcrossRoles) {
    // The combining rules must not change just because layers were added.
    auto now = bucketAlignedNow();
    DecisionCache checkCache(kTtl, [&now] { return now; }, kBucket);
    DecisionCache subproblemCache(kTtl, [&now] { return now; }, kBucket);
    RoleGraph graph;
    graph.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    graph.addRole(Role{"suspended", {deny("db:read", "urn:table:users")}, {}});
    graph.assign("alice", "engineer");
    graph.assign("alice", "suspended");

    EXPECT_FALSE(PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph, kRead));
}

// --- Name collisions between the two layers ----------------------------
//
// The layers key on the same shape and differ only in what `subject`
// means, so a role and a person sharing a name is the interesting case.
// Separate DecisionCache instances are what keep them apart; these pin
// that both directions stay correct.

TEST(RbacCached, PersonNamedLikeARoleDoesNotInheritIt) {
    auto now = bucketAlignedNow();
    DecisionCache checkCache(kTtl, [&now] { return now; }, kBucket);
    DecisionCache subproblemCache(kTtl, [&now] { return now; }, kBucket);

    RoleGraph graph;
    graph.addRole(Role{"employee", {allow("db:read", "urn:table:handbook")}, {}});
    graph.assign("alice", "employee");
    // NOTE: the person literally named "employee" holds no roles at all.

    const Request aliceReads{"alice", "db:read", "urn:table:handbook"};
    const Request personNamedEmployee{"employee", "db:read", "urn:table:handbook"};

    // Alice's check populates the subproblem layer under subject "employee"
    // -- meaning the ROLE.
    ASSERT_TRUE(PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph, aliceReads));
    ASSERT_EQ(subproblemCache.size(), 1u);

    // The PERSON of the same name must not pick that up. Sharing one cache
    // between the layers would return true here: privilege escalation by
    // name collision.
    EXPECT_FALSE(
        PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph, personNamedEmployee));
}

TEST(RbacCached, RoleNamedLikeAPersonIsNotPoisonedByThem) {
    // Same collision, opposite order and opposite failure: the person's
    // cached denial must not be read back as the role's answer.
    auto now = bucketAlignedNow();
    DecisionCache checkCache(kTtl, [&now] { return now; }, kBucket);
    DecisionCache subproblemCache(kTtl, [&now] { return now; }, kBucket);

    RoleGraph graph;
    graph.addRole(Role{"employee", {allow("db:read", "urn:table:handbook")}, {}});
    graph.assign("alice", "employee");

    const Request personNamedEmployee{"employee", "db:read", "urn:table:handbook"};
    const Request aliceReads{"alice", "db:read", "urn:table:handbook"};

    // The role-less person goes first and is correctly denied.
    ASSERT_FALSE(
        PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph, personNamedEmployee));

    // Alice still gets her grant. With one shared cache the subproblem
    // lookup for role "employee" would hit the person's Deny instead.
    EXPECT_TRUE(PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph, aliceReads));
}

// The subproblem layer is private, so these reach it the only way a real
// caller can -- through evaluateRbacCached, inspecting the cache after.

TEST(RbacCached, ReadsAPoisonedSubproblemEntryRatherThanReevaluating) {
    auto now = bucketAlignedNow();
    DecisionCache checkCache(kTtl, [&now] { return now; }, kBucket);
    DecisionCache subproblemCache(kTtl, [&now] { return now; }, kBucket);

    RoleGraph graph;
    graph.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    graph.assign("alice", "engineer");

    // Poison layer 2 only. The role genuinely allows this, so a `false`
    // proves the cached entry was used instead of a fresh evaluation.
    subproblemCache.put(CacheKey{"engineer", "db:read", "urn:table:users"}, now, Decision::Deny);

    EXPECT_FALSE(PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph, kRead));
}

TEST(RbacCached, CachesUndecidedRolesRatherThanSkippingThem) {
    // A role that matched nothing must be stored as Undecided, not left
    // uncached. Treating "nothing matched" as a miss would re-evaluate a
    // known-empty role on every single request forever.
    auto now = bucketAlignedNow();
    DecisionCache checkCache(kTtl, [&now] { return now; }, kBucket);
    DecisionCache subproblemCache(kTtl, [&now] { return now; }, kBucket);

    RoleGraph graph;
    graph.addRole(Role{"engineer", {allow("db:write", "urn:table:orders")}, {}});
    graph.assign("alice", "engineer");

    EXPECT_FALSE(PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph, kRead));
    ASSERT_EQ(subproblemCache.size(), 1u);

    const auto cached = subproblemCache.get(CacheKey{"engineer", "db:read", "urn:table:users"}, now);
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(*cached, Decision::Undecided);
}

// Consistency-level integration, now that evaluateRbacCached is the only
// cached entry point. selectSnapshot is unit-tested above; these check
// the wiring actually honours what it returns.

TEST(RbacCached, FullyConsistentCannotHitTheSharedBucket) {
    const Snapshot base = bucketAlignedNow();
    auto now = base + milliseconds(750);
    DecisionCache checkCache(kTtl, [&now] { return now; }, kBucket);
    DecisionCache subproblemCache(kTtl, [&now] { return now; }, kBucket);

    RoleGraph graph;
    graph.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    graph.assign("alice", "engineer");

    // Poison the shared bucket. FullyConsistent selects an exact instant,
    // which is a different key, so it cannot reach this entry.
    checkCache.put(CacheKey{"alice", "db:read", "urn:table:users"}, base, Decision::Deny);

    EXPECT_TRUE(PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph, kRead,
                                                    Consistency::FullyConsistent));
}

TEST(RbacCached, AtLeastAsFreshSharesTheMinimizeLatencyBucket) {
    const Snapshot base = bucketAlignedNow();
    auto now = base + milliseconds(750);
    DecisionCache checkCache(kTtl, [&now] { return now; }, kBucket);
    DecisionCache subproblemCache(kTtl, [&now] { return now; }, kBucket);

    RoleGraph graph;
    graph.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    graph.assign("alice", "engineer");

    checkCache.put(CacheKey{"alice", "db:read", "urn:table:users"}, base, Decision::Deny);

    // Old token -> already satisfied by the bucket -> reuses that entry.
    EXPECT_FALSE(PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph, kRead,
                                                    Consistency::AtLeastAsFresh, base - kBucket));
}

TEST(RbacCached, AtLeastAsFreshMissesWhenTokenIsFresherThanTheBucket) {
    const Snapshot base = bucketAlignedNow();
    auto now = base + milliseconds(750);
    DecisionCache checkCache(kTtl, [&now] { return now; }, kBucket);
    DecisionCache subproblemCache(kTtl, [&now] { return now; }, kBucket);

    RoleGraph graph;
    graph.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    graph.assign("alice", "engineer");

    checkCache.put(CacheKey{"alice", "db:read", "urn:table:users"}, base, Decision::Deny);

    // Token demands newer than the bucket start -> different key -> real
    // evaluation, so the poisoned entry is not reached.
    EXPECT_TRUE(PolicyEngine::evaluateRbacCached(checkCache, subproblemCache, graph, kRead,
                                                    Consistency::AtLeastAsFresh,
                                                    base + milliseconds(500)));
}
