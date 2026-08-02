#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "iam/service.hpp"

using namespace iam;
using std::chrono::milliseconds;

namespace {

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

const Request kRead{"alice", "db:read", "urn:table:users"};

} // namespace

TEST(AuthorizationService, DeniesByDefault) {
    AuthorizationService authz;
    EXPECT_FALSE(authz.check(kRead));
}

TEST(AuthorizationService, AllowsThroughARole) {
    AuthorizationService authz;
    authz.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    authz.assign("alice", "engineer");

    EXPECT_TRUE(authz.check(kRead));
}

TEST(AuthorizationService, AllowsThroughInheritance) {
    AuthorizationService authz;
    authz.addRole(Role{"employee", {allow("db:read", "urn:table:users")}, {}});
    authz.addRole(Role{"engineer", {}, {"employee"}});
    authz.assign("alice", "engineer");

    EXPECT_TRUE(authz.check(kRead));
}

TEST(AuthorizationService, DenyStillOutranksAllow) {
    AuthorizationService authz;
    authz.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    authz.addRole(Role{"suspended", {deny("db:read", "urn:table:users")}, {}});
    authz.assign("alice", "engineer");
    authz.assign("alice", "suspended");

    EXPECT_FALSE(authz.check(kRead));
}

TEST(AuthorizationService, RepeatedChecksAreServedFromCache) {
    AuthorizationService authz;
    authz.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    authz.assign("alice", "engineer");

    ASSERT_TRUE(authz.check(kRead));
    const size_t missesAfterFirst = authz.stats().checkMisses;

    for (int i = 0; i < 100; ++i) {
        EXPECT_TRUE(authz.check(kRead));
    }

    // No further misses: every repeat came from the whole-check layer.
    EXPECT_EQ(authz.stats().checkMisses, missesAfterFirst);
    EXPECT_EQ(authz.stats().checkHits, 100u);
}

TEST(AuthorizationService, PrincipalsSharingARoleShareTheSubproblem) {
    AuthorizationService authz;
    authz.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    authz.assign("alice", "engineer");
    authz.assign("bob", "engineer");

    EXPECT_TRUE(authz.check(Request{"alice", "db:read", "urn:table:users"}));
    EXPECT_TRUE(authz.check(Request{"bob", "db:read", "urn:table:users"}));

    const AuthorizationService::Stats stats = authz.stats();
    EXPECT_EQ(stats.checkEntries, 2u);      // two principals, two answers
    EXPECT_EQ(stats.subproblemEntries, 1u); // but one role evaluation
}

TEST(AuthorizationService, AWriteTakesEffectOnTheNextCheck) {
    // The revision floor, reached through the facade: no waiting for a
    // bucket boundary.
    auto now = std::chrono::steady_clock::now();
    AuthorizationService::Config config;
    config.clock = [&now] { return now; };
    AuthorizationService authz(config);

    authz.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    authz.assign("alice", "engineer");
    ASSERT_TRUE(authz.check(kRead));

    now += milliseconds(10); // nowhere near the 1000ms bucket boundary

    authz.addRole(Role{"suspended", {deny("db:read", "urn:table:users")}, {}});
    authz.assign("alice", "suspended");

    EXPECT_FALSE(authz.check(kRead));
}

TEST(AuthorizationService, AWriteReturnsATokenThatGuaranteesReadYourOwnWrite) {
    AuthorizationService authz;
    authz.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    const Snapshot token = authz.assign("alice", "engineer");

    EXPECT_EQ(token, authz.revision());
    EXPECT_TRUE(authz.check(kRead, Consistency::AtLeastAsFresh, token));
}

TEST(AuthorizationService, FullyConsistentAlwaysReevaluates) {
    AuthorizationService authz;
    authz.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    authz.assign("alice", "engineer");

    for (int i = 0; i < 10; ++i) {
        EXPECT_TRUE(authz.check(kRead, Consistency::FullyConsistent));
    }
    // Every one picked a private snapshot, so none could reuse another.
    EXPECT_EQ(authz.stats().checkHits, 0u);
}

TEST(AuthorizationService, ConfiguredDefaultConsistencyIsUsed) {
    AuthorizationService::Config config;
    config.defaultConsistency = Consistency::FullyConsistent;
    AuthorizationService authz(config);

    authz.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    authz.assign("alice", "engineer");

    EXPECT_TRUE(authz.check(kRead));
    EXPECT_TRUE(authz.check(kRead));
    EXPECT_EQ(authz.stats().checkHits, 0u); // the default really applied
}

TEST(AuthorizationService, IsSafeToShareAcrossRequestThreads) {
    AuthorizationService authz;
    authz.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});
    for (int p = 0; p < 32; ++p) {
        authz.assign("user" + std::to_string(p), "engineer");
    }

    // Held by const reference, exactly as a request handler would.
    const AuthorizationService& shared = authz;

    std::atomic<int> allowed{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < 200; ++i) {
                const std::string principal = "user" + std::to_string((t * 5 + i) % 32);
                if (shared.check(Request{principal, "db:read", "urn:table:users"})) {
                    ++allowed;
                }
            }
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }

    EXPECT_EQ(allowed.load(), 8 * 200);
}
