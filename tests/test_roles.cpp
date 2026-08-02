#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "iam/roles.hpp"

using namespace iam;

namespace {

std::vector<RoleName> sorted(std::vector<RoleName> names) {
    std::sort(names.begin(), names.end());
    return names;
}

} // namespace

TEST(RoleGraph, UnknownPrincipalHasNoRoles) {
    RoleGraph graph;
    EXPECT_TRUE(graph.effectiveRoles("nobody").empty());
}

TEST(RoleGraph, DirectAssignmentOnly) {
    RoleGraph graph;
    graph.addRole(Role{"engineer", {}, {}});
    graph.assign("alice", "engineer");

    EXPECT_EQ(graph.effectiveRoles("alice"), std::vector<RoleName>{"engineer"});
}

TEST(RoleGraph, InheritedRoleIsIncluded) {
    RoleGraph graph;
    graph.addRole(Role{"employee", {}, {}});
    graph.addRole(Role{"engineer", {}, {"employee"}});
    graph.assign("alice", "engineer");

    EXPECT_EQ(sorted(graph.effectiveRoles("alice")),
              (std::vector<RoleName>{"employee", "engineer"}));
}

TEST(RoleGraph, InheritanceIsTransitive) {
    RoleGraph graph;
    graph.addRole(Role{"human", {}, {}});
    graph.addRole(Role{"employee", {}, {"human"}});
    graph.addRole(Role{"engineer", {}, {"employee"}});
    graph.assign("alice", "engineer");

    EXPECT_EQ(sorted(graph.effectiveRoles("alice")),
              (std::vector<RoleName>{"employee", "engineer", "human"}));
}

TEST(RoleGraph, DiamondInheritanceReportsEachRoleOnce) {
    //      base
    //     /    \
    //   left  right
    //     \    /
    //      lead
    RoleGraph graph;
    graph.addRole(Role{"base", {}, {}});
    graph.addRole(Role{"left", {}, {"base"}});
    graph.addRole(Role{"right", {}, {"base"}});
    graph.addRole(Role{"lead", {}, {"left", "right"}});
    graph.assign("alice", "lead");

    EXPECT_EQ(sorted(graph.effectiveRoles("alice")),
              (std::vector<RoleName>{"base", "lead", "left", "right"}));
}

TEST(RoleGraph, CyclicInheritanceTerminates) {
    // If this hangs rather than fails, the visited set is missing.
    RoleGraph graph;
    graph.addRole(Role{"a", {}, {"b"}});
    graph.addRole(Role{"b", {}, {"a"}});
    graph.assign("alice", "a");

    EXPECT_EQ(sorted(graph.effectiveRoles("alice")), (std::vector<RoleName>{"a", "b"}));
}

// --- Revision monotonicity ---------------------------------------------
//
// The revision floor is only sound if the revision never regresses and
// never stalls. Both are enforced rather than assumed, because the clock
// is injectable and therefore not guaranteed to behave.

TEST(RoleGraph, RevisionStartsAtTheEpochBeforeAnyWrite) {
    RoleGraph graph;
    EXPECT_EQ(graph.revision(), Snapshot{});
}

TEST(RoleGraph, RevisionNeverMovesBackward) {
    // A regressing revision would make pre-write cache entries reachable
    // again -- silently resurrecting a revoked permission.
    auto now = std::chrono::steady_clock::now();
    RoleGraph graph([&now] { return now; });

    graph.addRole(Role{"a", {}, {}});
    const Snapshot afterFirstWrite = graph.revision();

    now -= std::chrono::seconds(5); // clock jumps backwards
    graph.addRole(Role{"b", {}, {}});

    EXPECT_GT(graph.revision(), afterFirstWrite);
}

TEST(RoleGraph, RevisionAdvancesEvenWhenTheClockDoesNot) {
    // Two writes inside one clock tick: without a forced advance the
    // second would leave the revision unchanged and invalidate nothing.
    auto frozen = std::chrono::steady_clock::now();
    RoleGraph graph([&frozen] { return frozen; }); // never moves

    graph.addRole(Role{"a", {}, {}});
    const Snapshot afterFirstWrite = graph.revision();
    graph.addRole(Role{"b", {}, {}});

    EXPECT_GT(graph.revision(), afterFirstWrite);
}

// --- Concurrency --------------------------------------------------------

TEST(RoleGraph, AFoundRoleSurvivesAConcurrentOverwrite) {
    // find() used to return `const Role*` into roles_, but the lock is
    // released when it returns -- so addRole() overwriting the same name
    // mutated the object out from under the caller. ThreadSanitizer
    // reported it as a real data race.
    //
    // Roles are now immutable and shared: a write installs a NEW pointer,
    // so a reader's snapshot stays valid and unchanged. Run this file
    // under TSan to actually exercise the guarantee; without it this is
    // only a smoke test.
    RoleGraph graph;
    graph.addRole(Role{"engineer", {}, {"base"}});

    std::atomic<bool> stop{false};
    std::atomic<size_t> observed{0};

    std::thread reader([&] {
        while (!stop.load()) {
            if (std::shared_ptr<const Role> role = graph.find("engineer")) {
                // Dereferenced well after find()'s lock was released.
                const size_t inherited = role->inherits.size();
                EXPECT_TRUE(inherited == 1 || inherited == 2);
                ++observed;
            }
        }
    });

    for (int i = 0; i < 2000; ++i) {
        graph.addRole(Role{"engineer", {}, {"base", "extra"}});
        graph.addRole(Role{"engineer", {}, {"base"}});
    }
    stop.store(true);
    reader.join();

    EXPECT_GT(observed.load(), 0u); // the reader really did run
}

TEST(RoleGraph, ConcurrentReadersSeeAWholeRoleSetNotAHalfWrittenOne) {
    // effectiveRoles holds one lock across the whole traversal, so a
    // concurrent write cannot land mid-walk and produce a set that mixes
    // pre- and post-write state.
    RoleGraph graph;
    graph.addRole(Role{"base", {}, {}});
    graph.addRole(Role{"engineer", {}, {"base"}});
    graph.assign("alice", "engineer");

    std::atomic<bool> stop{false};
    std::vector<std::thread> readers;
    for (int t = 0; t < 4; ++t) {
        readers.emplace_back([&] {
            while (!stop.load()) {
                for (const RoleName& name : graph.effectiveRoles("alice")) {
                    // Every name must be one that actually exists.
                    EXPECT_TRUE(graph.find(name) != nullptr) << "unknown role: " << name;
                }
            }
        });
    }

    for (int i = 0; i < 1000; ++i) {
        graph.addRole(Role{"extra" + std::to_string(i), {}, {}});
    }
    stop.store(true);
    for (std::thread& t : readers) {
        t.join();
    }
}
