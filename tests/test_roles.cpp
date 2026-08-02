#include <gtest/gtest.h>

#include <algorithm>
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
