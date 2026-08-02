#include <gtest/gtest.h>

#include <algorithm>
#include <vector>

#include "iam/engine.hpp"
#include "iam/roles.hpp"

using namespace iam;

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

std::vector<RoleName> sorted(std::vector<RoleName> names) {
    std::sort(names.begin(), names.end());
    return names;
}

const Request kRead{"alice", "db:read", "urn:table:users"};

} // namespace

// --- RoleGraph::effectiveRoles -----------------------------------------

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

// --- evaluateForRole: the cacheable subproblem --------------------------

TEST(EvaluateForRole, UndecidedWhenRoleDoesNotExist) {
    RoleGraph graph;
    EXPECT_EQ(PolicyEngine::evaluateForRole(graph, "ghost", kRead), Decision::Undecided);
}

TEST(EvaluateForRole, UndecidedWhenNothingMatches) {
    RoleGraph graph;
    graph.addRole(Role{"engineer", {allow("db:write", "urn:table:orders")}, {}});

    EXPECT_EQ(PolicyEngine::evaluateForRole(graph, "engineer", kRead), Decision::Undecided);
}

TEST(EvaluateForRole, AllowWhenAStatementMatches) {
    RoleGraph graph;
    graph.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});

    EXPECT_EQ(PolicyEngine::evaluateForRole(graph, "engineer", kRead), Decision::Allow);
}

TEST(EvaluateForRole, DenyBeatsAllowWithinOneRole) {
    RoleGraph graph;
    graph.addRole(Role{"engineer",
                       {allow("db:read", "urn:table:users"), deny("db:read", "urn:table:users")},
                       {}});

    EXPECT_EQ(PolicyEngine::evaluateForRole(graph, "engineer", kRead), Decision::Deny);
}

TEST(EvaluateForRole, IgnoresInheritedRoles) {
    // The subproblem is deliberately one role's OWN policies. Inheritance
    // is evaluateRbac's job -- keeping it out is what makes this unit
    // small enough to be shared across principals.
    RoleGraph graph;
    graph.addRole(Role{"employee", {allow("db:read", "urn:table:users")}, {}});
    graph.addRole(Role{"engineer", {}, {"employee"}});

    EXPECT_EQ(PolicyEngine::evaluateForRole(graph, "engineer", kRead), Decision::Undecided);
}

TEST(EvaluateForRole, DoesNotDependOnThePrincipal) {
    // The property that makes this cacheable: same role, same request
    // shape, different principals -> identical answer, so one cached
    // result serves every holder of the role.
    RoleGraph graph;
    graph.addRole(Role{"engineer", {allow("db:read", "urn:table:users")}, {}});

    const Request asAlice{"alice", "db:read", "urn:table:users"};
    const Request asBob{"bob", "db:read", "urn:table:users"};

    EXPECT_EQ(PolicyEngine::evaluateForRole(graph, "engineer", asAlice),
              PolicyEngine::evaluateForRole(graph, "engineer", asBob));
}

// --- evaluateRbac: combining the subproblems ----------------------------

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
    RoleGraph graph;
    graph.addRole(Role{"engineer", {allow("db:write", "urn:table:orders")}, {}});
    graph.assign("alice", "engineer");

    EXPECT_FALSE(PolicyEngine::evaluateRbac(graph, kRead));
}
