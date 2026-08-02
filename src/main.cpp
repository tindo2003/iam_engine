// A walkthrough of the assembled system, from an enforcement point's
// point of view: build an AuthorizationService, ask it questions, and
// watch the caches and the revision floor do their work.
//
// Everything below goes through the single public entry point a PEP
// would use -- authz.check(request) -- with no engine internals, no
// caches passed by hand, and no snapshots computed by the caller.

#include <chrono>
#include <cstdio>
#include <string>

#include "iam/service.hpp"

namespace {

using namespace iam;

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

void step(const char* title) {
    std::printf("\n\033[1m%s\033[0m\n", title);
}

void ask(const AuthorizationService& authz, const Request& request) {
    const bool allowed = authz.check(request);
    std::printf("    %-6s %-10s %-22s -> %s\n", request.principal.c_str(),
                request.action.c_str(), request.resource.c_str(),
                allowed ? "ALLOW" : "DENY");
}

void showStats(const AuthorizationService& authz) {
    const AuthorizationService::Stats s = authz.stats();
    std::printf("    whole-check   %zu hits / %zu misses, %zu entries\n", s.checkHits,
                s.checkMisses, s.checkEntries);
    std::printf("    subproblem    %zu hits / %zu misses, %zu entries\n", s.subproblemHits,
                s.subproblemMisses, s.subproblemEntries);
}

} // namespace

int main() {
    // A controllable clock, so the walkthrough can move time deliberately
    // rather than depending on how fast the machine runs.
    auto now = std::chrono::steady_clock::now();
    AuthorizationService::Config config;
    config.clock = [&now] { return now; };
    AuthorizationService authz(config);

    const Request aliceReads{"alice", "db:read", "urn:table:users"};
    const Request bobReads{"bob", "db:read", "urn:table:users"};

    step("1. Nothing is granted by default");
    ask(authz, aliceReads);

    step("2. Grant through a role hierarchy: engineer inherits employee");
    authz.addRole(Role{"employee", {allow("db:read", "urn:table:users")}, {}});
    authz.addRole(Role{"engineer", {allow("db:write", "urn:table:users")}, {"employee"}});
    authz.assign("alice", "engineer");
    // Bob is assigned NOW, before any checks. Every assign() is a write,
    // which advances the revision and makes all earlier cache entries
    // unreachable -- so assigning him later would invalidate exactly the
    // entries step 4 is meant to show him reusing.
    authz.assign("bob", "engineer");
    ask(authz, aliceReads);
    std::printf("    (the grant came from employee, reached via inheritance)\n");

    step("3. Repeat the identical question 1000 times");
    for (int i = 0; i < 1000; ++i) {
        authz.check(aliceReads);
    }
    showStats(authz);
    std::printf("    one evaluation, then the whole-check layer answers everything\n");

    step("4. A different principal holding the same role");
    const size_t roleWorkBefore = authz.stats().subproblemMisses;
    ask(authz, bobReads);
    const AuthorizationService::Stats after = authz.stats();
    showStats(authz);
    std::printf("    bob needed %zu new role evaluations -- alice had already done them\n",
                after.subproblemMisses - roleWorkBefore);

    step("5. Revoke mid-bucket: alice is suspended");
    now += std::chrono::milliseconds(10); // nowhere near the 1000ms boundary
    authz.addRole(Role{"suspended", {deny("db:read", "urn:table:users")}, {}});
    const Snapshot afterRevoke = authz.assign("alice", "suspended");
    ask(authz, aliceReads);
    std::printf("    denied on the very next check -- the write moved the revision,\n");
    std::printf("    so the cached ALLOW became unreachable rather than waiting to expire\n");

    step("6. Bob is unaffected, and can prove he saw the write");
    ask(authz, bobReads);
    std::printf("    bob asked at AtLeastAsFresh(token) -> %s\n",
                authz.check(bobReads, Consistency::AtLeastAsFresh, afterRevoke) ? "ALLOW" : "DENY");

    step("Final cache state");
    showStats(authz);
    std::printf("\n");
    return 0;
}
