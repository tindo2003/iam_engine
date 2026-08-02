#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "iam/policy.hpp"

namespace iam {

using RoleName = std::string;

// A named bundle of policies, optionally absorbing other roles.
//
// `inherits` is what turns evaluation from a flat scan into a graph
// traversal -- and a graph traversal is what finally gives this engine
// real subproblems to cache (see the note on RoleGraph below).
struct Role {
    RoleName name;
    std::vector<Policy> policies;
    std::vector<RoleName> inherits;
};

// Who has which roles, and which roles absorb which.
//
// Note what this changes about evaluation: PolicyEngine::evaluate() today
// ignores request.principal entirely -- the caller is expected to have
// already worked out which policies apply. With RBAC the principal
// becomes load-bearing, because resolving it to a set of roles IS the
// first step of the check.
//
// Why this matters for caching (the reason RBAC came before subproblem
// caching): "does role R allow this action on this resource" is
// independent of WHO asked. Ten principals holding `engineer` all share
// one `engineer` subproblem. That is the decomposition SpiceDB caches --
// subproblems, not whole checks -- and it was unreachable while
// evaluate() was a single flat pass.
// Leaving room for a PAP (Policy Administration Point)
// ----------------------------------------------------
// addRole()/assign() are the write path; everything in PolicyEngine
// takes `const RoleGraph&` and is a pure read. That split is already the
// right shape for a PAP to own writes later without touching the PDP.
//
// The one real gap a PAP has to close: snapshots are currently invented
// by the clock, not derived from actual policy writes, so nothing checks
// that a `policies`/graph state genuinely corresponds to the snapshot a
// caller claims. Closing it means giving RoleGraph a monotonic revision
// bumped by every mutation, and having it report that revision:
//
//     Snapshot revision() const;   // future, not built
//
// Then evaluateRbacCached's snapshot can be tied to a real write rather
// than asserted by whoever calls it, and a ZedToken handed back from a write
// becomes meaningful. That change is purely additive -- no existing
// signature has to move -- which is why it is safe to defer.
class RoleGraph {
public:
    void addRole(Role role);
    void assign(const std::string& principal, const RoleName& role);

    // Null when no such role has been added.
    const Role* find(const RoleName& name) const;

    // Every role this principal effectively holds: their direct
    // assignments plus everything reachable through `inherits`.
    //
    // Must be cycle-safe (roles are user data; A inherits B inherits A is
    // a thing people will write) and must not report a role twice under
    // diamond inheritance.
    std::vector<RoleName> effectiveRoles(const std::string& principal) const;

private:
    std::unordered_map<RoleName, Role> roles_;
    std::unordered_map<std::string, std::vector<RoleName>> assignments_;
};

} // namespace iam
