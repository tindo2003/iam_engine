#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "iam/policy.hpp"
#include "iam/types.hpp"

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
// revision() is the piece that closes the PAP gap: it reports the moment
// this graph was last written to, so a cached answer can be tied to the
// data version that produced it rather than merely to wall-clock time.
//
// What that buys, concretely: a write moves every subsequent read onto a
// new cache key IMMEDIATELY, instead of leaving stale answers reachable
// until the quantization bucket happens to roll over. That is lesson
// 0001's new enemy problem solved rather than merely bounded.
//
// Still missing for a real PAP: nothing here persists, authorises, or
// audits a write. This is the mechanism a PAP would drive, not the PAP.
//
// Thread-safe, with a shared_mutex rather than a plain one because the
// access pattern is lopsided: every check reads, only administration
// writes. Readers therefore never block each other.
class RoleGraph {
public:
    using Clock = std::function<Snapshot()>;

    // Injectable clock, same pattern as DecisionCache: tests need to
    // control when a "write" is stamped without sleeping.
    explicit RoleGraph(Clock clock = std::chrono::steady_clock::now);

    // Both mutators stamp the current time as the new revision.
    void addRole(Role role);
    void assign(const std::string& principal, const RoleName& role);

    // Null when no such role has been added.
    //
    // Returns a shared_ptr, NOT a raw pointer, and that is a correctness
    // requirement rather than a style choice. A `const Role*` would point
    // into roles_, but the lock is released the moment find() returns --
    // so a concurrent addRole() overwriting that same name would mutate
    // the object out from under the caller. Confirmed as a real data race
    // under ThreadSanitizer before this was changed.
    //
    // Stored Roles are immutable once created; a write installs a NEW
    // shared_ptr rather than modifying the old one, so any reader holding
    // the previous pointer keeps a consistent snapshot for as long as it
    // needs it. Copy-on-write, in other words.
    std::shared_ptr<const Role> find(const RoleName& name) const;

    // Every role this principal effectively holds: their direct
    // assignments plus everything reachable through `inherits`.
    //
    // Must be cycle-safe (roles are user data; A inherits B inherits A is
    // a thing people will write) and must not report a role twice under
    // diamond inheritance.
    std::vector<RoleName> effectiveRoles(const std::string& principal) const;

    // When this graph was last mutated. A never-written graph sits at the
    // clock's epoch, which is older than any real snapshot and therefore
    // never disturbs the bucket a request would otherwise have chosen.
    Snapshot revision() const;

private:
    // Transitive closure with no locking, for callers already holding one.
    std::vector<RoleName> effectiveRolesUnlocked(const std::string& principal) const;
    std::shared_ptr<const Role> findUnlocked(const RoleName& name) const;

    // Guards every member below. `mutable` so const reads can lock;
    // shared_mutex because checks read constantly and only administration
    // writes, so readers must not queue behind each other.
    //
    // Locking discipline:
    //   shared   find(), effectiveRoles(), revision()
    //   unique   addRole(), assign()
    //
    // effectiveRoles() holds its shared lock across the WHOLE traversal
    // rather than re-taking it per node -- see the comment on its
    // definition. That is what the *Unlocked helpers above are for, and
    // they must only be called with this already held.
    mutable std::shared_mutex mutex_;
    Clock clock_;
    Snapshot revision_{};
    // Values are immutable and shared: writers replace the pointer,
    // never the pointee, so readers that already took a copy are
    // unaffected by a concurrent write.
    std::unordered_map<RoleName, std::shared_ptr<const Role>> roles_;
    std::unordered_map<std::string, std::vector<RoleName>> assignments_;
};

} // namespace iam
