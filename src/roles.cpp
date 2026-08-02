#include "iam/roles.hpp"

#include <algorithm>
#include <set>

namespace iam {

RoleGraph::RoleGraph(Clock clock) : clock_(std::move(clock)) {}

namespace {

// Stamp a write, guaranteeing the revision STRICTLY advances.
//
// Two properties, and both matter for correctness rather than tidiness:
//
//   * Never backward. A revision that regressed would make previously
//     unreachable pre-write entries reachable again -- silently undoing a
//     revocation. steady_clock will not do this, but the clock here is
//     injectable, so the invariant is enforced rather than assumed.
//
//   * Never merely equal. std::max(revision_, clock_()) alone is not
//     enough: two writes inside one clock tick would leave the revision
//     unchanged, so the second silently invalidates nothing. steady_clock
//     is monotonic (non-decreasing), NOT strictly increasing, and coarse
//     resolution makes that a real case rather than a theoretical one.
//
// Forcing a one-tick advance when the clock has not moved is the same
// trick a hybrid logical clock uses. Cost: the revision can drift a few
// ticks ahead of real time under a stalled clock, bounded by the number
// of writes. Cheap next to a write that fails to invalidate.
Snapshot stampWrite(Snapshot previous, Snapshot now) {
    return std::max(now, previous + Snapshot::duration{1});
}

} // namespace

void RoleGraph::addRole(Role role) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    roles_[role.name] = role;
    revision_ = stampWrite(revision_, clock_());
}

void RoleGraph::assign(const std::string& principal, const RoleName& role) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    assignments_[principal].push_back(role);
    revision_ = stampWrite(revision_, clock_());
}

Snapshot RoleGraph::revision() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return revision_;
}

const Role* RoleGraph::find(const RoleName& name) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return findUnlocked(name);
}

const Role* RoleGraph::findUnlocked(const RoleName& name) const {
    auto it = roles_.find(name);
    if (it != roles_.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<RoleName> RoleGraph::effectiveRoles(const std::string& principal) const {
    // One shared lock for the whole traversal, not one per node lookup --
    // otherwise a concurrent write could land mid-walk and the result
    // would mix pre- and post-write state. Exactly the bug
    // demos/snapshot_consistency_race.cpp reproduces.
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return effectiveRolesUnlocked(principal);
}

std::vector<RoleName> RoleGraph::effectiveRolesUnlocked(const std::string& principal) const {
    // Breadth-first transitive closure over `inherits`.
    //
    // `visited` is seeded with the direct assignments and updated at
    // ENQUEUE time, not at process time. That pairing -- check and mark at
    // the same moment -- is what makes cycles terminate and stops diamond
    // inheritance from reporting a role twice.
    std::vector<RoleName> ans;

    std::vector<RoleName> curRoles;
    auto assigned = assignments_.find(principal);
    if (assigned != assignments_.end()) {
        curRoles = assigned->second;
    }

    std::set<RoleName> visited(curRoles.begin(), curRoles.end());
    std::vector<RoleName> nextLayer;

    while (!curRoles.empty()) {
        nextLayer.clear();

        for (const RoleName& role : curRoles) {
            ans.push_back(role);

            const Role* found = findUnlocked(role); // already holding the lock
            if (found == nullptr) {
                continue; // an assignment may name a role nobody defined
            }

            for (const RoleName& child : found->inherits) {
                if (visited.count(child) == 0) {
                    nextLayer.push_back(child);
                    visited.insert(child);
                }
            }
        }

        curRoles = nextLayer;
    }

    return ans;
}

} // namespace iam
