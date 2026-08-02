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
    // Install a NEW immutable Role rather than assigning over the old
    // one. Readers holding the previous shared_ptr keep it alive and
    // unchanged; overwriting in place would mutate it underneath them.
    RoleName name = role.name; // copy the key before the value is moved
    roles_[std::move(name)] = std::make_shared<const Role>(std::move(role));
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

std::shared_ptr<const Role> RoleGraph::find(const RoleName& name) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return findUnlocked(name);
}

std::shared_ptr<const Role> RoleGraph::findUnlocked(const RoleName& name) const {
    auto it = roles_.find(name);
    if (it != roles_.end()) {
        // Copies the shared_ptr, not the Role. The caller's snapshot stays
        // valid even after the lock is released and a writer replaces this
        // entry, because a write installs a NEW pointer rather than
        // mutating the one already handed out.
        return it->second;
    }
    return nullptr;
}

std::vector<RoleName> RoleGraph::effectiveRoles(const std::string& principal) const {
    // ONE shared lock, held across the entire traversal -- not one per
    // node lookup. This is why the *Unlocked helpers exist at all: the
    // public methods lock and delegate, and the walk below calls the
    // unlocked variants.
    //
    // Two reasons, and the second is the one that matters.
    //
    //   1. std::shared_mutex is not recursive, so re-acquiring it on
    //      every node would deadlock against ourselves.
    //
    //   2. Releasing between node lookups would let a write land
    //      mid-walk, so the returned role set could mix pre- and
    //      post-write state -- a set this graph never actually held at
    //      any single instant. That is exactly the bug reproduced in
    //      demos/snapshot_consistency_race.cpp, and exactly what a
    //      snapshot timestamp buys Zanzibar (lesson 0007).
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

            const std::shared_ptr<const Role> found =
                findUnlocked(role); // already holding the lock
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
