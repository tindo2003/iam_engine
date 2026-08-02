#include "iam/roles.hpp"

#include <set>

namespace iam {

void RoleGraph::addRole(Role role) {
    roles_[role.name] = role;
}

void RoleGraph::assign(const std::string& principal, const RoleName& role) {
    assignments_[principal].push_back(role);
}

const Role* RoleGraph::find(const RoleName& name) const {
    auto it = roles_.find(name);
    if (it != roles_.end()) {
        return &it->second;
    }
    return nullptr;
}

std::vector<RoleName> RoleGraph::effectiveRoles(const std::string& principal) const {
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

            const Role* found = find(role);
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
