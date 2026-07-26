#include "iam/engine.hpp"

namespace iam {

bool PolicyEngine::evaluate(const std::vector<Policy>& policies, const Request& request) {
    bool allowed = false; // default deny

    for (const auto& policy : policies) {
        for (const auto& statement : policy.statements) {
            if (!statement.matchesAction(request.action)) {
                continue;
            }
            if (!statement.matchesResource(request.resource)) {
                continue;
            }

            if (statement.effect == Effect::Deny) {
                return false; // explicit deny short-circuits everything
            }
            allowed = true; // explicit allow, but keep scanning for a later deny
        }
    }

    return allowed;
}

} // namespace iam
