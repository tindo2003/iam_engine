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

bool PolicyEngine::evaluateCached(DecisionCache& cache,
                                const std::vector<Policy>& policies,
                                const Request& request,
                                Consistency consistency,
                                PolicyVersion policy_version) {
    const CacheKey cache_key{.principal = request.principal, .action = request.action, .resource = request.resource};

    // Deliberately exhaustive, no `default:` -- if Consistency ever grows a
    // new value, this should fail to compile (-Wswitch) instead of silently
    // falling into the wrong branch.
    std::optional<bool> cached;
    switch (consistency) {
        case Consistency::FullyConsistent:
            // A fully-consistent caller must never see a cached answer, so
            // `cached` stays unset and we fall through to evaluate() below.
            // We still cache.put() the fresh result afterward, so the next
            // MinimizeLatency caller benefits from this evaluation.
            break;
        case Consistency::MinimizeLatency:
            cached = cache.get(cache_key);
            break;
        case Consistency::AtLeastAsFresh:
            cached = cache.get(cache_key, policy_version);
            break;
    }

    if (cached.has_value()) {
        return *cached;
    }

    bool decision = evaluate(policies, request);
    cache.put(cache_key, decision, policy_version);
    return decision;
}

} // namespace iam
