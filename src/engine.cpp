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
    // TODO:
    // 1. Build a CacheKey from request.principal/action/resource.
    // 2. If consistency == Consistency::FullyConsistent: skip cache.get()
    //    entirely and just call evaluate(). Decide (and leave a comment
    //    explaining) whether you still cache.put() the result for the next
    //    MinimizeLatency caller, or leave the cache untouched -- both are
    //    real, defensible choices real systems make differently.
    // 3. Otherwise: try cache.get(key). On a hit, return it directly
    //    (skip evaluate() -- that's the whole point). On a miss, call
    //    evaluate(), cache.put() the result, then return it.
    CacheKey cache_key = CacheKey{.principal = request.principal, .action = request.action, .resource = request.resource};
    if (consistency == Consistency::FullyConsistent) {
        bool decision = evaluate(policies, request);
        // still cache.put() even though consistency is fully consistent
        cache.put(cache_key, decision, policy_version);
        return decision;
    } else if (consistency == Consistency::AtLeastAsFresh) {
        std::optional<bool> res = cache.get(cache_key, policy_version);
        if (res.has_value()) {
            return res.value();
        } 
    }
    std::optional<bool> res = cache.get(cache_key);
    if (res.has_value()) {
        return res.value();
    }

    bool decision = evaluate(policies, request);
    cache.put(cache_key, decision, policy_version);
    return decision;
}

} // namespace iam
