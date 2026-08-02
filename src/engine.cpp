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

Snapshot PolicyEngine::selectSnapshot(Consistency consistency,
                                    Snapshot minSnapshot,
                                    Snapshot now,
                                    std::chrono::milliseconds bucketSize) {
    // Deliberately exhaustive, no `default:` -- if Consistency ever grows a
    // new value, this should fail to compile (-Wswitch) instead of silently
    // falling into the wrong branch.
    switch (consistency) {
        case Consistency::MinimizeLatency:
            // Everyone in this window computes the same bucket, so they all
            // share one cache entry by construction.
            return quantize(now, bucketSize);

        case Consistency::AtLeastAsFresh: {
            // If the shared bucket already satisfies the caller's token,
            // reuse it -- that is the common case, and it means a
            // token-bearing request still shares with MinimizeLatency
            // traffic. Only a token newer than the bucket forces a private,
            // unshared snapshot.
            const Snapshot bucket = quantize(now, bucketSize);
            return bucket >= minSnapshot ? bucket : minSnapshot;
        }

        case Consistency::FullyConsistent:
            // Exact instant, unquantized: essentially never collides with
            // an existing key, which is what disables reuse. No explicit
            // cache bypass needed anywhere.
            return now;
    }

    return now; // unreachable; keeps -Wreturn-type quiet
}

bool PolicyEngine::evaluateCached(DecisionCache& cache,
                                const std::vector<Policy>& policies,
                                const Request& request,
                                Consistency consistency,
                                Snapshot minSnapshot) {
    const CacheKey cache_key{.principal = request.principal, .action = request.action, .resource = request.resource};
    const Snapshot snapshot = selectSnapshot(consistency, minSnapshot, cache.now(), cache.bucketSize());

    if (std::optional<bool> cached = cache.get(cache_key, snapshot)) {
        return *cached;
    }

    const bool decision = evaluate(policies, request);
    cache.put(cache_key, snapshot, decision);
    return decision;
}

} // namespace iam
