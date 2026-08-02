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


Decision PolicyEngine::evaluateForRole(const RoleGraph& graph,
                                        const RoleName& role,
                                        const Request& request) {
    // Reads only this role's OWN policies -- `inherits` is evaluateRbac's
    // job. Tri-state because "denies" and "has nothing to say" must stay
    // distinguishable; see the note on Decision in engine.hpp.
    const Role* found = graph.find(role);
    if (found == nullptr) {
        return Decision::Undecided; // no such role: says nothing, denies nothing
    }

    Decision decision = Decision::Undecided;

    for (const auto& policy : found->policies) {
        for (const auto& statement : policy.statements) {
            if (!statement.matchesAction(request.action)) {
                continue;
            }
            if (!statement.matchesResource(request.resource)) {
                continue;
            }
            switch (statement.effect) {
                case Effect::Deny:
                    return Decision::Deny; // nothing can outrank a Deny
                case Effect::Allow:
                    decision = Decision::Allow; // keep scanning for a later Deny
                    break;
            }
        }
    }

    return decision;
}

bool PolicyEngine::evaluateRbac(const RoleGraph& graph, const Request& request) {
    // Resolves the principal to their effective roles (direct plus
    // everything inherited), asks each role independently, then combines:
    //
    //     any Deny       -> false
    //     else any Allow -> true
    //     else           -> false   (default deny, applied once, globally)
    //
    // Note the asymmetry in how the two outcomes are handled below: a Deny
    // returns immediately because nothing can outrank it, but an Allow
    // only sets a flag and keeps scanning, because a later role may still
    // Deny. This is the same rule evaluate() follows across statements,
    // now applied across roles.
    //
    // Collapsing Decision::Undecided into Deny here would be wrong for the
    // same reason it is wrong inside evaluateForRole: a role that simply
    // never mentions this resource must not veto a grant from another
    // role. Undecided contributes nothing in either direction; global
    // default-deny is what turns "nobody allowed it" into false, and it
    // applies exactly once, at the end.
    std::vector<RoleName> roles = graph.effectiveRoles(request.principal);
    std::vector<Decision> decisions;
    for (const RoleName& role: roles) {
        decisions.push_back(evaluateForRole(graph, role, request));
    }
    bool allowed = false;
    for (const Decision& decision: decisions) {
        if (decision == Decision::Deny) {
            return false;
        } else if (decision == Decision::Allow) {
            allowed = true;
        }
    }
    return allowed;
}

} // namespace iam
