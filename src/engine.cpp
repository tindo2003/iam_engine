#include "iam/engine.hpp"

namespace iam {
namespace {

// The one definition of how per-role answers become a final verdict.
//
//     any Deny       -> false
//     else any Allow -> true
//     else           -> false   (default deny, applied once, globally)
//
// Undecided contributes in neither direction: a role that never mentions
// this resource must not veto a grant from another role.
//
// File-local on purpose -- it is an implementation detail, not API. Both
// evaluateRbac() and evaluateRbacCached() route through it so the rule
// cannot drift between them.
//
// Note this takes a fully-built vector, so callers evaluate every role
// even when an early Deny makes the rest irrelevant. That is a deliberate
// trade: one definition of the rule beats a short-circuit at this scale.
bool combine(const std::vector<Decision>& decisions) {
    bool allowed = false;

    for (const Decision& decision : decisions) {
        if (decision == Decision::Deny) {
            return false; // nothing can outrank a Deny
        }
        if (decision == Decision::Allow) {
            allowed = true; // keep scanning; a later role may still Deny
        }
    }

    return allowed;
}

} // namespace

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
    const CacheKey cache_key{.subject = request.principal, .action = request.action, .resource = request.resource};
    const Snapshot snapshot = selectSnapshot(consistency, minSnapshot, cache.now(), cache.bucketSize());

    // A whole-check answer is genuinely binary -- global default-deny has
    // already been applied by evaluate() -- so this layer only ever stores
    // Allow or Deny, never Undecided. The tri-state value type exists for
    // the subproblem layer, which shares this same cache type.
    if (std::optional<Decision> cached = cache.get(cache_key, snapshot)) {
        return *cached == Decision::Allow;
    }

    const bool decision = evaluate(policies, request);
    cache.put(cache_key, snapshot, decision ? Decision::Allow : Decision::Deny);
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
    std::vector<Decision> decisions;
    for (const RoleName& role : graph.effectiveRoles(request.principal)) {
        decisions.push_back(evaluateForRole(graph, role, request));
    }
    return combine(decisions);
}

Decision PolicyEngine::evaluateForRoleCached(DecisionCache& subproblemCache,
                                            const RoleGraph& graph,
                                            const RoleName& role,
                                            const Request& request,
                                            Consistency consistency,
                                            Snapshot minSnapshot) {
    // TODO: the cached wrapper around evaluateForRole().
    //
    // Same shape as evaluateCached() above -- build a key, pick a
    // snapshot with selectSnapshot(), try the cache, compute + store on a
    // miss. Two differences that matter:
    //
    //   1. The key's `subject` is the ROLE name, not request.principal.
    //      Everything else (action, resource) still comes from `request`.
    //      Getting this wrong is the whole point of the exercise: bake in
    //      the principal and nothing is ever shared between users.
    //
    //   2. No bool conversion. Store the Decision as-is, Undecided
    //      included -- a cached Undecided is a real answer ("this role
    //      matched nothing"), not a miss. Collapsing it re-evaluates a
    //      known-empty role forever.
    const CacheKey cache_key{.subject = role, .action = request.action, .resource = request.resource};
    const Snapshot snapshot = selectSnapshot(consistency, minSnapshot, subproblemCache.now(), subproblemCache.bucketSize());

    if (std::optional<Decision> cached = subproblemCache.get(cache_key, snapshot)) {
        return *cached;
    }

    const Decision decision = evaluateForRole(graph, role, request);
    subproblemCache.put(cache_key, snapshot, decision);
    return decision;
}

bool PolicyEngine::evaluateRbacCached(DecisionCache& checkCache,
                                    DecisionCache& subproblemCache,
                                    const RoleGraph& graph,
                                    const Request& request,
                                    Consistency consistency,
                                    Snapshot minSnapshot) {
    // TODO: wire both layers together.
    //
    //   1. Layer 1: build a key from request.principal and try
    //      checkCache. A hit returns immediately -- an identical repeat
    //      request never touches the role layer at all.
    //
    //   2. On a miss, do what evaluateRbac() does, except call
    //      evaluateForRoleCached() (layer 2) instead of the uncached
    //      evaluateForRole(). Pass `consistency` and `minSnapshot`
    //      straight through so both layers agree on a snapshot.
    //
    //   3. Store the combined result in checkCache before returning.
    //
    // Combining rules are unchanged from evaluateRbac: Deny returns
    // immediately, Allow only sets a flag, and default-deny applies once
    // at the end. Consider whether you can just reuse that logic rather
    // than writing the loop a second time -- two copies of a combine rule
    // is exactly how they drift apart later.
    const CacheKey check_key{.subject = request.principal,
                            .action = request.action,
                            .resource = request.resource};
    const Snapshot snapshot = selectSnapshot(consistency, minSnapshot,
                                            checkCache.now(), checkCache.bucketSize());

    if (std::optional<Decision> cached = checkCache.get(check_key, snapshot)) {
        return *cached == Decision::Allow;   // layer 1 IS binary, so convert here
    }

    // Layer 1 missed. Resolve roles and ask layer 2 for each -- other
    // principals holding these same roles may already have populated it.
    std::vector<Decision> decisions;
    for (const RoleName& role : graph.effectiveRoles(request.principal)) {
        decisions.push_back(
            evaluateForRoleCached(subproblemCache, graph, role, request, consistency, minSnapshot));
    }

    // Same combining rule as evaluateRbac, by construction -- one shared
    // definition rather than a second copy of the loop.
    const bool decision = combine(decisions);

    // Must reach this store on every path, which is why combine() returns
    // rather than the loop returning early on a Deny: an uncached denial
    // would re-run the whole traversal on every repeat request.
    checkCache.put(check_key, snapshot, decision ? Decision::Allow : Decision::Deny);
    return decision;
}

} // namespace iam
