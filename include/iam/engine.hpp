#pragma once

#include <vector>

#include "iam/cache.hpp"
#include "iam/policy.hpp"
#include "iam/types.hpp"

namespace iam {

// Mirrors SpiceDB's per-request consistency levels (see
// teach/lessons/0002-how-spicedb-actually-caches.html). Only the two
// extremes are modeled here -- at_least_as_fresh/ZedTokens are a further
// exercise, not required for this pass.
enum class Consistency {
    MinimizeLatency, // default: use the cache
    FullyConsistent, // bypass the cache entirely
    AtLeastAsFresh, // middle ground between using the cache and bypass the cache
};

class PolicyEngine {
public:
    // Default deny. Any explicit Deny statement wins over any explicit
    // Allow statement, regardless of which policy or statement order
    // they appear in.
    static bool evaluate(const std::vector<Policy>& policies, const Request& request);

    // Same evaluation, but checks `cache` first (unless `consistency` is
    // FullyConsistent, which must ignore the cache entirely -- not just
    // skip reading it, but also decide deliberately whether it's still
    // allowed to write to it).
    static bool evaluateCached(DecisionCache& cache,
                                const std::vector<Policy>& policies,
                                const Request& request,
                                Consistency consistency = Consistency::MinimizeLatency,
                                PolicyVersion policy_version = 0);
};

} // namespace iam
