#pragma once

#include <chrono>
#include <cstddef>
#include <string>

#include "iam/cache.hpp"
#include "iam/engine.hpp"
#include "iam/roles.hpp"
#include "iam/types.hpp"

namespace iam {

// The assembled system: a role graph, both cache layers, and the policy
// they are configured with, behind one object.
//
// PolicyEngine is deliberately stateless static functions, which is right
// for a PDP but leaves a caller juggling five arguments and several
// invariants. This is the facade a PEP -- the enforcement point that
// intercepts a real request -- would actually hold:
//
//     if (!authz.check(request)) { reject(); }
//
// Owning the pieces is not just tidiness. It makes three mistakes that
// were previously possible unrepresentable:
//
//   1. Passing ONE cache for both layers. That collided a role named
//      "employee" with a person of the same name, in both directions, and
//      needed a runtime assert to catch. Two members, constructed
//      separately, cannot be confused.
//
//   2. Giving the graph and the caches different clocks. Harmless until
//      the revision floor made them comparable, after which a graph on a
//      real clock and caches on a fake one silently disagreed about which
//      snapshots were reachable. One clock now feeds all three.
//
//   3. Configuring the two caches differently, so the layers quantized
//      onto different buckets.
//
// Thread-safe, because everything underneath is: hold one instance and
// call check() from as many request threads as you like.
class AuthorizationService {
public:
    struct Config {
        // Retention, not correctness -- how long superseded snapshots are
        // kept for callers still asking about them.
        std::chrono::milliseconds ttl{5000};

        // Staleness bound AND sharing knob. Requests inside one bucket
        // collapse onto a single cache entry. SpiceDB's real defaults are
        // roughly this pair.
        std::chrono::milliseconds bucketSize{1000};

        Consistency defaultConsistency{Consistency::MinimizeLatency};

        // Injectable so tests can drive time without sleeping. Shared by
        // the graph and both caches -- see mistake 2 above.
        DecisionCache::Clock clock{std::chrono::steady_clock::now};
    };

    // Two constructors rather than `Config config = {}`: a default
    // argument of {} would need Config's member initializers to be
    // complete, and they are still being defined inside this class.
    AuthorizationService();
    explicit AuthorizationService(Config config);

    // --- The enforcement surface. A PEP needs only this. ----------------

    // const because this is logically a read. The caches it writes to are
    // `mutable`: memoization is an implementation detail, not a change to
    // what the system says. Lets a request handler hold this by const
    // reference.
    bool check(const Request& request) const;

    // Same check at an explicit consistency level -- e.g. a caller that
    // just performed a write and holds a token proving it happened.
    bool check(const Request& request, Consistency consistency,
                Snapshot minSnapshot = Snapshot{}) const;

    // --- The administration surface -------------------------------------
    //
    // Conceptually a PAP's, and deliberately marked off from the check
    // path above. A real deployment would not hand these to the same code
    // that serves requests -- most likely not even the same process --
    // and would authorise the write itself, which nothing here does.
    //
    // Each returns the resulting revision, which is the token a caller
    // passes back to check(..., AtLeastAsFresh, token) to guarantee it
    // sees its own write.
    Snapshot addRole(Role role);
    Snapshot assign(const std::string& principal, const RoleName& role);

    Snapshot revision() const;

    // --- Observability ---------------------------------------------------

    struct Stats {
        size_t checkHits{0};
        size_t checkMisses{0};
        size_t checkEntries{0};
        size_t subproblemHits{0};
        size_t subproblemMisses{0};
        size_t subproblemEntries{0};
        size_t coalesced{0};
    };
    Stats stats() const;

private:
    Consistency defaultConsistency_;
    RoleGraph graph_;

    // Mutable so check() can stay const. Two distinct instances, always.
    mutable DecisionCache checkCache_;
    mutable DecisionCache subproblemCache_;
};

} // namespace iam
