#pragma once

#include <chrono>
#include <vector>

#include "iam/cache.hpp"
#include "iam/policy.hpp"
#include "iam/roles.hpp"
#include "iam/types.hpp"

namespace iam {

// Where this file sits in the ABAC architecture (NIST SP 800-162), and
// how the other three pieces plug in later
// ------------------------------------------------------------------
// PolicyEngine is the PDP -- the Policy Decision Point, and nothing else.
// It is deliberately a set of pure static functions over explicit
// arguments: no ownership, no stored state, no I/O. That is what keeps
// the other three roles addable without reworking anything here.
//
// PEP (enforcement) would sit ABOVE this. It intercepts a real request,
// asks the PDP, and enforces the answer. What it will want that does not
// exist yet is a facade bundling the things evaluateRbac/evaluateCached
// currently take one at a time -- roughly:
//
//     class AuthorizationService {            // future, not built
//         RoleGraph graph_;
//         DecisionCache cache_;
//         Consistency defaultConsistency_;
//     public:
//         bool check(const Request&) const;   // PEP calls just this
//     };
//
// Nothing here blocks that: it is pure composition over the existing
// functions. Note a PEP often wants more than a bool (a reason, or
// obligations to apply). `Decision` below is already richer than bool,
// so widening the return type later is additive rather than a rewrite.
//
// PAP (administration) would sit BESIDE RoleGraph, owning the write path
// -- see the note in roles.hpp for the one real gap it needs to close.
//
// PIP (attribute lookup) has no place to attach yet, and correctly so:
// nothing in Request or Statement consults external attributes (time of
// day, department, MFA state). Condition blocks are what would create
// the need, and they are not built.

// Decision now lives in types.hpp, so that DecisionCache can store one
// without cache.hpp having to include this header.

// How a cached lookup actually works here
// ---------------------------------------
// A cache is shaped `subject -> {snapshot -> Decision}`. Critically, a
// lookup NEVER searches that inner map for a "close enough" snapshot.
// Every consistency level computes exactly one snapshot value first,
// then does a plain find() -- hit or miss, nothing in between:
//
//     MinimizeLatency        quantize(now, bucket)
//     AtLeastAsFresh(min)    bucket >= min ? bucket : min — i.e. max(bucket, min)
//     FullyConsistent        now, unquantized
//
// Walked through with bucket = 1000ms, K = (userA, read, ResourceA):
//
//   t     level                 snapshot                result                   map after
//   ----  --------------------  ----------------------  -----------------------  ------------------------
//   1200  MinimizeLatency       quantize(1200) = 1000   miss -> evaluate -> put  {1000}
//   1450  MinimizeLatency       1000                    HIT, no put              {1000}
//   1999  MinimizeLatency       1000                    HIT, no put              {1000}
//   2100  MinimizeLatency       quantize(2100) = 2000   miss -> evaluate -> put  {1000, 2000}
//   2300  AtLeastAsFresh(1500)  max(2000, 1500) = 2000  HIT (shared entry)       {1000, 2000}
//   2400  AtLeastAsFresh(2350)  max(2000, 2350) = 2350  miss -> evaluate -> put  {1000, 2000, 2350}
//   2500  FullyConsistent       2500 exact              miss -> evaluate -> put  {1000, 2000, 2350, 2500}
//
// Rows 2-3 are the payoff: three requests, one evaluation. Note put()
// happens only on a miss -- a hit writes nothing.
//
// Row 5 is the elegant part: a token-bearing request lands on the very
// entry ordinary MinimizeLatency traffic already populated, because the
// current bucket already satisfies its token.
//
// Row 6 is what a genuinely-fresher token costs -- a private key nobody
// else will ever share. That cost is the price of the stronger guarantee.
//
// Row 7 shows FullyConsistent missing purely because of the key it
// picked. There is no bypass logic anywhere in evaluateCached.

// Mirrors SpiceDB's per-request consistency levels. Each one is really
// just a different rule for choosing WHICH snapshot to evaluate at --
// see PolicyEngine::selectSnapshot.
enum class Consistency {
    MinimizeLatency, // default: evaluate at the current shared bucket
    FullyConsistent, // evaluate at an exact instant, so nothing can be reused
    AtLeastAsFresh,  // share the bucket unless a token demands newer
};

class PolicyEngine {
public:
    // Default deny. Any explicit Deny statement wins over any explicit
    // Allow statement, regardless of which policy or statement order
    // they appear in.
    static bool evaluate(const std::vector<Policy>& policies, const Request& request);

    // Picks the snapshot a request should be evaluated at. Pure function
    // of its arguments -- no cache, no clock, no state -- so it is
    // directly unit-testable.
    //
    // This is where the consistency levels actually differ. Notably
    // FullyConsistent needs no cache-bypass branch anywhere: returning an
    // exact, unquantized instant produces a key that essentially never
    // collides, so it misses and recomputes as a consequence of the key
    // rather than as a special case in the control flow.
    static Snapshot selectSnapshot(Consistency consistency,
                                    Snapshot minSnapshot,
                                    Snapshot now,
                                    std::chrono::milliseconds bucketSize);

    // Same evaluation, reading through `cache`. One code path for every
    // consistency level -- the level only influences which snapshot gets
    // selected above.
    static bool evaluateCached(DecisionCache& cache,
                                const std::vector<Policy>& policies,
                                const Request& request,
                                Consistency consistency = Consistency::MinimizeLatency,
                                Snapshot minSnapshot = Snapshot{});

    // --- RBAC -----------------------------------------------------------
    //
    // THE cacheable subproblem: what one role says about a request, using
    // only its own policies and ignoring everything it inherits.
    //
    // Deliberately does not take a principal. That is the whole point --
    // the answer is identical for every principal holding this role, so
    // one cached result serves all of them. Keeping inheritance OUT of
    // here is also deliberate: it keeps the unit small, and therefore
    // shared by more callers.
    static Decision evaluateForRole(const RoleGraph& graph,
                                    const RoleName& role,
                                    const Request& request);

    // Full RBAC check: resolve the principal's effective roles, ask each
    // one, then combine.
    static bool evaluateRbac(const RoleGraph& graph, const Request& request);

    // --- The two cache layers -------------------------------------------
    //
    // Layer 2 (subproblem). Keyed on the ROLE, not the principal, so every
    // holder of that role shares one entry: alice's check warms the cache
    // for bob. `subproblemCache` must be a different instance from the
    // whole-check cache -- that separation is what keeps a role named
    // "alice" from colliding with a principal named "alice".
    static Decision evaluateForRoleCached(DecisionCache& subproblemCache,
                                            const RoleGraph& graph,
                                            const RoleName& role,
                                            const Request& request,
                                            Consistency consistency = Consistency::MinimizeLatency,
                                            Snapshot minSnapshot = Snapshot{});

    // Both layers together. Layer 1 (`checkCache`) short-circuits an
    // identical repeat request; on a miss, layer 2 (`subproblemCache`) still
    // lets this check reuse per-role work done for other principals.
    static bool evaluateRbacCached(DecisionCache& checkCache,
                                    DecisionCache& subproblemCache,
                                    const RoleGraph& graph,
                                    const Request& request,
                                    Consistency consistency = Consistency::MinimizeLatency,
                                    Snapshot minSnapshot = Snapshot{});
};

} // namespace iam
