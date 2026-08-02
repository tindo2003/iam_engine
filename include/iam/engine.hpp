#pragma once

#include <chrono>
#include <vector>

#include "iam/cache.hpp"
#include "iam/policy.hpp"
#include "iam/types.hpp"

namespace iam {

// How a cached lookup actually works here
// ---------------------------------------
// The cache is shaped `identity -> {snapshot -> bool}`. Critically, a
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
};

} // namespace iam
