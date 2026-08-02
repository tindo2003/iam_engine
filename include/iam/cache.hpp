#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>

#include "iam/types.hpp"

namespace iam {

// What was evaluated. Note this does NOT include the snapshot -- see
// DecisionCache below for why the snapshot is a second, nested level
// rather than a fourth field here.
//
// `subject` is deliberately not called `principal`: the same key type
// serves both cache layers. In the whole-check cache it holds a principal
// ("alice"); in the subproblem cache it holds a role name ("engineer").
// Those two namespaces are kept apart by using two separate DecisionCache
// instances, not by anything in the key -- so a role named "alice" can
// never be confused with a principal named "alice".
struct CacheKey {
    std::string subject;
    std::string action;
    std::string resource;

    bool operator==(const CacheKey& other) const;
};

struct CacheKeyHash {
    size_t operator()(const CacheKey& key) const;
};

// (Snapshot itself now lives in types.hpp -- RoleGraph reports one too.)
//
// Rounds `t` down to the start of its `bucket` window; returns `t`
// unchanged when `bucket` is zero.
//
// This is what lets requests arriving at genuinely different instants
// agree on one shared cache key instead of each minting a private one.
// Free function (not a member) so PolicyEngine can pick a snapshot
// without holding a cache, and so it is trivially unit-testable.
Snapshot quantize(Snapshot t, std::chrono::milliseconds bucket);

// A snapshot-keyed decision cache, modeled on how Zanzibar/SpiceDB
// actually key their check cache (lessons 0002-0004).
//
// Logically the key is (identity, snapshot). Physically that is nested --
// identity -> ordered map of snapshot -> decision -- because eviction
// needs to find an identity's oldest snapshots cheaply, which a flat map
// with the snapshot folded into CacheKey could not do without a full scan.
//
// The two time knobs do genuinely different jobs here, and conflating
// them is the mistake this design exists to avoid:
//   * `bucketSize` bounds STALENESS (correctness). Once the bucket
//     advances, new requests compute a new key and miss automatically.
//   * `ttl` bounds RETENTION (capacity) only. An answer computed at
//     snapshot S is correct for S forever -- ttl decides how long it is
//     worth keeping around for callers still asking about S, nothing more.
//
// Thread-safe. Reads take a shared lock and writes an exclusive one,
// which suits a cache that is read far more often than written. Note the
// lock protects the CONTAINER, not the decision: two threads can still
// race to compute the same missing entry, which is what getOrCompute()
// below exists to prevent.
class DecisionCache {
public:
    using Clock = std::function<Snapshot()>;

    // `clock` is injectable so tests can fake time passing instead of
    // sleeping for real -- pass a lambda returning a variable you control.
    explicit DecisionCache(std::chrono::milliseconds ttl,
                            Clock clock = std::chrono::steady_clock::now,
                            std::chrono::milliseconds bucketSize = std::chrono::milliseconds{0});

    // Exact-match lookup. There is deliberately no freshness check: an
    // answer computed at snapshot S is correct for S permanently, so a
    // matching key is always a valid hit no matter how much wall-clock
    // time has passed.
    //
    // The optional and the Decision answer different questions, and both
    // are needed: nullopt means "not cached", while a cached
    // Decision::Undecided means "cached, and the answer is that nothing
    // matched". Collapsing the latter into a miss would re-evaluate a
    // known-empty role on every request.
    std::optional<Decision> get(const CacheKey& key, Snapshot snapshot) const;

    void put(const CacheKey& key, Snapshot snapshot, Decision decision);

    // Return the cached decision, or compute and store it -- running
    // `compute` at most ONCE across all threads asking for the same key.
    //
    // Thread safety alone does not stop N concurrent requests for the same
    // missing key from each running the full evaluation and then each
    // storing the identical answer: they simply do it without corrupting
    // the map. This deduplicates the *work*, not just the container --
    // the pattern usually called singleflight.
    //
    // `compute` runs with no lock held, so a slow evaluation never blocks
    // unrelated readers. Callers that arrive while it is running wait on
    // its result rather than starting their own.
    using Compute = std::function<Decision()>;
    Decision getOrCompute(const CacheKey& key, Snapshot snapshot, const Compute& compute);

    // How many calls waited on somebody else's in-flight computation
    // instead of running their own.
    size_t coalesced() const;

    Snapshot now() const;
    std::chrono::milliseconds bucketSize() const;

    // Total entries across every identity. Exposed for eviction tests.
    size_t size() const;

    // Hit/miss counters. Not test scaffolding -- a cache that cannot
    // report its own hit rate is a cache nobody can tune, and real ones
    // (SpiceDB included) export exactly these.
    size_t hits() const;
    size_t misses() const;
    void resetCounters();

private:
    // Drops snapshots older than `ttl_` for one identity. Runs on put, so
    // only identities being actively written get swept.
    //
    // Known limitation, accepted deliberately: an identity that goes cold
    // is never swept again, so its entries leak until the process exits.
    // A production cache needs a background sweep or a global LRU -- both
    // are their own topic, out of scope here.
    void evict(std::map<Snapshot, Decision>& snapshots);

    // Lookup with no locking, for callers that already hold one.
    std::optional<Decision> getUnlocked(const CacheKey& key, Snapshot snapshot) const;

    // A single in-flight computation is identified by the full logical
    // key: same identity AND same snapshot.
    struct FlightKey {
        CacheKey key;
        Snapshot snapshot;
        bool operator==(const FlightKey& other) const;
    };
    struct FlightKeyHash {
        size_t operator()(const FlightKey& flight) const;
    };

    std::chrono::milliseconds ttl_;
    Clock clock_;
    std::chrono::milliseconds bucket_;

    // Counters are atomic rather than mutex-guarded because get() holds
    // only a shared lock, so several readers increment concurrently.
    mutable std::atomic<size_t> hits_{0};
    mutable std::atomic<size_t> misses_{0};
    mutable std::atomic<size_t> coalesced_{0};

    mutable std::shared_mutex mutex_;
    std::unordered_map<CacheKey, std::map<Snapshot, Decision>, CacheKeyHash> entries_;
    std::unordered_map<FlightKey, std::shared_future<Decision>, FlightKeyHash> inFlight_;
};

} // namespace iam
