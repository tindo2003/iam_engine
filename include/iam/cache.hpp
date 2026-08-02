#pragma once

#include <chrono>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <unordered_map>

namespace iam {

// The identity being checked. Note this does NOT include the snapshot --
// see DecisionCache below for why the snapshot is a second, nested level
// rather than a fourth field here.
struct CacheKey {
    std::string principal;
    std::string action;
    std::string resource;

    bool operator==(const CacheKey& other) const;
};

struct CacheKeyHash {
    size_t operator()(const CacheKey& key) const;
};

// A point in the policy timeline. In a real system this is a database
// revision -- Spanner's TrueTime microseconds, surfaced to clients as an
// opaque ZedToken. Here it is just a steady_clock time_point.
//
// This single concept replaces the old separate PolicyVersion: a real
// ZedToken *is* a timestamp, so carrying both would have been two names
// for one idea. See
// teach/learning-records/0002-why-time-belongs-in-a-real-cache-key.md.
using Snapshot = std::chrono::steady_clock::time_point;

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
    std::optional<bool> get(const CacheKey& key, Snapshot snapshot) const;

    void put(const CacheKey& key, Snapshot snapshot, bool decision);

    Snapshot now() const;
    std::chrono::milliseconds bucketSize() const;

    // Total entries across every identity. Exposed for eviction tests.
    size_t size() const;

private:
    // Drops snapshots older than `ttl_` for one identity. Runs on put, so
    // only identities being actively written get swept.
    //
    // Known limitation, accepted deliberately: an identity that goes cold
    // is never swept again, so its entries leak until the process exits.
    // A production cache needs a background sweep or a global LRU -- both
    // are their own topic, out of scope here.
    void evict(std::map<Snapshot, bool>& snapshots);

    std::chrono::milliseconds ttl_;
    Clock clock_;
    std::chrono::milliseconds bucket_;
    std::unordered_map<CacheKey, std::map<Snapshot, bool>, CacheKeyHash> entries_;
};

} // namespace iam
