#pragma once

#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>

namespace iam {

struct CacheKey {
    std::string principal;
    std::string action;
    std::string resource;

    bool operator==(const CacheKey& other) const;
};

struct CacheKeyHash {
    size_t operator()(const CacheKey& key) const;
};

using PolicyVersion = std::uint64_t;

// A TTL-based decision cache, modeled on SpiceDB's default hotspot cache
// (see teach/lessons/0002-how-spicedb-actually-caches.html): a fixed
// window, thrown out unconditionally once it's stale. No version-stamping,
// no invalidation events -- staleness is bounded by `ttl`, not detected.
class DecisionCache {
public:
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    // `clock` is injectable so tests can fake time passing instead of
    // sleeping for real -- pass a lambda that returns a variable you control.
    explicit DecisionCache(std::chrono::milliseconds ttl,
                            Clock clock = std::chrono::steady_clock::now);

    // Returns the cached decision if `key` is present and still within
    // `ttl` of when it was stored; std::nullopt otherwise (a genuine miss,
    // or an expired entry -- both are treated identically by callers).
    std::optional<bool> get(const CacheKey& key) const;
    std::optional<bool> get(const CacheKey& key, PolicyVersion min_version) const; 

    // Stores `decision`, stamped with the current time from `clock_`.
    void put(const CacheKey& key, bool decision, PolicyVersion version);

private:
    struct Entry {
        bool decision;
        std::chrono::steady_clock::time_point cachedAt;
        PolicyVersion version;
    };

    std::chrono::milliseconds ttl_;
    Clock clock_;
    mutable std::unordered_map<CacheKey, Entry, CacheKeyHash> entries_;
};

} // namespace iam
