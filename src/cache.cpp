#include "iam/cache.hpp"

namespace iam {

bool CacheKey::operator==(const CacheKey& other) const {
    return
        action == other.action
        && principal == other.principal
        && resource == other.resource;
}

size_t CacheKeyHash::operator()(const CacheKey& key) const {
    size_t h = std::hash<std::string>{}(key.principal);
    h ^= std::hash<std::string>{}(key.action) + 0x9e3779b9 + (h << 6) + (h >> 2);
    h ^= std::hash<std::string>{}(key.resource) + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
}

Snapshot quantize(Snapshot t, std::chrono::milliseconds bucket) {
    if (bucket.count() == 0) {
        return t; // quantization disabled
    }

    // Integer division truncates toward zero, which for a non-negative
    // duration is exactly floor -- that is the whole trick. steady_clock's
    // epoch is process/boot start, so time_since_epoch() is never negative
    // in practice.
    const auto sinceEpoch = std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch());
    const auto rounded = (sinceEpoch / bucket) * bucket;
    return Snapshot{std::chrono::duration_cast<Snapshot::duration>(rounded)};
}

DecisionCache::DecisionCache(std::chrono::milliseconds ttl, Clock clock, std::chrono::milliseconds bucketSize)
    : ttl_(ttl), clock_(std::move(clock)), bucket_(bucketSize) {}

std::optional<bool> DecisionCache::get(const CacheKey& key, Snapshot snapshot) const {
    auto it = entries_.find(key);
    if (it == entries_.end()) {
        return std::nullopt;
    }

    const auto& snapshots = it->second;
    auto snapIt = snapshots.find(snapshot);
    if (snapIt == snapshots.end()) {
        return std::nullopt; // this identity has been checked, but not at this snapshot
    }
    return snapIt->second;
}

void DecisionCache::put(const CacheKey& key, Snapshot snapshot, bool decision) {
    auto& snapshots = entries_[key];
    snapshots[snapshot] = decision;
    evict(snapshots);
}

void DecisionCache::evict(std::map<Snapshot, bool>& snapshots) {
    const Snapshot cutoff = clock_() - ttl_;
    // lower_bound(cutoff) is the first snapshot >= cutoff, so everything
    // before it is strictly older than the retention window.
    snapshots.erase(snapshots.begin(), snapshots.lower_bound(cutoff));
}

Snapshot DecisionCache::now() const {
    return clock_();
}

std::chrono::milliseconds DecisionCache::bucketSize() const {
    return bucket_;
}

size_t DecisionCache::size() const {
    size_t total = 0;
    for (const auto& entry : entries_) {
        total += entry.second.size();
    }
    return total;
}

} // namespace iam
