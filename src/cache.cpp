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

DecisionCache::DecisionCache(std::chrono::milliseconds ttl, Clock clock)
    : ttl_(ttl), clock_(std::move(clock)) {}

std::optional<bool> DecisionCache::get(const CacheKey& key) const {
    // No version floor: PolicyVersion{0} is always satisfied by e.version >= 0,
    // since real versions start at 1 (see teach/lessons/0003's kMinPolicyVersion).
    return get(key, PolicyVersion{0});
}

std::optional<bool> DecisionCache::get(const CacheKey& key, PolicyVersion minVersion) const {
    // A hit requires both: still within ttl_, AND at least as fresh as
    // minVersion. A time-fresh but version-stale entry is still a miss --
    // neither condition alone is sufficient (see lesson 0003).
    auto it = entries_.find(key);
    if (it != entries_.end()) {
        const Entry& e = it->second;
        if (((clock_() - e.cachedAt) <= ttl_) && e.version >= minVersion) {
            return e.decision;
        }
    }
    return std::nullopt;
}

void DecisionCache::put(const CacheKey& key, bool decision, PolicyVersion version) {
    entries_[key] = Entry{.decision = decision, .cachedAt = clock_(), .version = version};
}

} // namespace iam
