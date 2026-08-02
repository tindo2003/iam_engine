#include "iam/cache.hpp"

namespace iam {

bool CacheKey::operator==(const CacheKey& other) const {
    return
        action == other.action
        && subject == other.subject
        && resource == other.resource;
}

size_t CacheKeyHash::operator()(const CacheKey& key) const {
    size_t h = std::hash<std::string>{}(key.subject);
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

bool DecisionCache::FlightKey::operator==(const FlightKey& other) const {
    return snapshot == other.snapshot && key == other.key;
}

size_t DecisionCache::FlightKeyHash::operator()(const FlightKey& flight) const {
    size_t h = CacheKeyHash{}(flight.key);
    const auto ticks = static_cast<size_t>(flight.snapshot.time_since_epoch().count());
    h ^= std::hash<size_t>{}(ticks) + 0x9e3779b9 + (h << 6) + (h >> 2);
    return h;
}

std::optional<Decision> DecisionCache::get(const CacheKey& key, Snapshot snapshot) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    const std::optional<Decision> found = getUnlocked(key, snapshot);

    // Counted here rather than in getUnlocked, because getOrCompute calls
    // both -- once on its fast path and again to re-check under the
    // exclusive lock. Counting in the helper tallied every miss twice.
    if (found.has_value()) {
        ++hits_;
    } else {
        ++misses_;
    }
    return found;
}

std::optional<Decision> DecisionCache::getUnlocked(const CacheKey& key, Snapshot snapshot) const {
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

void DecisionCache::put(const CacheKey& key, Snapshot snapshot, Decision decision) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    auto& snapshots = entries_[key];
    snapshots[snapshot] = decision;
    evict(snapshots);
}

void DecisionCache::evict(std::map<Snapshot, Decision>& snapshots) {
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

Decision DecisionCache::getOrCompute(const CacheKey& key, Snapshot snapshot, const Compute& compute) {
    if (std::optional<Decision> cached = get(key, snapshot)) {
        return *cached;
    }

    const FlightKey flightKey{key, snapshot};
    std::shared_future<Decision> waitOn;
    std::shared_ptr<std::promise<Decision>> owned;

    {
        // EXCLUSIVE, even though this block starts by reading. This is the
        // one place the shared/unique split is not mechanical, so it is
        // worth spelling out.
        //
        // Registering a flight is a read-then-write on inFlight_, and the
        // two halves have to be atomic with respect to each other. Under a
        // shared lock, two threads could inspect inFlight_ at the same
        // instant, both find nothing in progress, and both register
        // themselves as the owner -- reintroducing precisely the duplicate
        // computation this function exists to eliminate.
        std::unique_lock<std::shared_mutex> lock(mutex_);

        // Re-check the cache under that exclusive lock. Between the fast
        // path at the top of this function and here, another thread may
        // have finished its flight and stored the answer, in which case
        // there is nothing left to coordinate.
        if (std::optional<Decision> cached = getUnlocked(key, snapshot)) {
            return *cached;
        }

        auto it = inFlight_.find(flightKey);
        if (it != inFlight_.end()) {
            waitOn = it->second; // somebody is already computing this
        } else {
            owned = std::make_shared<std::promise<Decision>>();
            waitOn = owned->get_future().share();
            inFlight_.emplace(flightKey, waitOn);
        }
    }

    if (!owned) {
        // Deliberately outside the lock -- waiting while holding it would
        // block every reader on a computation we are not even doing.
        ++coalesced_;
        return waitOn.get();
    }

    // We own this flight. Compute with no lock held, so a slow evaluation
    // does not stall unrelated readers.
    try {
        const Decision decision = compute();
        put(key, snapshot, decision);
        owned->set_value(decision);
        {
            std::unique_lock<std::shared_mutex> lock(mutex_);
            inFlight_.erase(flightKey);
        }
        return decision;
    } catch (...) {
        // Retire the flight before rethrowing, or every waiter blocks
        // forever on a promise nobody will ever fulfil.
        {
            std::unique_lock<std::shared_mutex> lock(mutex_);
            inFlight_.erase(flightKey);
        }
        owned->set_exception(std::current_exception());
        throw;
    }
}

size_t DecisionCache::coalesced() const {
    return coalesced_;
}

size_t DecisionCache::hits() const {
    return hits_;
}

size_t DecisionCache::misses() const {
    return misses_;
}

void DecisionCache::resetCounters() {
    hits_ = 0;
    misses_ = 0;
    coalesced_ = 0;
}

size_t DecisionCache::size() const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    size_t total = 0;
    for (const auto& entry : entries_) {
        total += entry.second.size();
    }
    return total;
}

} // namespace iam
