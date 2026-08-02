#include "iam/service.hpp"

namespace iam {

AuthorizationService::AuthorizationService() : AuthorizationService(Config{}) {}

AuthorizationService::AuthorizationService(Config config)
    : defaultConsistency_(config.defaultConsistency),
        graph_(config.clock),
        // Both caches get the same clock and the same bucket as the graph.
        // Wiring them together here is the point of the class -- getting
        // this wrong is silent, and was previously the caller's problem.
        checkCache_(config.ttl, config.clock, config.bucketSize),
        subproblemCache_(config.ttl, config.clock, config.bucketSize) {}

bool AuthorizationService::check(const Request& request) const {
    return check(request, defaultConsistency_);
}

bool AuthorizationService::check(const Request& request, Consistency consistency,
                                    Snapshot minSnapshot) const {
    return PolicyEngine::evaluateRbacCached(checkCache_, subproblemCache_, graph_, request,
                                            consistency, minSnapshot);
}

Snapshot AuthorizationService::addRole(Role role) {
    graph_.addRole(std::move(role));
    return graph_.revision();
}

Snapshot AuthorizationService::assign(const std::string& principal, const RoleName& role) {
    graph_.assign(principal, role);
    return graph_.revision();
}

Snapshot AuthorizationService::revision() const {
    return graph_.revision();
}

AuthorizationService::Stats AuthorizationService::stats() const {
    Stats stats;
    stats.checkHits = checkCache_.hits();
    stats.checkMisses = checkCache_.misses();
    stats.checkEntries = checkCache_.size();
    stats.subproblemHits = subproblemCache_.hits();
    stats.subproblemMisses = subproblemCache_.misses();
    stats.subproblemEntries = subproblemCache_.size();
    stats.coalesced = checkCache_.coalesced() + subproblemCache_.coalesced();
    return stats;
}

} // namespace iam
