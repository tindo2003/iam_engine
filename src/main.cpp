#include <iostream>

#include "iam/engine.hpp"
#include "iam/policy.hpp"

namespace {

void printResult(const iam::Request& request, bool allowed) {
    std::cout << request.principal << " -> " << request.action << " on " << request.resource
              << ": " << (allowed ? "ALLOW" : "DENY") << "\n";
}

} // namespace

int main() {
    const iam::Policy policy = iam::Policy::fromJsonFile("policies/example.json");
    const std::vector<iam::Policy> policies{policy};

    const std::vector<iam::Request> requests{
        {"alice", "db:read", "urn:project:database:table_users"},
        {"alice", "db:write", "urn:project:database:table_users"},
        {"alice", "db:delete", "urn:project:database:table_users"},
        {"alice", "db:read", "urn:project:database:table_orders"},
    };

    for (const auto& request : requests) {
        printResult(request, iam::PolicyEngine::evaluate(policies, request));
    }

    return 0;
}
