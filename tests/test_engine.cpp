#include <cassert>
#include <iostream>

#include "iam/engine.hpp"
#include "iam/policy.hpp"

using namespace iam;

namespace {

Policy allowDenyPolicy() {
    return Policy::fromJsonString(R"({
        "Statement": [
            {"Effect": "Allow", "Action": ["db:read", "db:write"], "Resource": ["urn:table:users"]},
            {"Effect": "Deny", "Action": ["db:delete"], "Resource": ["*"]}
        ]
    })");
}

void test_default_deny_with_no_policies() {
    const std::vector<Policy> policies;
    const Request request{"alice", "db:read", "urn:table:users"};
    assert(PolicyEngine::evaluate(policies, request) == false);
}

void test_explicit_allow() {
    const std::vector<Policy> policies{allowDenyPolicy()};
    const Request request{"alice", "db:read", "urn:table:users"};
    assert(PolicyEngine::evaluate(policies, request) == true);
}

void test_no_matching_statement_is_denied() {
    const std::vector<Policy> policies{allowDenyPolicy()};
    const Request request{"alice", "db:read", "urn:table:orders"};
    assert(PolicyEngine::evaluate(policies, request) == false);
}

void test_explicit_deny_overrides_allow() {
    // db:delete matches the wildcard Deny statement even though the
    // resource also matches an Allow-eligible table.
    const std::vector<Policy> policies{allowDenyPolicy()};
    const Request request{"alice", "db:delete", "urn:table:users"};
    assert(PolicyEngine::evaluate(policies, request) == false);
}

void test_wildcard_action_match() {
    const Policy policy = Policy::fromJsonString(R"({
        "Statement": [
            {"Effect": "Allow", "Action": ["db:*"], "Resource": ["*"]}
        ]
    })");
    const std::vector<Policy> policies{policy};
    assert(PolicyEngine::evaluate(policies, Request{"alice", "db:read", "anything"}) == true);
    assert(PolicyEngine::evaluate(policies, Request{"alice", "db:delete", "anything"}) == true);
    assert(PolicyEngine::evaluate(policies, Request{"alice", "s3:read", "anything"}) == false);
}

void test_deny_from_a_different_policy_still_wins() {
    // Simulates two separately-attached policies (e.g. a user policy and
    // a group policy) where one allows broadly and the other denies narrowly.
    const Policy allowAll = Policy::fromJsonString(R"({
        "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}]
    })");
    const Policy denyDelete = Policy::fromJsonString(R"({
        "Statement": [{"Effect": "Deny", "Action": ["db:delete"], "Resource": ["*"]}]
    })");
    const std::vector<Policy> policies{allowAll, denyDelete};

    assert(PolicyEngine::evaluate(policies, Request{"alice", "db:read", "x"}) == true);
    assert(PolicyEngine::evaluate(policies, Request{"alice", "db:delete", "x"}) == false);
}

} // namespace

int main() {
    test_default_deny_with_no_policies();
    test_explicit_allow();
    test_no_matching_statement_is_denied();
    test_explicit_deny_overrides_allow();
    test_wildcard_action_match();
    test_deny_from_a_different_policy_still_wins();

    std::cout << "All tests passed.\n";
    return 0;
}
