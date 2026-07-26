#pragma once

#include <vector>

#include "iam/policy.hpp"
#include "iam/types.hpp"

namespace iam {

class PolicyEngine {
public:
    // Default deny. Any explicit Deny statement wins over any explicit
    // Allow statement, regardless of which policy or statement order
    // they appear in.
    static bool evaluate(const std::vector<Policy>& policies, const Request& request);
};

} // namespace iam
