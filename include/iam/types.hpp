#pragma once

#include <string>

namespace iam {

// A single access request: who, doing what, to which resource.
struct Request {
    std::string principal;
    std::string action;
    std::string resource;
};

// The outcome of evaluating something -- one role, or a whole check.
//
// Three-valued, not bool, because "denies" and "has nothing to say" must
// stay distinguishable while partial results are being combined: a role
// that never mentions a resource must not veto a grant from another role.
// Global default-deny is what finally turns Undecided into a refusal, and
// it applies exactly once, at the very end.
//
// Lives here rather than in engine.hpp because DecisionCache stores these
// too, and cache.hpp cannot include engine.hpp (engine.hpp already
// includes cache.hpp).
enum class Decision {
    Allow,
    Deny,
    Undecided, // nothing matched; contributes in neither direction
};

} // namespace iam
