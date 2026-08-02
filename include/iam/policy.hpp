#pragma once

#include <string>
#include <vector>

namespace iam {

enum class Effect { Allow, Deny };

// One rule: "Allow (or Deny) any of these actions on any of these
// resources." The in-memory form of a single JSON Statement object:
//
//     {"Effect": "Allow",
//      "Action":   ["db:read", "db:write"],
//      "Resource": ["urn:table:users"]}
//
//  ->  Statement{ effect:    Effect::Allow,
//                 actions:   {"db:read", "db:write"},
//                 resources: {"urn:table:users"} }
//
// Both lists are OR-ed within themselves and AND-ed against each other:
// a request matches when SOME entry in `actions` matches its action AND
// SOME entry in `resources` matches its resource. Entries are patterns,
// not literals -- see wildcardMatch below -- so "db:*" or a bare "*" are
// valid entries.
//
// Note what a Statement does NOT carry: any notion of WHO. There is no
// principal field. Which statements apply to a caller is decided outside
// this struct -- historically by whoever assembled the vector<Policy>
// passed to PolicyEngine::evaluate, and now by RoleGraph (roles.hpp),
// which attaches policies to roles and roles to principals.
struct Statement {
    Effect effect{Effect::Allow};
    std::vector<std::string> actions;
    std::vector<std::string> resources;

    // Both are "does ANY pattern in my list match this one value".
    bool matchesAction(const std::string& action) const;
    bool matchesResource(const std::string& resource) const;
};

// A bundle of statements, parsed from one JSON policy document. Order is
// irrelevant to evaluation: a Deny anywhere in the bundle outranks an
// Allow anywhere else, so callers must scan every statement rather than
// stopping at the first match.
struct Policy {
    std::vector<Statement> statements;

    static Policy fromJsonString(const std::string& jsonText);
    static Policy fromJsonFile(const std::string& path);
};

// Matches `value` against `pattern`. Supports a trailing '*' wildcard
// (e.g. "db:*" matches "db:read") and a bare "*" matching anything.
bool wildcardMatch(const std::string& pattern, const std::string& value);

} // namespace iam
