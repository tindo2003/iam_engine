#pragma once

#include <string>
#include <vector>

namespace iam {

enum class Effect { Allow, Deny };

struct Statement {
    Effect effect{Effect::Allow};
    std::vector<std::string> actions;
    std::vector<std::string> resources;

    bool matchesAction(const std::string& action) const;
    bool matchesResource(const std::string& resource) const;
};

struct Policy {
    std::vector<Statement> statements;

    static Policy fromJsonString(const std::string& jsonText);
    static Policy fromJsonFile(const std::string& path);
};

// Matches `value` against `pattern`. Supports a trailing '*' wildcard
// (e.g. "db:*" matches "db:read") and a bare "*" matching anything.
bool wildcardMatch(const std::string& pattern, const std::string& value);

} // namespace iam
