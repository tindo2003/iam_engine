#include "iam/policy.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>

#include <nlohmann/json.hpp>

namespace iam {

using json = nlohmann::json;

bool wildcardMatch(const std::string& pattern, const std::string& value) {
    if (pattern == "*") {
        return true;
    }
    if (!pattern.empty() && pattern.back() == '*') {
        const std::string prefix = pattern.substr(0, pattern.size() - 1);
        return value.compare(0, prefix.size(), prefix) == 0;
    }
    return pattern == value;
}

bool Statement::matchesAction(const std::string& action) const {
    for (const auto& pattern : actions) {
        if (wildcardMatch(pattern, action)) {
            return true;
        }
    }
    return false;
}

bool Statement::matchesResource(const std::string& resource) const {
    for (const auto& pattern : resources) {
        if (wildcardMatch(pattern, resource)) {
            return true;
        }
    }
    return false;
}

namespace {

// Policy documents allow a field to be a single string or an array of
// strings (mirrors how real-world policy languages like AWS IAM behave).
std::vector<std::string> readStringOrArray(const json& value) {
    std::vector<std::string> result;
    if (value.is_string()) {
        result.push_back(value.get<std::string>());
    } else if (value.is_array()) {
        for (const auto& item : value) {
            result.push_back(item.get<std::string>());
        }
    }
    return result;
}

Effect parseEffect(const std::string& text) {
    if (text == "Allow") {
        return Effect::Allow;
    }
    if (text == "Deny") {
        return Effect::Deny;
    }
    throw std::runtime_error("Unknown Effect: " + text);
}

} // namespace

Policy Policy::fromJsonString(const std::string& jsonText) {
    const json doc = json::parse(jsonText);
    Policy policy;

    for (const auto& stmt : doc.at("Statement")) {
        Statement statement;
        statement.effect = parseEffect(stmt.at("Effect").get<std::string>());
        statement.actions = readStringOrArray(stmt.at("Action"));
        statement.resources = readStringOrArray(stmt.at("Resource"));
        policy.statements.push_back(std::move(statement));
    }

    return policy;
}

Policy Policy::fromJsonFile(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Could not open policy file: " + path);
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return Policy::fromJsonString(buffer.str());
}

} // namespace iam
