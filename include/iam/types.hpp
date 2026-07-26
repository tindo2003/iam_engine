#pragma once

#include <string>

namespace iam {

// A single access request: who, doing what, to which resource.
struct Request {
    std::string principal;
    std::string action;
    std::string resource;
};

} // namespace iam
