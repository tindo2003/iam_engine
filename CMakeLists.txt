cmake_minimum_required(VERSION 3.16)
project(iam_engine CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
    json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    DOWNLOAD_EXTRACT_TIMESTAMP true
)
FetchContent_MakeAvailable(json)

add_library(iam_core src/policy.cpp src/engine.cpp)
target_include_directories(iam_core PUBLIC include)
target_link_libraries(iam_core PUBLIC nlohmann_json::nlohmann_json)

add_executable(iam_demo src/main.cpp)
target_link_libraries(iam_demo PRIVATE iam_core)

enable_testing()
add_subdirectory(tests)
