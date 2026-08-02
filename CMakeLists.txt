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

FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.15.2.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP true
)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_library(iam_core src/policy.cpp src/engine.cpp src/cache.cpp src/roles.cpp)
target_include_directories(iam_core PUBLIC include)
target_link_libraries(iam_core PUBLIC nlohmann_json::nlohmann_json)

add_executable(iam_demo src/main.cpp)
target_link_libraries(iam_demo PRIVATE iam_core)

# Standalone teaching demo -- deliberately not part of iam_core, see
# demos/snapshot_consistency_race.cpp.
find_package(Threads REQUIRED)
add_executable(snapshot_race_demo demos/snapshot_consistency_race.cpp)
target_link_libraries(snapshot_race_demo PRIVATE Threads::Threads)

enable_testing()
add_subdirectory(tests)
