include(GoogleTest)

add_executable(test_engine test_engine.cpp)
target_link_libraries(test_engine PRIVATE iam_core GTest::gtest_main)
gtest_discover_tests(test_engine)

add_executable(test_cache test_cache.cpp)
target_link_libraries(test_cache PRIVATE iam_core GTest::gtest_main)
gtest_discover_tests(test_cache)
