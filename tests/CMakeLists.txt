include(GoogleTest)

add_executable(test_engine test_engine.cpp)
target_link_libraries(test_engine PRIVATE iam_core GTest::gtest_main)

gtest_discover_tests(test_engine)
