add_executable(test_engine test_engine.cpp)
target_link_libraries(test_engine PRIVATE iam_core)
add_test(NAME test_engine COMMAND test_engine)
