cmake_minimum_required(VERSION 3.14)
project(test_project CXX)

set(CMAKE_CXX_STANDARD 17)

# Use dynamic CRT on Windows (required for gtest compatibility)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

include(FetchContent)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

add_executable(demo_test test_main.cpp)
target_link_libraries(demo_test GTest::gtest_main)

enable_testing()
add_test(NAME demo_test COMMAND demo_test)

