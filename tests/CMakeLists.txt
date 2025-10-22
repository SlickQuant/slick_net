
find_package(GTest CONFIG QUIET)

if (GTest_FOUND)
    message(STATUS "GTest found: ${GTest_VERSION}")
else()
    include(FetchContent)
    FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
    )
    # For Windows: Prevent overriding the parent project's compiler/linker on Windows
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
endif()

enable_testing()

add_executable(websocket_tests websocket_tests.cpp)
target_link_libraries(websocket_tests PRIVATE slick_net GTest::gtest_main)

add_executable(http_tests http_tests.cpp)
target_link_libraries(http_tests PRIVATE slick_net GTest::gtest_main)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(websocket_tests PRIVATE /fsanitize=address)
    target_compile_options(http_tests PRIVATE /fsanitize=address)
endif()

add_test(NAME WebsocketTests COMMAND websocket_tests)
add_test(NAME HttpTests COMMAND http_tests)
