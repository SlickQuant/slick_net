project(websocket_client_example LANGUAGES CXX)

find_package(OpenSSL REQUIRED)

include(FetchContent)
# Disable examples, tests, and benchmarks for slick_logger
set(BUILD_SLICK_LOGGER_EXAMPLES OFF CACHE BOOL "" FORCE)
set(BUILD_SLICK_LOGGER_TESTING OFF CACHE BOOL "" FORCE)
set(BUILD_SLICK_LOGGER_BENCHMARKS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    slick_logger
    GIT_REPOSITORY https://github.com/SlickQuant/slick_logger.git
    GIT_TAG v0.1.1.0
)
FetchContent_MakeAvailable(slick_logger)
find_package(nlohmann_json REQUIRED)

add_executable(websocket_client_example websocket_client.cpp)
target_include_directories(websocket_client_example PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_link_libraries(websocket_client_example PRIVATE slick_net nlohmann_json::nlohmann_json)