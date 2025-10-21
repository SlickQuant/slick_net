cmake_minimum_required(VERSION 3.20)

if (MSVC)
    option(LINK_STATICALLY "Build tests" OFF)
    if (LINK_STATICALLY)
        set(VCPKG_TARGET_TRIPLET x64-windows-static)
    endif()
endif()

set(BUILD_VERSION 1.1.0.1)
project(slick_net VERSION ${BUILD_VERSION} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (LINK_STATICALLY)
    set(Boost_USE_STATIC_LIBS ON)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
    set(OPENSSL_MSVC_STATIC_RT TRUE)
endif()
find_package(Boost CONFIG REQUIRED COMPONENTS beast context)
find_package(OpenSSL REQUIRED)

include(FetchContent)

# Disable tests for slick_queue
set(BUILD_SLICK_QUEUE_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    slick_queue
    GIT_REPOSITORY https://github.com/SlickQuant/slick_queue.git
    GIT_TAG v1.1.0.2
)
FetchContent_MakeAvailable(slick_queue)

message(STATUS "slick_queue: ${slick_queue_SOURCE_DIR}")
message(STATUS "OpenSSL: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "Beast: ${boost_beast_CONFIG}")

# Add header-only library
add_library(slick_net INTERFACE)
target_include_directories(slick_net INTERFACE 
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)
target_link_libraries(slick_net INTERFACE slick_logger slick_queue Boost::asio Boost::beast Boost::context OpenSSL::SSL OpenSSL::Crypto)
target_precompile_headers(slick_net INTERFACE
    # Standard library headers
    <atomic>
    <cstdlib>
    <functional>
    <unordered_map>
    <mutex>
    <csignal>
    <thread>
    # Boost headers
    <boost/beast/core.hpp>
    <boost/beast/websocket.hpp>
    <boost/beast/websocket/ssl.hpp>
    <boost/beast/http.hpp>
    <boost/asio/ssl.hpp>
    <boost/asio/strand.hpp>
    <boost/asio/awaitable.hpp>
    <boost/asio/co_spawn.hpp>
    <boost/asio/signal_set.hpp>
    <boost/asio/ip/tcp.hpp>
    <boost/asio/ssl/stream.hpp>
    <boost/asio/connect.hpp>
    <boost/asio/post.hpp>
    <boost/asio/as_tuple.hpp>
    # External dependencies
    <slick/queue.h>
)

if (MSVC)
    set(CMAKE_CXX_FLAGS_RELEASE "-O2")
    add_definitions(-D_WIN32_WINNT=0x0A00)
    set(CMAKE_SUPPRESS_REGENERATION true)   # supress zero_check
    set_target_properties(slick_net PROPERTIES LINK_INCREMENTAL ON)
    target_compile_options(slick_net INTERFACE "/bigobj")
    if (LINK_STATICALLY)
        set_target_properties(slick_net PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
else()
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -flto")
endif()

option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
if(ENABLE_ASAN)
  if(MSVC)
    # MSVC AddressSanitizer (requires Visual Studio 2022 17.7+)
    if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL "19.37")
      add_compile_options(/fsanitize=address)
      add_link_options(/INCREMENTAL:NO)

      # Additional MSVC ASan flags for better compatibility
      add_compile_definitions(_DISABLE_VECTOR_ANNOTATION)
      add_compile_definitions(_DISABLE_STRING_ANNOTATION)

      message(STATUS "AddressSanitizer enabled for MSVC ${CMAKE_CXX_COMPILER_VERSION}")
    else()
      message(WARNING "AddressSanitizer requires Visual Studio 2022 17.7+ (current: ${CMAKE_CXX_COMPILER_VERSION})")
      set(ENABLE_ASAN OFF CACHE BOOL "ASan disabled - compiler too old" FORCE)
    endif()
  else()
    # GCC/Clang AddressSanitizer
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
  endif()
endif()

option(BUILD_SLICK_NET_TESTS "Build tests" ON)
if (BUILD_SLICK_NET_TESTS)
    message(STATUS "Building slick_net tests")
    add_subdirectory(tests)
else()
    message(STATUS "Skipping slick_net tests")
endif()

option(BUILD_SLICK_NET_EXAMPLES "Build examples" ON)
if(BUILD_SLICK_NET_EXAMPLES)
    message(STATUS "Building slick_net examples")
    add_subdirectory(examples)
else()
    message(STATUS "Skipping slick_net examples")
endif()

# Installation rules
install(DIRECTORY include/ DESTINATION include)

# Automatically run install after build in Release mode
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_target(dist_slick_net ALL
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_BINARY_DIR}/dist/include
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Copying slick_net headers to dist/include"
        VERBATIM
    )

    if (PROJECT_IS_TOP_LEVEL)
        add_custom_target(package_slick_net ALL
            COMMAND ${CMAKE_COMMAND} -E tar "cfv" "${CMAKE_BINARY_DIR}/dist/slick_net_${BUILD_VERSION}.zip" --format=zip "include"
            WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/dist"
            COMMENT "Creating zip archive"
        )

        add_dependencies(package_slick_net dist_slick_net)
    endif()
endif()
