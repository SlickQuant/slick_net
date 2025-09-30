cmake_minimum_required(VERSION 3.20)

if (MSVC)
    option(LINK_STATICALLY "Build tests" OFF)
    if (LINK_STATICALLY)
        set(VCPKG_TARGET_TRIPLET x64-windows-static)
    endif()
endif()

set(BUILD_VERSION 0.1.0.0)
project(slick_net VERSION ${BUILD_VERSION} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if (CMAKE_BUILD_TYPE MATCHES Debug)
    add_definitions(-DDEBUG)
endif()

if (CMAKE_BUILD_TYPE MATCHES Release)
    add_definitions(-DNDEBUG)
endif()

if (LINK_STATICALLY)
    set(Boost_USE_STATIC_LIBS ON)
endif()
find_package(Boost CONFIG REQUIRED COMPONENTS beast context)
find_package(OpenSSL REQUIRED)

include(FetchContent)

# Disable tests for slick_queue
set(BUILD_SLICK_QUEUE_TESTS OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    slick_queue
    GIT_REPOSITORY https://github.com/SlickQuant/slick_queue.git
    GIT_TAG v1.0.2.0
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
target_precompile_headers(slick_net INTERFACE include/slick_net/pch.h)

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
    set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-fsanitize=address,undefined")
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

# # Installation rules
# install(DIRECTORY include/ DESTINATION include)

# # Automatically run install after build in Release mode
# if(CMAKE_BUILD_TYPE STREQUAL "Release")
#     add_custom_target(dist_slick_logger ALL
#         COMMAND ${CMAKE_COMMAND} --install ${CMAKE_BINARY_DIR} --prefix ${CMAKE_BINARY_DIR}/dist
#         COMMENT "Create distribution after release build"
#         VERBATIM
#     )

#     if (PROJECT_IS_TOP_LEVEL)
#         add_custom_target(package_slick_logger ALL
#             COMMAND ${CMAKE_COMMAND} -E tar "cfv" "${CMAKE_BINARY_DIR}/dist/slick_logger_${BUILD_VERSION}.zip" --format=zip "include"
#             WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/dist"
#             COMMENT "Creating zip archive"
#         )

#         add_dependencies(package_slick_logger dist_slick_logger dist_slick_queue)
#     endif()
# endif()
