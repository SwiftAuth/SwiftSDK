cmake_minimum_required(VERSION 3.16)
project(SwiftAuth VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Library ──────────────────────────────────────────────────────────

add_library(swiftauth STATIC
    src/swiftauth.cpp
)

target_include_directories(swiftauth PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Find libcurl (required on Linux/macOS)
if(NOT WIN32)
    find_package(CURL REQUIRED)
    target_link_libraries(swiftauth PRIVATE CURL::libcurl)
endif()

# ── Example App ──────────────────────────────────────────────────────

add_executable(swiftauth_example example/main.cpp)
target_link_libraries(swiftauth_example PRIVATE swiftauth)
