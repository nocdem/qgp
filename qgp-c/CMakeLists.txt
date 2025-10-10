cmake_minimum_required(VERSION 3.10)
project(qgp C)

# Version
set(VERSION_MAJOR 1)
set(VERSION_MINOR 1)

# Auto-increment patch version based on git commit count since last minor version bump
# This gives us: 1.1.0, 1.1.1, 1.1.2, etc. automatically with each commit
execute_process(
    COMMAND git rev-list --count HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_COUNT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

# If git command fails (e.g., not a git repo), default to 0
if(NOT GIT_COMMIT_COUNT)
    set(GIT_COMMIT_COUNT 0)
endif()

# Use commit count as patch version for continuous versioning
set(VERSION_PATCH ${GIT_COMMIT_COUNT})

# Build info
execute_process(
    COMMAND git log -1 --format=%h
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

string(TIMESTAMP BUILD_TIMESTAMP "%Y-%m-%d")
message("Build date: ${BUILD_TIMESTAMP}")
message("Git SHA: ${GIT_COMMIT_HASH}")

set(QGP_VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")
set(BUILD_TS "${BUILD_TIMESTAMP}")
set(BUILD_HASH "${GIT_COMMIT_HASH}")

add_definitions("-DQGP_VERSION=\"${QGP_VERSION}\"")
add_definitions("-DBUILD_TS=\"${BUILD_TS}\"")
add_definitions("-DBUILD_HASH=\"${BUILD_HASH}\"")

# Cellframe SDK configuration
set(CELLFRAME_MODULES "core")  # Need core module which includes crypto
set(SPHINCSPLUS_FLEX ON)
option(CELLFRAME_NO_OPTIMIZATION "Build without BMI BMI2 CPU instruction." ON)
set(DAP_CRYPTO_XKCP_PLAINC ON)

# Include SDK
set(CELLFRAME_SDK_PATH "${CMAKE_SOURCE_DIR}/../cellframe-sdk")
set(DAP_SDK_PATH "${CELLFRAME_SDK_PATH}/dap-sdk")
include(${DAP_SDK_PATH}/cmake/OS_Detection.cmake)

# Include DAP-SDK (crypto/core)
# Removed EXCLUDE_FROM_ALL so that targets like BuildXKCP are visible for dependencies
add_subdirectory(${DAP_SDK_PATH} dap-sdk-build)

# Main executable
add_executable(${PROJECT_NAME}
    main.c
    keygen.c
    sign.c
    verify.c
    export.c
    encrypt.c
    decrypt.c
    keyring.c
    privkey.c
    utils.c
    armor.c
    aes_keywrap.c
)

# Link flags
set_property(TARGET ${PROJECT_NAME} APPEND_STRING PROPERTY LINK_FLAGS "-D_GNU_SOURCE")

# Link libraries (only DAP-SDK crypto needed)
target_link_libraries(${PROJECT_NAME}
    m
    dap_core
    dap_crypto
    pthread
)

# Include directories
# We need to explicitly add the SDK includes because the INTERFACE directories use relative paths
# that don't resolve correctly in our build context
# IMPORTANT: Only include generated XKCP headers, NOT the source XKCP directory (which has #error directives)
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${DAP_SDK_PATH}/core/include
    ${DAP_SDK_PATH}/crypto/include
    ${DAP_SDK_PATH}/crypto/src
    ${DAP_SDK_PATH}/crypto/src/sha3
    ${DAP_SDK_PATH}/crypto/src/rand
    ${DAP_SDK_PATH}/crypto/src/iaes
    ${CMAKE_BINARY_DIR}/dap-sdk-build/crypto/XKCP/xkcp_build_src/bin/libdap-XKCP-plainc-native.a.headers
)

# Build type configuration
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_C_FLAGS_DEBUG "-g -O0 -DDEBUG")
    add_definitions("-DDAP_DEBUG_MODE")
    message(STATUS "Debug build enabled")
else()
    set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")
    message(STATUS "Release build enabled")
endif()

# Install target
install(TARGETS ${PROJECT_NAME} DESTINATION bin)
