# ML-DSA-65-compatible signature implementation; no validation claim
# SDK Independence: Vendored from pq-crystals/dilithium reference implementation
# Dilithium mode 3 / ML-DSA-65 parameter set

cmake_minimum_required(VERSION 3.10)

project(dilithium C)

# Source files
set(DILITHIUM_SOURCES
    fips202.c
    ntt.c
    packing.c
    poly.c
    polyvec.c
    reduce.c
    rounding.c
    sign.c
    symmetric-shake.c
)

# Header files
set(DILITHIUM_HEADERS
    api.h
    config.h
    fips202.h
    ntt.h
    packing.h
    params.h
    poly.h
    polyvec.h
    randombytes.h
    reduce.h
    rounding.h
    sign.h
    symmetric.h
)

# Create static library
add_library(dilithium STATIC ${DILITHIUM_SOURCES})

# Include directories
target_include_directories(dilithium PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../..  # For qgp_random.h
)

# Compiler flags (cross-platform)
if(MSVC)
    # MSVC compiler flags
    target_compile_options(dilithium PRIVATE
        /W3           # Warning level 3
        /O2           # Optimize for speed
    )
    target_compile_definitions(dilithium PRIVATE
        DILITHIUM_MODE=3  # ML-DSA-65 parameter set
    )
else()
    # GCC/Clang compiler flags
    target_compile_options(dilithium PRIVATE
        -Wall
        -Wextra
        -O3
        -DDILITHIUM_MODE=3  # ML-DSA-65 parameter set
    )
endif()

# Installation
install(TARGETS dilithium
    ARCHIVE DESTINATION lib
)

install(FILES ${DILITHIUM_HEADERS}
    DESTINATION include/dilithium
)
