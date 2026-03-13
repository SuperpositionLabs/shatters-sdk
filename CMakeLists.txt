cmake_minimum_required(VERSION 3.25)

# vcpkg auto-detection: VCPKG_ROOT env → submodule → warning
if(NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    if(DEFINED ENV{VCPKG_ROOT})
        set(CMAKE_TOOLCHAIN_FILE
            "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
            CACHE FILEPATH "vcpkg toolchain")
    elseif(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake")
        set(CMAKE_TOOLCHAIN_FILE
            "${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake"
            CACHE FILEPATH "vcpkg toolchain")
    else()
        message(WARNING
            "vcpkg not found. Run: git submodule update --init")
    endif()
endif()

project(shatters-sdk
    VERSION     0.1.0
    LANGUAGES   CXX
    DESCRIPTION "shatters cryptographic SDK"
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Hardening
if(MSVC)
    add_compile_options(/W4 /WX /sdl /GS /guard:cf)
    add_link_options(/guard:cf)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror -fstack-protector-strong)
    add_compile_definitions($<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=2>)
endif()

# Dependencies
find_package(unofficial-sodium CONFIG REQUIRED)

# Library
add_library(shatters-sdk
    src/init.cpp
    src/crypto/secure_memory.cpp
    src/crypto/keys.cpp
    src/crypto/kdf.cpp
    src/crypto/hash.cpp
    src/crypto/aead.cpp
)

target_include_directories(shatters-sdk
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(shatters-sdk
    PUBLIC unofficial-sodium::sodium
)

# Tests
option(SHATTERS_BUILD_TESTS "Build tests" ON)
if(SHATTERS_BUILD_TESTS)
    enable_testing()
    find_package(GTest CONFIG REQUIRED)
    add_subdirectory(tests)
endif()
