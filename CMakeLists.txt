cmake_minimum_required(VERSION 3.25)

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
            "vcpkg not found. run: git submodule update --init")
    endif()
endif()

project(shatters-sdk
    VERSION     0.1.0
    LANGUAGES   CXX
    DESCRIPTION "shatters sdk"
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(SHATTERS_BUILD_TESTS  "build unit tests" ON)
option(SHATTERS_ASAN         "enable address sanitizer" OFF)
option(SHATTERS_TSAN         "enable thread sanitizer" OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-fstack-protector-strong)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    add_compile_definitions(_FORTIFY_SOURCE=2)

    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wconversion -Wsign-conversion
        -Wformat=2 -Wformat-security
        -Wnull-dereference
        -Wdouble-promotion
        -Wshadow
        -Wno-unused-parameter
    )

    add_link_options(
        -Wl,-z,relro
        -Wl,-z,now
        -Wl,-z,noexecstack
    )

    if(SHATTERS_ASAN)
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()

    if(SHATTERS_TSAN)
        add_compile_options(-fsanitize=thread)
        add_link_options(-fsanitize=thread)
    endif()

elseif(MSVC)
    add_compile_options(
        /W4
        /GS      
        /guard:cf 
        /sdl     
    )
    add_link_options(
        /DYNAMICBASE   
        /NXCOMPAT      
        /CETCOMPAT     
    )
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(spdlog CONFIG REQUIRED)
find_package(unofficial-sodium CONFIG REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)

file(GLOB_RECURSE SDK_SOURCES CONFIGURE_DEPENDS "src/*.cpp")
file(GLOB_RECURSE SDK_HEADERS CONFIGURE_DEPENDS "include/*.hpp")

add_library(shatters-sdk STATIC
    ${SDK_SOURCES}
    ${SDK_HEADERS}
)
add_library(shatters::sdk ALIAS shatters-sdk)

target_include_directories(shatters-sdk
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_BINARY_DIR}
)

target_link_libraries(shatters-sdk
    PUBLIC
        unofficial-sodium::sodium
    PRIVATE
        spdlog::spdlog
        unofficial::sqlite3::sqlite3
)

if(SHATTERS_BUILD_TESTS)
    enable_testing()
    find_package(GTest REQUIRED)

    file(GLOB_RECURSE TEST_SOURCES "tests/unit/*.cpp")

    add_executable(shatters-sdk-tests ${TEST_SOURCES})
    target_link_libraries(shatters-sdk-tests
        PRIVATE
            shatters-sdk
            GTest::gtest_main
    )
    target_include_directories(shatters-sdk-tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    )

    include(GoogleTest)
    gtest_discover_tests(shatters-sdk-tests)
    
    file(GLOB_RECURSE INTEGRATION_SOURCES "tests/integration/*.cpp")
    if(INTEGRATION_SOURCES)
        add_executable(shatters-sdk-integration ${INTEGRATION_SOURCES})
        target_link_libraries(shatters-sdk-integration
            PRIVATE
                shatters-sdk
                GTest::gtest_main
        )
    endif()
endif()

include(GNUInstallDirs)

install(TARGETS shatters-sdk
    EXPORT shatters-sdk-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/shatters 
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
install(EXPORT shatters-sdk-targets
    FILE shatters-sdk-config.cmake
    NAMESPACE shatters::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/shatters-sdk
)