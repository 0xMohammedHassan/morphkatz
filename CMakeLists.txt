cmake_minimum_required(VERSION 3.25)

# vcpkg toolchain must be set by the preset before project() is evaluated.
project(MorphKatz
    VERSION 0.1.0
    DESCRIPTION "Polymorphic machine-code rewriter for Windows x64 binaries"
    HOMEPAGE_URL "https://github.com/0xMohammedHassan/morphkatz"
    LANGUAGES CXX
)

# ---------------------------------------------------------------------------
# Global options
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "" FORCE)
endif()

option(MORPHKATZ_BUILD_TESTS     "Build Catch2 unit and golden tests"   ON)
option(MORPHKATZ_BUILD_BENCH     "Build benchmark harness"              OFF)
option(MORPHKATZ_BUILD_FUZZ      "Build libFuzzer smoke harness"        OFF)
option(MORPHKATZ_ENABLE_ASAN     "Enable /fsanitize=address"            OFF)
option(MORPHKATZ_ENABLE_UBSAN    "Enable undefined-behaviour sanitizer (clang-cl)" OFF)
option(MORPHKATZ_WITH_YARA       "Enable --target <rules.yar> mode"     ON)
option(MORPHKATZ_WITH_UNICORN    "Enable --verify=unicorn"              ON)
option(MORPHKATZ_WITH_HYPERSCAN  "Enable SIMD byte-pattern matcher"     OFF)
option(MORPHKATZ_WARNINGS_AS_ERRORS "Treat warnings as errors"          ON)

# ---------------------------------------------------------------------------
# Warning and language flags
# ---------------------------------------------------------------------------
add_library(morphkatz_compile_options INTERFACE)
add_library(morphkatz::compile_options ALIAS morphkatz_compile_options)

if(MSVC)
    target_compile_options(morphkatz_compile_options INTERFACE
        /W4
        /permissive-
        /EHsc
        /utf-8
        /Zc:preprocessor
        /Zc:__cplusplus
        /Zc:inline
        /Zc:throwingNew
        /volatile:iso
        /external:anglebrackets /external:W0
        $<$<BOOL:${MORPHKATZ_WARNINGS_AS_ERRORS}>:/WX>
        $<$<CONFIG:Debug>:/Od>
        $<$<CONFIG:Debug>:/Ob0>
        $<$<CONFIG:Debug>:/RTC1>
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:Release>:/Oi>
        $<$<CONFIG:Release>:/GL>
        $<$<CONFIG:RelWithDebInfo>:/O2>
        $<$<CONFIG:RelWithDebInfo>:/Zi>
    )
    target_compile_definitions(morphkatz_compile_options INTERFACE
        _CRT_SECURE_NO_WARNINGS
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        UNICODE _UNICODE
    )
    if(MORPHKATZ_ENABLE_ASAN)
        target_compile_options(morphkatz_compile_options INTERFACE /fsanitize=address)
        target_link_options(morphkatz_compile_options    INTERFACE /INCREMENTAL:NO)
    endif()
else()
    target_compile_options(morphkatz_compile_options INTERFACE
        -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
        -Wnon-virtual-dtor -Wcast-align -Wunused -Wmisleading-indentation
        -Wduplicated-cond -Wduplicated-branches -Wlogical-op
        -Wnull-dereference -Wdouble-promotion -Wformat=2
        $<$<BOOL:${MORPHKATZ_WARNINGS_AS_ERRORS}>:-Werror>
    )
    if(MORPHKATZ_ENABLE_ASAN)
        target_compile_options(morphkatz_compile_options INTERFACE -fsanitize=address -fno-omit-frame-pointer)
        target_link_options(morphkatz_compile_options    INTERFACE -fsanitize=address)
    endif()
    if(MORPHKATZ_ENABLE_UBSAN)
        target_compile_options(morphkatz_compile_options INTERFACE -fsanitize=undefined)
        target_link_options(morphkatz_compile_options    INTERFACE -fsanitize=undefined)
    endif()
endif()

# ---------------------------------------------------------------------------
# Third-party dependencies (via vcpkg manifest mode)
# ---------------------------------------------------------------------------
find_package(Zydis         CONFIG REQUIRED)
find_package(LIEF          CONFIG REQUIRED)
find_package(CLI11         CONFIG REQUIRED)
find_package(spdlog        CONFIG REQUIRED)
find_package(fmt           CONFIG REQUIRED)
find_package(yaml-cpp      CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
# OpenSSL is already pulled in as a transitive of LIEF; we depend on it
# directly for analysis/metrics.cpp's SHA-256 helper.
find_package(OpenSSL       REQUIRED)

if(MORPHKATZ_WITH_YARA)
    find_package(unofficial-libyara CONFIG QUIET)
    if(NOT unofficial-libyara_FOUND)
        find_package(yara CONFIG REQUIRED)
    endif()
endif()

if(MORPHKATZ_WITH_UNICORN)
    # The vcpkg port currently ships only a pkg-config file for unicorn
    # (no unicornConfig.cmake). Prefer a CMake package if a future port
    # starts shipping one; fall back to locating the static library and
    # headers under the vcpkg-managed prefix and wrapping them in an
    # imported target so downstream code can keep linking against
    # unicorn::unicorn uniformly.
    find_package(unicorn CONFIG QUIET)
    if(NOT TARGET unicorn::unicorn)
        find_library(MORPHKATZ_UNICORN_LIB   NAMES unicorn REQUIRED)
        find_path   (MORPHKATZ_UNICORN_INC   NAMES unicorn/unicorn.h REQUIRED)
        add_library(unicorn::unicorn UNKNOWN IMPORTED)
        set_target_properties(unicorn::unicorn PROPERTIES
            IMPORTED_LOCATION             "${MORPHKATZ_UNICORN_LIB}"
            INTERFACE_INCLUDE_DIRECTORIES "${MORPHKATZ_UNICORN_INC}")
        message(STATUS "Unicorn: wrapped pkg-config-only port as unicorn::unicorn")
        message(STATUS "  lib : ${MORPHKATZ_UNICORN_LIB}")
        message(STATUS "  inc : ${MORPHKATZ_UNICORN_INC}")
    endif()
endif()

# ---------------------------------------------------------------------------
# Core library: morphkatz_core
# ---------------------------------------------------------------------------
add_library(morphkatz_core STATIC
    # common
    src/common/logging.cpp
    src/common/wide.cpp
    src/common/error.cpp
    # format
    src/format/pe_image.cpp
    src/format/pe_section_appender.cpp
    src/format/pe_reloc.cpp
    src/format/pe_tls.cpp
    # disasm
    src/disasm/decoder.cpp
    src/disasm/cfg.cpp
    # ir
    src/ir/instruction.cpp
    src/ir/flags_effect.cpp
    # analysis
    src/analysis/flag_liveness.cpp
    src/analysis/metrics.cpp
    src/analysis/binary_diff.cpp
    # rules
    src/rules/rule_loader.cpp
    src/rules/rule_matcher.cpp
    # datapass (atom-mutation pass for .rdata/.data)
    src/datapass/atom_discovery.cpp
    src/datapass/decoder_stub.cpp
    src/datapass/pass.cpp
    # engine
    src/engine/rng.cpp
    src/engine/pad_policy.cpp
    src/engine/polymorph.cpp
    src/engine/patcher.cpp
    src/engine/encoder.cpp
    src/engine/orchestrator.cpp
    src/engine/batch.cpp
    src/engine/compare.cpp
    # verify
    src/verify/re_disasm_check.cpp
    src/verify/unicorn_verify.cpp
    # yara targeting
    src/yara/yara_target.cpp
    # scan (Defender Tier-1)
    src/scan/scanner.cpp
    src/scan/preconditions.cpp
    src/scan/threat_classify.cpp
    src/scan/mpcmdrun_scanner.cpp
    src/scan/pe_scan_ranges.cpp
    src/scan/bisect.cpp
    src/scan/defender_target.cpp
    src/scan/scan_subcommand.cpp
    # report
    src/report/diff_report.cpp
    # cli args
    src/cli/args.cpp
)
add_library(morphkatz::core ALIAS morphkatz_core)

target_include_directories(morphkatz_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(morphkatz_core
    PUBLIC
        morphkatz::compile_options
        Zydis::Zydis
        LIEF::LIEF
        CLI11::CLI11
        spdlog::spdlog
        fmt::fmt
        yaml-cpp::yaml-cpp
        nlohmann_json::nlohmann_json
        OpenSSL::Crypto
)

if(WIN32)
    target_link_libraries(morphkatz_core PUBLIC
        imagehlp
        wintrust
        crypt32
        bcrypt
    )
endif()

if(MORPHKATZ_WITH_YARA)
    target_compile_definitions(morphkatz_core PUBLIC MORPHKATZ_WITH_YARA=1)
    if(TARGET unofficial::libyara::libyara)
        target_link_libraries(morphkatz_core PUBLIC unofficial::libyara::libyara)
    else()
        target_link_libraries(morphkatz_core PUBLIC yara::yara)
    endif()
endif()

if(MORPHKATZ_WITH_UNICORN)
    target_compile_definitions(morphkatz_core PUBLIC MORPHKATZ_WITH_UNICORN=1)
    target_link_libraries(morphkatz_core PUBLIC unicorn::unicorn)
endif()

if(MORPHKATZ_WITH_HYPERSCAN)
    find_package(hyperscan CONFIG REQUIRED)
    target_compile_definitions(morphkatz_core PUBLIC MORPHKATZ_WITH_HYPERSCAN=1)
    target_link_libraries(morphkatz_core PUBLIC hyperscan::hyperscan)
endif()

# ---------------------------------------------------------------------------
# Executable: morphkatz
# ---------------------------------------------------------------------------
add_executable(morphkatz src/main.cpp)
target_link_libraries(morphkatz PRIVATE morphkatz::core morphkatz::compile_options)
set_target_properties(morphkatz PROPERTIES OUTPUT_NAME "morphkatz")

# Natvis debug visualisers for Visual Studio.
if(MSVC)
    target_sources(morphkatz PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/packaging/vs/morphkatz.natvis)
endif()

# Embed the shipped rule packs alongside the executable on install.
install(TARGETS morphkatz RUNTIME DESTINATION bin)
install(DIRECTORY rules/ DESTINATION share/morphkatz/rules)
install(DIRECTORY docs/  DESTINATION share/morphkatz/docs OPTIONAL)
install(FILES README.md LICENSE DESTINATION share/morphkatz)

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(MORPHKATZ_BUILD_TESTS)
    enable_testing()
    find_package(Catch2 3 CONFIG REQUIRED)
    include(Catch)
    add_subdirectory(tests)
endif()

# ---------------------------------------------------------------------------
# Bench
# ---------------------------------------------------------------------------
if(MORPHKATZ_BUILD_BENCH)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/bench/CMakeLists.txt")
        message(WARNING
            "MORPHKATZ_BUILD_BENCH=ON but bench/ is absent; skipping. "
            "Benchmarks are planned for v1.1.")
    else()
        find_package(benchmark CONFIG REQUIRED)
        add_subdirectory(bench)
    endif()
endif()

# ---------------------------------------------------------------------------
# Fuzz (libFuzzer, clang-cl only)
# ---------------------------------------------------------------------------
if(MORPHKATZ_BUILD_FUZZ)
    if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        message(WARNING
            "MORPHKATZ_BUILD_FUZZ=ON requires clang-cl; current compiler is "
            "${CMAKE_CXX_COMPILER_ID}. Skipping fuzz targets.")
    else()
        add_subdirectory(fuzz)
    endif()
endif()

# ---------------------------------------------------------------------------
# IDE grouping for Visual Studio solution explorer
# ---------------------------------------------------------------------------
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR}/include PREFIX "Header Files" FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/include)
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR}/src     PREFIX "Source Files" FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/src)
