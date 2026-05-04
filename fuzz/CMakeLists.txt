# Fuzz targets are clang-cl + libFuzzer only. The top-level CMakeLists.txt
# guards the add_subdirectory() call behind MORPHKATZ_BUILD_FUZZ=ON and a
# Clang compiler-id check, so the checks here are defensive.

if(NOT CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    message(FATAL_ERROR "fuzz/ requires clang-cl; configure with the clang-cl-asan preset.")
endif()

add_executable(fuzz_rule_matcher fuzz_rule_matcher.cpp)
target_link_libraries(fuzz_rule_matcher
    PRIVATE
        morphkatz::core
        morphkatz::compile_options
)
target_compile_options(fuzz_rule_matcher PRIVATE
    /fsanitize=fuzzer,address
)
target_link_options(fuzz_rule_matcher PRIVATE
    /fsanitize=fuzzer,address
    /INCREMENTAL:NO
)
set_target_properties(fuzz_rule_matcher PROPERTIES
    FOLDER "fuzz"
    OUTPUT_NAME "fuzz_rule_matcher"
)
