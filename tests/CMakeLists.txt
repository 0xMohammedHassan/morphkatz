add_executable(morphkatz_tests
    unit/smoke_test.cpp
    unit/error_test.cpp
    unit/wide_test.cpp
    unit/rng_test.cpp
    unit/pad_policy_test.cpp
    unit/flags_effect_test.cpp
    unit/flag_liveness_test.cpp
    unit/rule_loader_test.cpp
    unit/rule_matcher_test.cpp
    unit/cfg_test.cpp
    unit/patcher_test.cpp
    unit/polymorph_test.cpp
    unit/yara_target_test.cpp
    unit/pe_image_test.cpp
    unit/metrics_test.cpp
    unit/binary_diff_test.cpp
    unit/orchestrator_test.cpp
    unit/batch_test.cpp
    unit/cli_test.cpp
    unit/report_test.cpp
    unit/mpcmdrun_discovery_test.cpp
    unit/mpcmdrun_parse_test.cpp
    unit/threat_classify_test.cpp
    unit/pe_scan_ranges_test.cpp
    unit/bisect_test.cpp
    unit/defender_target_test.cpp
    unit/preconditions_test.cpp
    unit/eicar_smoke_test.cpp
    unit/atom_discovery_test.cpp
    unit/pe_section_appender_test.cpp
    unit/decoder_stub_test.cpp
    unit/pe_reloc_test.cpp
    unit/pe_tls_test.cpp
    unit/data_pass_test.cpp
    integration/targeted_byte_pairs_test.cpp
    integration/data_string_demo_test.cpp
)

target_link_libraries(morphkatz_tests
    PRIVATE
        morphkatz::core
        morphkatz::compile_options
        Catch2::Catch2WithMain
)

target_compile_definitions(morphkatz_tests
    PRIVATE
        MORPHKATZ_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}"
        MORPHKATZ_RULES_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../rules"
)

catch_discover_tests(morphkatz_tests
    TEST_SPEC "~[requires-defender]"
    PROPERTIES
        LABELS "unit"
    DISCOVERY_TIMEOUT 30
)

# Defender-dependent tests: registered with a separate label so the
# CI gates can opt-in (--label-regex requires-defender) without paying
# the Defender-availability tax on every run.
catch_discover_tests(morphkatz_tests
    TEST_SPEC "[requires-defender]"
    TEST_PREFIX "defender."
    PROPERTIES
        LABELS "requires-defender"
    DISCOVERY_TIMEOUT 30
)

set_target_properties(morphkatz_tests PROPERTIES FOLDER "tests")
