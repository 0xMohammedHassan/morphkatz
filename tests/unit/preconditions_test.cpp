#include "morphkatz/scan/preconditions.hpp"

#include <catch2/catch_test_macros.hpp>

using morphkatz::scan::DefenderState;
using morphkatz::scan::PreconditionExpectations;
using morphkatz::scan::query_state;
using morphkatz::scan::state_to_string;
using morphkatz::scan::validate;

TEST_CASE("validate accepts a fully-disabled Defender", "[scan][unit]") {
    DefenderState s;
    s.defender_present              = true;
    s.spynet_reporting              = 0;
    s.submit_samples_consent        = 2;
    s.disable_realtime_monitoring   = 1;

    PreconditionExpectations e;
    e.require_cloud_off       = true;
    e.require_submission_off  = true;
    e.require_rtp_off         = true;
    auto r = validate(s, e);
    CHECK(r.ok());
}

TEST_CASE("validate ignores SubmitSamplesConsent when MAPS is off", "[scan][unit]") {
    // Real-world reproducer: registry stores SubmitSamplesConsent=0
    // ("AlwaysPrompt") but `Get-MpPreference` reports the effective
    // value "2 = NeverSend" because cloud is off and there's nothing
    // to submit. The validator must not false-fail in that state.
    DefenderState s;
    s.defender_present       = true;
    s.spynet_reporting       = 0;        // cloud off
    s.submit_samples_consent = 0;        // raw registry is 0
    PreconditionExpectations e;
    auto r = validate(s, e);
    CHECK(r.ok());
}

TEST_CASE("validate hard-fails when MAPS still on", "[scan][unit]") {
    DefenderState s;
    s.defender_present       = true;
    s.spynet_reporting       = 2;        // basic reporting
    s.submit_samples_consent = 2;
    PreconditionExpectations e;
    auto r = validate(s, e);
    CHECK_FALSE(r.ok());
    CHECK(r.error().what.find("SpynetReporting") != std::string::npos);
    CHECK(r.error().what.find("Set-MpPreference") != std::string::npos);
}

TEST_CASE("validate passes when Defender hive missing", "[scan][unit]") {
    DefenderState s;
    s.defender_present = false;
    PreconditionExpectations e;
    auto r = validate(s, e);
    CHECK(r.ok());
}

TEST_CASE("validate honours tolerate_unreadable", "[scan][unit]") {
    DefenderState s;
    s.defender_present = true;          // hive readable, values aren't
    PreconditionExpectations e;
    e.tolerate_unreadable = true;
    auto r = validate(s, e);
    CHECK(r.ok());
}

TEST_CASE("state_to_string is stable", "[scan][unit]") {
    DefenderState s;
    s.defender_present = true;
    s.spynet_reporting = 0;
    auto txt = state_to_string(s);
    CHECK(txt.find("defender_present=yes") != std::string::npos);
    CHECK(txt.find("SpynetReporting") != std::string::npos);
}

TEST_CASE("query_state runs without crashing", "[scan][unit]") {
    auto s = query_state();
    // We can't assert the exact values - they depend on the host -
    // but the call should succeed.
    (void)s;
    SUCCEED();
}
