#include "morphkatz/scan/mpcmdrun_scanner.hpp"
#include "morphkatz/scan/scanner.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

using morphkatz::scan::parse_mpcmdrun_output;
using morphkatz::scan::parse_mpcmdrun_threat_line;
using morphkatz::scan::sanitize_scanner_output;

TEST_CASE("parse_mpcmdrun_threat_line recognises canonical key", "[scan][unit]") {
    auto t = parse_mpcmdrun_threat_line("Threat                  : Trojan:Win32/Mimikatz");
    REQUIRE(t.has_value());
    CHECK(t->name == "Trojan:Win32/Mimikatz");
    CHECK_FALSE(t->is_ml);

    auto t2 = parse_mpcmdrun_threat_line("Threat: Trojan:Script/Wacatac.B!ml");
    REQUIRE(t2.has_value());
    CHECK(t2->is_ml);
}

TEST_CASE("parse_mpcmdrun_threat_line skips unrelated lines", "[scan][unit]") {
    CHECK_FALSE(parse_mpcmdrun_threat_line("Severity : Severe").has_value());
    CHECK_FALSE(parse_mpcmdrun_threat_line("just some text").has_value());
    CHECK_FALSE(parse_mpcmdrun_threat_line("").has_value());
}

TEST_CASE("parse_mpcmdrun_output handles a clean scan", "[scan][unit]") {
    static const std::string canned =
        "Scan starting...\r\n"
        "Engine Version              : 1.1.24080.4\r\n"
        "Antivirus signature version : 1.413.2226.0\r\n"
        "Scan completed.\r\n"
        "No threats found.\r\n";
    auto v = parse_mpcmdrun_output(canned, 0);
    CHECK_FALSE(v.infected);
    CHECK(v.threats.empty());
    CHECK(v.engine_version == "1.1.24080.4");
    CHECK(v.vdm_version    == "1.413.2226.0");
    CHECK(v.raw_exit_code  == 0);
}

TEST_CASE("parse_mpcmdrun_output picks up a single threat", "[scan][unit]") {
    static const std::string canned =
        "Scan starting...\r\n"
        "Threat                  : Virus:DOS/EICAR_Test_File\r\n"
        "Severity                : Severe\r\n"
        "Engine Version          : 1.1.24080.4\r\n"
        "Antivirus signature version: 1.413.2226.0\r\n";
    auto v = parse_mpcmdrun_output(canned, 2);
    CHECK(v.infected);
    REQUIRE(v.threats.size() == 1);
    CHECK(v.threats[0].name == "Virus:DOS/EICAR_Test_File");
    CHECK(v.threats[0].severity == "Severe");
    CHECK(v.raw_exit_code == 2);
}

TEST_CASE("parse_mpcmdrun_output picks up multiple threats", "[scan][unit]") {
    static const std::string canned =
        "Threat   : Trojan:Win32/Mimikatz\r\n"
        "Severity : Severe\r\n"
        "Threat   : HackTool:Win32/Mimikatz!8\r\n"
        "Severity : High\r\n";
    auto v = parse_mpcmdrun_output(canned, 2);
    REQUIRE(v.threats.size() == 2);
    CHECK(v.threats[0].name == "Trojan:Win32/Mimikatz");
    CHECK(v.threats[0].severity == "Severe");
    CHECK(v.threats[1].name == "HackTool:Win32/Mimikatz!8");
    CHECK(v.threats[1].severity == "High");
}

TEST_CASE("sanitize_scanner_output strips control bytes", "[scan][unit]") {
    // Use string-concat to terminate the hex escape so 0x01 doesn't
    // greedily absorb the following 'b' into 0x1ba.
    std::string raw{"foo\x00" "bar\x01" "baz\r\nend\n  ", 17};
    auto out = sanitize_scanner_output(raw);
    // NUL and 0x01 dropped, trailing whitespace trimmed
    CHECK(out.find('\x00') == std::string::npos);
    CHECK(out.find('\x01') == std::string::npos);
    CHECK(out.back() == 'd');
}
