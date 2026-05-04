#include "morphkatz/report/diff_report.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>

TEST_CASE("DiffReport writes JSON by default", "[report]") {
    morphkatz::report::DiffReport r("in.exe", "out.exe.patched");
    r.record_direct(0x1000, 0x400, {0x48, 0x31, 0xC0}, {0x48, 0x29, 0xC0},
                    "x64.zero.xor_to_sub");

    const auto tmp = std::filesystem::temp_directory_path() / "morphkatz_report.json";
    auto rc = r.write(tmp);
    REQUIRE(rc.ok());

    std::string s;
    {
        std::ifstream f(tmp);
        std::stringstream body;
        body << f.rdbuf();
        s = body.str();
    }  // close the ifstream before removing; Windows refuses delete while the read handle is open.
    REQUIRE(s.find("x64.zero.xor_to_sub") != std::string::npos);
    REQUIRE(s.find("\"count\": 1") != std::string::npos);
    std::filesystem::remove(tmp);
}

TEST_CASE("DiffReport writes HTML when extension is .html", "[report]") {
    morphkatz::report::DiffReport r("in.exe", "out.exe.patched");
    r.record_raw(0x200, {0x33, 0xC0}, {0x29, 0xC0}, "x64.donut.zero_eax_variant_1");

    const auto tmp = std::filesystem::temp_directory_path() / "morphkatz_report.html";
    auto rc = r.write(tmp);
    REQUIRE(rc.ok());

    std::string s;
    {
        std::ifstream f(tmp);
        std::stringstream body;
        body << f.rdbuf();
        s = body.str();
    }
    REQUIRE(s.find("<!doctype html>") != std::string::npos);
    REQUIRE(s.find("donut") != std::string::npos);
    std::filesystem::remove(tmp);
}

TEST_CASE("DiffReport YARA summary surfaces broken rules", "[report][yara]") {
    morphkatz::report::DiffReport r("in.exe", "out.exe.patched");
    r.record_yara({"Sig_A", "Sig_B", "Sig_C"}, {"Sig_C"});
    const auto& y = r.yara();
    REQUIRE(y.pre_hits.size()  == 3);
    REQUIRE(y.post_hits.size() == 1);
    REQUIRE(y.broken.size()    == 2);

    const auto tmp = std::filesystem::temp_directory_path() / "morphkatz_report_yara.json";
    auto rc = r.write(tmp);
    REQUIRE(rc.ok());
    std::string s;
    {
        std::ifstream f(tmp);
        std::stringstream body; body << f.rdbuf();
        s = body.str();
    }
    REQUIRE(s.find("\"broken\"") != std::string::npos);
    REQUIRE(s.find("Sig_A") != std::string::npos);
    std::filesystem::remove(tmp);
}
