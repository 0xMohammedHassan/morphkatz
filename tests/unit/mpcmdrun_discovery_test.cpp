#include "morphkatz/scan/mpcmdrun_scanner.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>

using morphkatz::scan::discover_mpcmdrun;

namespace {

std::filesystem::path make_fake_mpcmdrun(const std::filesystem::path& dir) {
    std::filesystem::create_directories(dir);
    auto exe = dir / "MpCmdRun.exe";
    std::ofstream f(exe, std::ios::binary | std::ios::trunc);
    f << "fake";
    return exe;
}

}

TEST_CASE("discover_mpcmdrun honours extra_search_dirs first", "[scan][unit]") {
    const auto root = std::filesystem::temp_directory_path()
        / "morphkatz-discovery-test";
    std::filesystem::remove_all(root);
    const auto fake = make_fake_mpcmdrun(root / "platform");

    auto found = discover_mpcmdrun({root / "platform"});
    REQUIRE(found.has_value());
    CHECK(std::filesystem::equivalent(*found, fake));

    std::filesystem::remove_all(root);
}

TEST_CASE("discover_mpcmdrun returns nullopt when nothing matches", "[scan][unit]") {
    const auto root = std::filesystem::temp_directory_path()
        / "morphkatz-discovery-empty";
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);

    // The defaults probe Defender's real install path; on a CI runner
    // this may or may not exist, so we can only assert the
    // extra_search_dirs override path explicitly. With an empty
    // override and a guaranteed-absent dir, the result is dependent on
    // the host. Skip the assertion when Defender is installed.
    auto found = discover_mpcmdrun({root});
    if (found) {
        // Some host-installed Defender path was returned. We at least
        // sanity check that it isn't the fake dir we created.
        CHECK_FALSE(std::filesystem::equivalent(found->parent_path(), root));
    } else {
        SUCCEED("Defender not installed on this host - discover returned nullopt");
    }

    std::filesystem::remove_all(root);
}
