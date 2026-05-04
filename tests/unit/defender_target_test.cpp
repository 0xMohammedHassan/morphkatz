#include "morphkatz/scan/defender_target.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace {

using morphkatz::scan::IDefenderScanner;
using morphkatz::scan::ScanVerdict;
using morphkatz::scan::Threat;

// Tiny mock scanner whose verdict can be reconfigured per-call. The
// orchestrator only consults `scan_file` and `scan_buffer`, so we
// stub both. `scan_file` reads bytes off disk and delegates to
// scan_buffer so a single rule (the contains_needle predicate) covers
// both paths.
class MockScanner final : public IDefenderScanner {
public:
    void set_verdict(bool infected, std::string threat_name,
                     bool is_ml = false) {
        infected_ = infected;
        name_     = std::move(threat_name);
        is_ml_    = is_ml;
    }

    morphkatz::Result<ScanVerdict>
    scan_file(const std::filesystem::path& path) override {
        std::ifstream f(path, std::ios::binary);
        if (!f) {
            return morphkatz::Error::make(morphkatz::ErrorKind::Io,
                "mock cannot open", path.string());
        }
        std::vector<uint8_t> buf{
            std::istreambuf_iterator<char>(f),
            std::istreambuf_iterator<char>()
        };
        return scan_buffer(std::span<const uint8_t>(buf), "from-file");
    }

    morphkatz::Result<ScanVerdict>
    scan_buffer(std::span<const uint8_t> bytes,
                std::string_view) override {
        ScanVerdict v;
        // Honour the configured verdict only when the buffer contains
        // our magic 4-byte needle so bisection still narrows the
        // window to the needle location.
        bool flag = infected_;
        if (flag) {
            bool found = false;
            for (size_t i = 0; i + 4 <= bytes.size(); ++i) {
                if (bytes[i] == 0xCC && bytes[i + 1] == 0xCC &&
                    bytes[i + 2] == 0xCC && bytes[i + 3] == 0xCC) {
                    found = true; break;
                }
            }
            flag = found;
        }
        v.infected = flag;
        if (flag) {
            Threat t;
            t.name  = name_;
            t.is_ml = is_ml_;
            v.threats.push_back(std::move(t));
        }
        return v;
    }

    std::string engine_label() const override { return "Mock"; }

private:
    bool        infected_ = false;
    std::string name_;
    bool        is_ml_    = false;
};

std::filesystem::path write_buf(const std::vector<uint8_t>& bytes,
                                const std::string& tag) {
    auto dir = std::filesystem::temp_directory_path() / "morphkatz-defender-test";
    std::filesystem::create_directories(dir);
    auto p = dir / (tag + ".bin");
    std::ofstream f(p, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    return p;
}

}  // namespace

TEST_CASE("DefenderTarget probe + bisect populates an anchor", "[scan][unit]") {
    std::vector<uint8_t> bytes(2048, 0xAA);
    bytes[1024] = 0xCC; bytes[1025] = 0xCC;
    bytes[1026] = 0xCC; bytes[1027] = 0xCC;
    auto path = write_buf(bytes, "anchor-input");

    auto scanner = std::make_shared<MockScanner>();
    scanner->set_verdict(true, "Trojan:Win32/Foo");

    auto t = morphkatz::scan::DefenderTarget::from_file(path, scanner);
    REQUIRE(t.ok());
    auto& target = *t;
    REQUIRE(target.probe().ok());
    CHECK(target.probed());
    REQUIRE(target.pre_threats().size() == 1);
    CHECK(target.pre_threats()[0].name == "Trojan:Win32/Foo");
    REQUIRE(target.anchors().size() == 1);
    const auto& anchor = target.anchors().front();
    CHECK(anchor.file_offset <= 1024);
    CHECK(anchor.file_offset + anchor.bytes.size() > 1024);
}

TEST_CASE("DefenderTarget priority_for_va boosts overlapping VAs", "[scan][unit]") {
    std::vector<uint8_t> bytes(512, 0xAA);
    bytes[100] = bytes[101] = bytes[102] = bytes[103] = 0xCC;
    auto path = write_buf(bytes, "boost-input");

    auto scanner = std::make_shared<MockScanner>();
    scanner->set_verdict(true, "Trojan:Win32/Boost");
    auto t = morphkatz::scan::DefenderTarget::from_file(path, scanner);
    REQUIRE(t.ok());
    REQUIRE(t->probe().ok());

    std::vector<uint8_t> old_bytes(4, 0xAA);
    std::vector<uint8_t> new_bytes(4, 0xBB);
    const auto va_inside  = t->anchors().front().file_offset;
    const auto va_outside = uint64_t{0};
    CHECK(t->priority_for_va(va_inside,
        std::span<const uint8_t>(old_bytes),
        std::span<const uint8_t>(new_bytes)) > 0.0);
    CHECK(t->priority_for_va(va_outside,
        std::span<const uint8_t>(old_bytes),
        std::span<const uint8_t>(new_bytes)) == 0.0);
}

TEST_CASE("DefenderTarget evaluate_after_mutation reports diff", "[scan][unit]") {
    std::vector<uint8_t> bytes(256, 0xAA);
    bytes[64] = bytes[65] = bytes[66] = bytes[67] = 0xCC;
    auto pre  = write_buf(bytes, "pre");
    auto scanner = std::make_shared<MockScanner>();
    scanner->set_verdict(true, "Trojan:Win32/Demo");

    auto t = morphkatz::scan::DefenderTarget::from_file(pre, scanner);
    REQUIRE(t.ok());
    REQUIRE(t->probe().ok());

    // Now mutate: zero out the needle so the post-scan would come
    // back clean.
    auto mutated = bytes;
    mutated[64] = mutated[65] = mutated[66] = mutated[67] = 0x90;
    auto post = write_buf(mutated, "post");

    auto diff = t->evaluate_after_mutation(post);
    REQUIRE(diff.ok());
    CHECK(diff->broken.size() == 1);
    CHECK(diff->broken.front() == "Trojan:Win32/Demo");
    CHECK(diff->persisted.empty());
    CHECK(diff->introduced.empty());
}
