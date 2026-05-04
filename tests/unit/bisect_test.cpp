#include "morphkatz/scan/bisect.hpp"
#include "morphkatz/scan/pe_scan_ranges.hpp"
#include "morphkatz/scan/scanner.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace {

using morphkatz::scan::IDefenderScanner;
using morphkatz::scan::ScanVerdict;
using morphkatz::scan::Threat;

// A scanner that flags any buffer containing a byte sequence in a
// configured "needle" range. Used to simulate a Defender hit anywhere
// inside a known offset window so the bisection algorithm can be
// exercised without a real engine.
class WindowScanner final : public IDefenderScanner {
public:
    WindowScanner(size_t lo, size_t hi, std::string threat_name,
                  bool is_ml = false)
        : lo_(lo), hi_(hi), name_(std::move(threat_name)), is_ml_(is_ml) {}

    morphkatz::Result<ScanVerdict>
    scan_file(const std::filesystem::path&) override {
        return morphkatz::Error::make(morphkatz::ErrorKind::NotSupported,
            "WindowScanner only handles buffers");
    }

    morphkatz::Result<ScanVerdict>
    scan_buffer(std::span<const uint8_t> bytes,
                std::string_view) override {
        ScanVerdict v;
        v.raw_exit_code = bytes_overlap(bytes) ? 2 : 0;
        v.infected = bytes_overlap(bytes);
        if (v.infected) {
            Threat t;
            t.name  = name_;
            t.is_ml = is_ml_;
            v.threats.push_back(std::move(t));
        }
        scan_count_++;
        return v;
    }

    std::string engine_label() const override { return "WindowScanner"; }

    int scan_count() const noexcept { return scan_count_; }

private:
    bool bytes_overlap(std::span<const uint8_t> bytes) const noexcept {
        // The fake scanner is fed sub-spans of the same backing
        // sequence we constructed in the test; we infer overlap by
        // searching for the needle byte (0xCC) inside the slice.
        for (size_t i = 0; i + 4 <= bytes.size(); ++i) {
            if (bytes[i] == 0xCC && bytes[i + 1] == 0xCC &&
                bytes[i + 2] == 0xCC && bytes[i + 3] == 0xCC) {
                return true;
            }
        }
        return false;
    }

    size_t lo_;
    size_t hi_;
    std::string name_;
    bool is_ml_;
    int scan_count_ = 0;
};

std::vector<uint8_t> make_buf(size_t n, size_t needle_at) {
    std::vector<uint8_t> v(n, 0xAA);
    for (size_t i = 0; i < 4 && needle_at + i < n; ++i) {
        v[needle_at + i] = 0xCC;
    }
    return v;
}

}  // namespace

TEST_CASE("bisect_single isolates a left-half anchor", "[scan][unit]") {
    auto buf = make_buf(1024, 64);
    WindowScanner s(64, 68, "Trojan:Win32/Foo");
    morphkatz::scan::BisectOptions opts;
    opts.min_chunk = 8;

    auto br = morphkatz::scan::bisect_single(s, std::span<const uint8_t>(buf), opts);
    REQUIRE(br.ok());
    CHECK(br->status == morphkatz::scan::BisectResult::Status::Found);
    CHECK(br->offset <= 64);
    CHECK(br->offset + br->length > 64);
    CHECK(br->length <= 16);  // narrowed past initial halve
    CHECK(s.scan_count() > 1);
}

TEST_CASE("bisect_single isolates a right-half anchor", "[scan][unit]") {
    auto buf = make_buf(2048, 1900);
    WindowScanner s(1900, 1904, "Trojan:Win32/Bar");
    morphkatz::scan::BisectOptions opts;
    opts.min_chunk = 8;

    auto br = morphkatz::scan::bisect_single(s, std::span<const uint8_t>(buf), opts);
    REQUIRE(br.ok());
    CHECK(br->status == morphkatz::scan::BisectResult::Status::Found);
    CHECK(br->offset <= 1900);
    CHECK(br->offset + br->length > 1903);
}

TEST_CASE("bisect_single returns Clean for non-flagged input", "[scan][unit]") {
    std::vector<uint8_t> buf(256, 0xAA);
    WindowScanner s(0, 0, "irrelevant");
    auto br = morphkatz::scan::bisect_single(
        s, std::span<const uint8_t>(buf), {});
    REQUIRE(br.ok());
    CHECK(br->status == morphkatz::scan::BisectResult::Status::Clean);
    CHECK(s.scan_count() == 1);
}

TEST_CASE("bisect_single refuses to recurse on !ml detections", "[scan][unit]") {
    auto buf = make_buf(512, 100);
    WindowScanner s(100, 104, "Trojan:Win32/Foo!ml", /*is_ml=*/true);
    auto br = morphkatz::scan::bisect_single(
        s, std::span<const uint8_t>(buf), {});
    REQUIRE(br.ok());
    CHECK(br->status == morphkatz::scan::BisectResult::Status::MlDetection);
    CHECK(s.scan_count() == 1);
}

TEST_CASE("bisect_single honours max_scans budget", "[scan][unit]") {
    auto buf = make_buf(1 << 14, (1 << 13));
    WindowScanner s(0, 0, "Trojan:Win32/Budget");
    morphkatz::scan::BisectOptions opts;
    opts.max_scans = 5;
    opts.min_chunk = 1;
    auto br = morphkatz::scan::bisect_single(
        s, std::span<const uint8_t>(buf), opts);
    REQUIRE(br.ok());
    CHECK(s.scan_count() <= 6);  // initial + budget
}

// Scanner with N independent needles. Used to exercise bisect_multi's
// peel-and-rescan behaviour: each peel masks the previously-found
// needle in the working copy, so the next call should observe the
// next-strongest signature.
namespace {

class MultiNeedleScanner final : public IDefenderScanner {
public:
    struct Needle {
        std::vector<uint8_t> bytes;
        std::string          name;
        bool                 is_ml = false;
    };

    explicit MultiNeedleScanner(std::vector<Needle> needles)
        : needles_(std::move(needles)) {}

    morphkatz::Result<ScanVerdict>
    scan_file(const std::filesystem::path&) override {
        return morphkatz::Error::make(morphkatz::ErrorKind::NotSupported,
            "MultiNeedleScanner only handles buffers");
    }

    morphkatz::Result<ScanVerdict>
    scan_buffer(std::span<const uint8_t> bytes,
                std::string_view) override {
        scan_count_++;
        ScanVerdict v;
        for (const auto& n : needles_) {
            if (contains(bytes, n.bytes)) {
                Threat t;
                t.name  = n.name;
                t.is_ml = n.is_ml;
                v.threats.push_back(std::move(t));
                v.infected = true;
            }
        }
        v.raw_exit_code = v.infected ? 2 : 0;
        return v;
    }

    std::string engine_label() const override { return "MultiNeedleScanner"; }
    int scan_count() const noexcept { return scan_count_; }

private:
    static bool contains(std::span<const uint8_t> hay,
                         std::span<const uint8_t> needle) noexcept {
        if (needle.empty() || hay.size() < needle.size()) return false;
        for (size_t i = 0; i + needle.size() <= hay.size(); ++i) {
            bool match = true;
            for (size_t j = 0; j < needle.size(); ++j) {
                if (hay[i + j] != needle[j]) { match = false; break; }
            }
            if (match) return true;
        }
        return false;
    }

    std::vector<Needle> needles_;
    int                 scan_count_ = 0;
};

void splice(std::vector<uint8_t>& dst, size_t at,
            const std::vector<uint8_t>& src) {
    REQUIRE(at + src.size() <= dst.size());
    std::copy(src.begin(), src.end(), dst.begin() + at);
}

}  // namespace

TEST_CASE("bisect_multi isolates two distinct anchors", "[scan][unit]") {
    std::vector<uint8_t> buf(4096, 0xAA);
    const std::vector<uint8_t> n1{0xCC, 0xCC, 0xCC, 0xCC};
    const std::vector<uint8_t> n2{0xDD, 0xDD, 0xDD, 0xDD};
    splice(buf, 200,  n1);
    splice(buf, 3500, n2);

    MultiNeedleScanner s({{n1, "Trojan:Win32/Foo", false},
                          {n2, "Trojan:Win32/Bar", false}});

    morphkatz::scan::MultiBisectOptions opts;
    opts.min_chunk            = 8;
    opts.max_anchors          = 4;
    opts.total_max_scans      = 128;
    opts.per_anchor_max_scans = 64;

    auto br = morphkatz::scan::bisect_multi(
        s, std::span<const uint8_t>(buf), opts);
    REQUIRE(br.ok());
    CHECK(br->status == morphkatz::scan::MultiBisectResult::Status::Done);
    REQUIRE(br->anchors.size() == 2);
    CHECK(br->initial_threats.size() == 2);

    bool covers_left  = false;
    bool covers_right = false;
    for (const auto& a : br->anchors) {
        if (a.offset <= 200  && a.offset + a.length > 200 + 3)  covers_left  = true;
        if (a.offset <= 3500 && a.offset + a.length > 3500 + 3) covers_right = true;
    }
    CHECK(covers_left);
    CHECK(covers_right);
}

TEST_CASE("bisect_multi isolates three independent anchors", "[scan][unit]") {
    std::vector<uint8_t> buf(8192, 0xAA);
    const std::vector<uint8_t> n1{0xCC, 0xCC, 0xCC, 0xCC};
    const std::vector<uint8_t> n2{0xDD, 0xDD, 0xDD, 0xDD};
    const std::vector<uint8_t> n3{0xEE, 0xEE, 0xEE, 0xEE};
    splice(buf, 100,  n1);
    splice(buf, 4000, n2);
    splice(buf, 7900, n3);

    MultiNeedleScanner s({{n1, "Trojan:Win32/A", false},
                          {n2, "Trojan:Win32/B", false},
                          {n3, "Trojan:Win32/C", false}});

    morphkatz::scan::MultiBisectOptions opts;
    opts.min_chunk            = 8;
    opts.max_anchors          = 8;
    opts.total_max_scans      = 256;
    opts.per_anchor_max_scans = 64;

    auto br = morphkatz::scan::bisect_multi(
        s, std::span<const uint8_t>(buf), opts);
    REQUIRE(br.ok());
    CHECK(br->status == morphkatz::scan::MultiBisectResult::Status::Done);
    CHECK(br->anchors.size() == 3);
}

TEST_CASE("bisect_multi honours max_anchors cap", "[scan][unit]") {
    std::vector<uint8_t> buf(4096, 0xAA);
    const std::vector<uint8_t> n1{0xCC, 0xCC, 0xCC, 0xCC};
    const std::vector<uint8_t> n2{0xDD, 0xDD, 0xDD, 0xDD};
    splice(buf, 200,  n1);
    splice(buf, 3000, n2);

    MultiNeedleScanner s({{n1, "Trojan:Win32/A", false},
                          {n2, "Trojan:Win32/B", false}});

    morphkatz::scan::MultiBisectOptions opts;
    opts.min_chunk            = 8;
    opts.max_anchors          = 1;          // cap to one
    opts.total_max_scans      = 128;
    opts.per_anchor_max_scans = 64;

    auto br = morphkatz::scan::bisect_multi(
        s, std::span<const uint8_t>(buf), opts);
    REQUIRE(br.ok());
    CHECK(br->status ==
          morphkatz::scan::MultiBisectResult::Status::ExhaustedAnchors);
    CHECK(br->anchors.size() == 1);
}

TEST_CASE("bisect_multi honours total_max_scans budget", "[scan][unit]") {
    std::vector<uint8_t> buf(8192, 0xAA);
    const std::vector<uint8_t> n1{0xCC, 0xCC, 0xCC, 0xCC};
    const std::vector<uint8_t> n2{0xDD, 0xDD, 0xDD, 0xDD};
    const std::vector<uint8_t> n3{0xEE, 0xEE, 0xEE, 0xEE};
    splice(buf, 200,  n1);
    splice(buf, 4000, n2);
    splice(buf, 7800, n3);

    MultiNeedleScanner s({{n1, "Trojan:Win32/A", false},
                          {n2, "Trojan:Win32/B", false},
                          {n3, "Trojan:Win32/C", false}});

    morphkatz::scan::MultiBisectOptions opts;
    opts.min_chunk            = 8;
    opts.max_anchors          = 8;
    opts.total_max_scans      = 4;          // very tight
    opts.per_anchor_max_scans = 64;

    auto br = morphkatz::scan::bisect_multi(
        s, std::span<const uint8_t>(buf), opts);
    REQUIRE(br.ok());
    CHECK(br->status ==
          morphkatz::scan::MultiBisectResult::Status::ExhaustedScans);
    CHECK(br->scan_count <= static_cast<int>(opts.total_max_scans) + 1);
}

TEST_CASE("bisect_multi refuses ML detection", "[scan][unit]") {
    std::vector<uint8_t> buf(1024, 0xAA);
    const std::vector<uint8_t> ml{0xEE, 0xEE, 0xEE, 0xEE};
    splice(buf, 100, ml);

    MultiNeedleScanner s({{ml, "Trojan:Win32/Foo!ml", true}});

    auto br = morphkatz::scan::bisect_multi(
        s, std::span<const uint8_t>(buf),
        morphkatz::scan::MultiBisectOptions{});
    REQUIRE(br.ok());
    CHECK(br->status ==
          morphkatz::scan::MultiBisectResult::Status::MlDetection);
    CHECK(br->anchors.empty());
}

// ---------------------------------------------------------------------
// Scoped (PE-aware) bisection tests. Use a hand-rolled synthetic PE so
// `compute_pe_scan_ranges` returns meaningful section windows. The
// MultiNeedleScanner mock above is reused - it doesn't care about PE
// structure, just byte-presence of the needles in whatever buffer it
// receives. The scoped bisect sends the FULL buffer with bytes outside
// the candidate window masked, so a needle inside .text disappears
// from the L scan that doesn't keep .text -> matches what Defender's
// signature engine sees in the real codepath.
// ---------------------------------------------------------------------
namespace {

constexpr size_t kPeSize       = 0x900;
constexpr size_t kPeElfanew    = 0x80;
constexpr size_t kPeSectTable  = 0x188;
constexpr size_t kTextOff      = 0x200;
constexpr size_t kTextSize     = 0x100;
constexpr size_t kRdataOff     = 0x500;
constexpr size_t kRdataSize    = 0x100;
constexpr size_t kDataOff      = 0x800;
constexpr size_t kDataSize     = 0x100;

inline void w16(std::vector<uint8_t>& b, size_t o, uint16_t v) {
    b[o] = uint8_t(v); b[o + 1] = uint8_t(v >> 8);
}
inline void w32(std::vector<uint8_t>& b, size_t o, uint32_t v) {
    b[o] = uint8_t(v); b[o + 1] = uint8_t(v >> 8);
    b[o + 2] = uint8_t(v >> 16); b[o + 3] = uint8_t(v >> 24);
}

void write_section(std::vector<uint8_t>& b, size_t off, const char* name,
                   uint32_t vsize, uint32_t vaddr,
                   uint32_t rsize, uint32_t rptr, uint32_t chars) {
    std::memset(b.data() + off, 0, 40);
    std::memcpy(b.data() + off, name, std::min<size_t>(8, std::strlen(name)));
    w32(b, off +  8, vsize);
    w32(b, off + 12, vaddr);
    w32(b, off + 16, rsize);
    w32(b, off + 20, rptr);
    w32(b, off + 36, chars);
}

std::vector<uint8_t> make_synthetic_pe() {
    std::vector<uint8_t> b(kPeSize, 0xCC);
    b[0] = 'M'; b[1] = 'Z';
    w32(b, 0x3c, uint32_t(kPeElfanew));

    b[kPeElfanew + 0] = 'P'; b[kPeElfanew + 1] = 'E';
    b[kPeElfanew + 2] = 0;   b[kPeElfanew + 3] = 0;

    const size_t coff = kPeElfanew + 4;
    w16(b, coff +  0, 0x8664);
    w16(b, coff +  2, 3);
    w16(b, coff + 16, 0xF0);
    w16(b, coff + 18, 0x22);

    const size_t opt = coff + 20;
    w16(b, opt + 0,    0x20b);
    w32(b, opt + 0x6c, 16);
    // No directories pointing into our needle locations -> the test
    // wouldn't survive a hole punched through the needle byte. We
    // explicitly leave all 16 entries zero.

    constexpr uint32_t kCode  = 0x60000020u;
    constexpr uint32_t kRdata = 0x40000040u;
    constexpr uint32_t kData  = 0xC0000040u;
    write_section(b, kPeSectTable + 0 * 40, ".text",
                  uint32_t(kTextSize),  0x1000,
                  uint32_t(kTextSize),  uint32_t(kTextOff),  kCode);
    write_section(b, kPeSectTable + 1 * 40, ".rdata",
                  uint32_t(kRdataSize), 0x2000,
                  uint32_t(kRdataSize), uint32_t(kRdataOff), kRdata);
    write_section(b, kPeSectTable + 2 * 40, ".data",
                  uint32_t(kDataSize),  0x3000,
                  uint32_t(kDataSize),  uint32_t(kDataOff),  kData);
    return b;
}

}  // namespace

TEST_CASE("bisect_single (scoped) narrows a needle inside .text",
          "[scan][unit][scoped]") {
    auto buf = make_synthetic_pe();
    const std::vector<uint8_t> n1{0xCC, 0xCC, 0xCC, 0xCC};
    // Needle goes inside .text, but .text is filled with 0xCC by
    // make_synthetic_pe (default fill). To make the needle uniquely
    // detectable, first zero the section and then splice the needle.
    std::fill(buf.begin() +
                static_cast<std::ptrdiff_t>(kTextOff),
              buf.begin() +
                static_cast<std::ptrdiff_t>(kTextOff + kTextSize),
              uint8_t{0xAA});
    splice(buf, kTextOff + 0x40, n1);
    // Same for the other sections - keep them un-needle-coloured.
    std::fill(buf.begin() +
                static_cast<std::ptrdiff_t>(kRdataOff),
              buf.begin() +
                static_cast<std::ptrdiff_t>(kRdataOff + kRdataSize),
              uint8_t{0xBB});
    std::fill(buf.begin() +
                static_cast<std::ptrdiff_t>(kDataOff),
              buf.begin() +
                static_cast<std::ptrdiff_t>(kDataOff + kDataSize),
              uint8_t{0xDD});

    MultiNeedleScanner s({{n1, "Trojan:Win32/Text", false}});

    auto ranges_r = morphkatz::scan::compute_pe_scan_ranges(
        buf, morphkatz::scan::ScanScope::Sections);
    REQUIRE(ranges_r.ok());
    REQUIRE_FALSE(ranges_r->empty());

    morphkatz::scan::BisectOptions opts;
    opts.min_chunk   = 4;
    opts.scan_ranges = *ranges_r;

    auto br = morphkatz::scan::bisect_single(
        s, std::span<const uint8_t>(buf), opts);
    REQUIRE(br.ok());
    CHECK(br->status == morphkatz::scan::BisectResult::Status::Found);
    CHECK(br->offset >= kTextOff);
    CHECK(br->offset + br->length <= kTextOff + kTextSize);
    CHECK(br->length <= 16);

    REQUIRE_FALSE(br->fragments.empty());
    for (const auto& f : br->fragments) {
        CHECK(f.file_offset >= kTextOff);
        CHECK(f.file_offset + f.length <= kTextOff + kTextSize);
    }
}

TEST_CASE("bisect_multi (scoped) finds anchors in .text and .rdata",
          "[scan][unit][scoped]") {
    auto buf = make_synthetic_pe();
    const std::vector<uint8_t> n1{0x11, 0x11, 0x11, 0x11};
    const std::vector<uint8_t> n2{0x22, 0x22, 0x22, 0x22};
    // Replace each section's 0xCC fill with a benign byte so the
    // needle bytes are uniquely identifiable.
    std::fill(buf.begin() +
                static_cast<std::ptrdiff_t>(kTextOff),
              buf.begin() +
                static_cast<std::ptrdiff_t>(kTextOff + kTextSize),
              uint8_t{0xAA});
    std::fill(buf.begin() +
                static_cast<std::ptrdiff_t>(kRdataOff),
              buf.begin() +
                static_cast<std::ptrdiff_t>(kRdataOff + kRdataSize),
              uint8_t{0xBB});
    std::fill(buf.begin() +
                static_cast<std::ptrdiff_t>(kDataOff),
              buf.begin() +
                static_cast<std::ptrdiff_t>(kDataOff + kDataSize),
              uint8_t{0xDD});
    splice(buf, kTextOff  + 0x20, n1);
    splice(buf, kRdataOff + 0x80, n2);

    MultiNeedleScanner s({
        {n1, "Trojan:Win32/Text",  false},
        {n2, "Trojan:Win32/Rdata", false},
    });

    auto ranges_r = morphkatz::scan::compute_pe_scan_ranges(
        buf, morphkatz::scan::ScanScope::Sections);
    REQUIRE(ranges_r.ok());

    morphkatz::scan::MultiBisectOptions opts;
    opts.min_chunk       = 4;
    opts.scan_ranges     = *ranges_r;
    opts.max_anchors     = 4;
    opts.total_max_scans = 256;

    auto br = morphkatz::scan::bisect_multi(
        s, std::span<const uint8_t>(buf), opts);
    REQUIRE(br.ok());
    CHECK(br->status == morphkatz::scan::MultiBisectResult::Status::Done);
    REQUIRE(br->anchors.size() == 2);

    bool covers_text  = false;
    bool covers_rdata = false;
    for (const auto& a : br->anchors) {
        if (a.offset >= kTextOff &&
            a.offset + a.length <= kTextOff + kTextSize) {
            covers_text = true;
        }
        if (a.offset >= kRdataOff &&
            a.offset + a.length <= kRdataOff + kRdataSize) {
            covers_rdata = true;
        }
    }
    CHECK(covers_text);
    CHECK(covers_rdata);
}
