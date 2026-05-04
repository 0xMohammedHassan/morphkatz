#include "morphkatz/analysis/binary_diff.hpp"

#include "morphkatz/analysis/metrics.hpp"

#include <algorithm>
#include <cmath>

namespace morphkatz::analysis {

ByteProfile profile_bytes(std::span<const uint8_t> data) {
    ByteProfile p;
    p.size     = data.size();
    p.sha256   = sha256_hex(data);
    p.entropy  = shannon_entropy(data);
    p.richhash = rich_hash(data);
    for (auto byte : data) {
        p.histogram[byte]++;
    }
    return p;
}

namespace {

double cosine_similarity(const std::array<uint64_t, 256>& x,
                         const std::array<uint64_t, 256>& y) noexcept {
    double dot  = 0.0;
    double nx2  = 0.0;
    double ny2  = 0.0;
    for (size_t i = 0; i < 256; ++i) {
        const double xi = static_cast<double>(x[i]);
        const double yi = static_cast<double>(y[i]);
        dot += xi * yi;
        nx2 += xi * xi;
        ny2 += yi * yi;
    }
    if (nx2 == 0.0 || ny2 == 0.0) return 0.0;
    return dot / (std::sqrt(nx2) * std::sqrt(ny2));
}

double alphabet_jaccard(const std::array<uint64_t, 256>& x,
                        const std::array<uint64_t, 256>& y) noexcept {
    size_t inter = 0;
    size_t uni   = 0;
    for (size_t i = 0; i < 256; ++i) {
        const bool in_x = x[i] > 0;
        const bool in_y = y[i] > 0;
        if (in_x && in_y) ++inter;
        if (in_x || in_y) ++uni;
    }
    return uni == 0 ? 0.0 : static_cast<double>(inter) / static_cast<double>(uni);
}

}  // namespace

BinaryDiff diff_profiles(const ByteProfile& a, const ByteProfile& b) {
    BinaryDiff d;
    d.a = a;
    d.b = b;
    d.histogram_cosine = cosine_similarity(a.histogram, b.histogram);
    d.alphabet_jaccard = alphabet_jaccard(a.histogram, b.histogram);
    // Aligned byte counters require access to the original spans, which
    // we don't hold here. diff_bytes() fills them in when the raw data
    // is still available. When diffing from cached profiles only, we
    // leave aligned_* at 0 and rely on histogram_cosine / alphabet_*.
    return d;
}

BinaryDiff diff_bytes(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    BinaryDiff d;
    d.a = profile_bytes(a);
    d.b = profile_bytes(b);
    d.histogram_cosine = cosine_similarity(d.a.histogram, d.b.histogram);
    d.alphabet_jaccard = alphabet_jaccard(d.a.histogram, d.b.histogram);

    const size_t aligned = std::min(a.size(), b.size());
    size_t diff = 0;
    for (size_t i = 0; i < aligned; ++i) {
        if (a[i] != b[i]) ++diff;
    }
    d.aligned_bytes_diff = diff;
    d.aligned_bytes_same = aligned - diff;
    d.aligned_hamming_pct = aligned == 0
        ? 0.0
        : static_cast<double>(diff) * 100.0 / static_cast<double>(aligned);
    return d;
}

}
