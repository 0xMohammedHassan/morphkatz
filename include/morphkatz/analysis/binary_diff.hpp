#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace morphkatz::analysis {

// Cheap-to-compute, cache-friendly summary of a binary. Built once per
// file so the all-pairs compare mode stays O(N) in I/O and O(N^2) in
// tiny arithmetic rather than O(N^2) in disk reads.
struct ByteProfile {
    size_t                      size      = 0;
    std::string                 sha256;
    double                      entropy   = 0.0;   // bits/byte
    uint32_t                    richhash  = 0;
    std::array<uint64_t, 256>   histogram {};
};

// Pairwise comparison result between two ByteProfiles.
//
// "aligned" counters operate on the min-length prefix; files of
// different length contribute their shared prefix to hamming and
// nothing to the tail (the size delta is visible via a.size vs b.size).
struct BinaryDiff {
    ByteProfile a;
    ByteProfile b;

    size_t aligned_bytes_same = 0;
    size_t aligned_bytes_diff = 0;
    double aligned_hamming_pct = 0.0;

    // Cosine similarity of the 256-bin byte histograms.
    //   1.0 = identical distributions
    //   0.0 = no shared bytes at all
    // Robust to byte-level edits that break pure hamming counting
    // (e.g. inserting NOP sleds that shift everything right).
    double histogram_cosine = 0.0;

    // Jaccard index of the byte *alphabet* (which of the 256 values
    // appear at all). Same range, simpler signal: detects whether a
    // binary gained or lost entire classes of bytes.
    double alphabet_jaccard = 0.0;
};

[[nodiscard]] ByteProfile profile_bytes(std::span<const uint8_t> data);

[[nodiscard]] BinaryDiff diff_profiles(const ByteProfile& a,
                                        const ByteProfile& b);

[[nodiscard]] BinaryDiff diff_bytes(std::span<const uint8_t> a,
                                     std::span<const uint8_t> b);

}
