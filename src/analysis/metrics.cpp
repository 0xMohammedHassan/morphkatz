#include "morphkatz/analysis/metrics.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>

namespace morphkatz::analysis {

double shannon_entropy(std::span<const uint8_t> data) noexcept {
    if (data.empty()) return 0.0;
    std::array<uint64_t, 256> freq{};
    for (auto b : data) ++freq[b];
    const double n = static_cast<double>(data.size());
    double h = 0.0;
    for (auto c : freq) {
        if (c == 0) continue;
        const double p = static_cast<double>(c) / n;
        h -= p * std::log2(p);
    }
    return h;
}

std::string sha256_hex(std::span<const uint8_t> data) {
    unsigned int md_len = 0;
    std::array<unsigned char, EVP_MAX_MD_SIZE> md{};

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return {};
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1
           && EVP_DigestUpdate(ctx, data.data(), data.size()) == 1
           && EVP_DigestFinal_ex(ctx, md.data(), &md_len) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok || md_len != 32) return {};

    std::string out;
    out.resize(md_len * 2);
    static constexpr char kHex[] = "0123456789abcdef";
    for (unsigned int i = 0; i < md_len; ++i) {
        out[i * 2 + 0] = kHex[(md[i] >> 4) & 0xF];
        out[i * 2 + 1] = kHex[ md[i]       & 0xF];
    }
    return out;
}

size_t byte_diff_count(std::span<const uint8_t> before,
                       std::span<const uint8_t> after) noexcept {
    const size_t common = std::min(before.size(), after.size());
    const size_t tail   = (before.size() > common) ? before.size() - common
                                                   : after.size()  - common;
    size_t n = tail;
    for (size_t i = 0; i < common; ++i) {
        if (before[i] != after[i]) ++n;
    }
    return n;
}

namespace {

inline uint32_t rotl32(uint32_t v, unsigned n) noexcept {
    n &= 31;
    return (v << n) | (v >> ((32 - n) & 31));
}

// Walk raw PE bytes and, if a Rich header is present, return the
// checksum using the same algorithm pefile's `RichHeader.checksum`
// implements: seed with the DanS offset, fold each pre-DanS byte with
// `rol(byte, index)` (skipping e_lfanew at [0x3C..0x40)), then fold
// each decoded (CompID<<16|Count) entry with `rol(entry, count)`.
uint32_t rich_hash_impl(std::span<const uint8_t> data) noexcept {
    if (data.size() < 0x80) return 0;
    if (!(data[0] == 'M' && data[1] == 'Z')) return 0;

    uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, data.data() + 0x3C, sizeof(e_lfanew));
    if (e_lfanew < 0x80 ||
        static_cast<size_t>(e_lfanew) > data.size()) {
        return 0;
    }

    // Scan [0x80, e_lfanew) for "Rich" + key; the DanS sentinel sits 0x10
    // bytes plus N*8 bytes (N entries) before "Rich".
    size_t rich_off = 0;
    for (size_t i = 0x80; i + 8 <= e_lfanew; i += 4) {
        if (data[i]   == 'R' && data[i + 1] == 'i' &&
            data[i+2] == 'c' && data[i + 3] == 'h') {
            rich_off = i;
            break;
        }
    }
    if (rich_off == 0) return 0;

    uint32_t key = 0;
    std::memcpy(&key, data.data() + rich_off + 4, sizeof(key));

    // Find DanS by scanning backwards from Rich for (u32 ^ key) == "DanS".
    constexpr uint32_t kDanS = 0x536E6144u;
    size_t dans_off = 0;
    for (size_t i = rich_off; i >= 0x80 + 4; i -= 4) {
        uint32_t w = 0;
        std::memcpy(&w, data.data() + (i - 4), sizeof(w));
        if ((w ^ key) == kDanS) {
            dans_off = i - 4;
            break;
        }
    }
    if (dans_off == 0) return 0;

    // Entries sit at [dans_off + 0x10, rich_off) as (CompID<<16|Count)
    // u32 words, each XOR'd with `key`.
    if (rich_off < dans_off + 0x10) return 0;
    const size_t entries_bytes = rich_off - (dans_off + 0x10);
    if ((entries_bytes & 0x7u) != 0) return 0;

    uint32_t checksum = static_cast<uint32_t>(dans_off);
    for (size_t i = 0; i < dans_off; ++i) {
        if (i >= 0x3C && i < 0x40) continue;
        checksum = checksum + rotl32(data[i], static_cast<unsigned>(i & 31));
    }

    // Each Rich entry is two XOR'd DWORDs: comp (product << 16 | build)
    // followed by count. The checksum contribution is
    // `rol(comp_decoded, count_decoded & 31)` — see pefile's
    // RichHeader.get_hash.
    for (size_t i = dans_off + 0x10; i + 8 <= rich_off; i += 8) {
        uint32_t comp_enc = 0, count_enc = 0;
        std::memcpy(&comp_enc,  data.data() + i,     sizeof(comp_enc));
        std::memcpy(&count_enc, data.data() + i + 4, sizeof(count_enc));
        const uint32_t comp  = comp_enc  ^ key;
        const uint32_t count = count_enc ^ key;
        checksum = checksum + rotl32(comp, static_cast<unsigned>(count & 31));
    }
    return checksum;
}

}  // namespace

uint32_t rich_hash(std::span<const uint8_t> data) noexcept {
    return rich_hash_impl(data);
}

}  // namespace morphkatz::analysis
