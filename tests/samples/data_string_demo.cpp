// data_string_demo.cpp -- minimal test fixture for the data-section
// morphing pass.
//
// Stores a literal string in .rdata, prints it, and exits with code
// 42 only when the runtime contents match the build-time literal.
// After morphkatz --data-morph on rewrites the binary, the literal
// must still appear intact at runtime (because the decoder stub
// restores it); if the decoder is broken, the comparison fails and
// we exit non-zero, signalling a regression.
//
// Build (Windows):
//   cl /nologo /MD /Os /Fe:data_string_demo.exe data_string_demo.cpp
//
// Or use the bundled `build_data_string_demo.cmd` script.

#include <cstdio>
#include <cstring>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

extern "C" __declspec(noinline)
int verify_bytes(const char* a, const unsigned char* expected, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (static_cast<unsigned char>(a[i]) != expected[i]) return 1;
    }
    return 42;
}

// The literal lives in .rdata; an unmorphed binary will see exactly
// these bytes. After morph, they're encoded on disk and decoded at
// startup before main() runs.
static const char kSecret[] = "MorphKatz_DataPass_OK_1234567890";

// Stored XOR-masked so the literal bytes "MorphKatz_..." never appear
// in .rdata anywhere other than kSecret itself.  Without this, MSVC's
// constant-merging would happily dedupe a second copy of the same
// bytes, masking a broken decoder by comparing two encoded copies.
static const unsigned char kMask = 0xA7u;
static const unsigned char kExpectedMasked[] = {
    'M' ^ 0xA7u, 'o' ^ 0xA7u, 'r' ^ 0xA7u, 'p' ^ 0xA7u, 'h' ^ 0xA7u,
    'K' ^ 0xA7u, 'a' ^ 0xA7u, 't' ^ 0xA7u, 'z' ^ 0xA7u, '_' ^ 0xA7u,
    'D' ^ 0xA7u, 'a' ^ 0xA7u, 't' ^ 0xA7u, 'a' ^ 0xA7u, 'P' ^ 0xA7u,
    'a' ^ 0xA7u, 's' ^ 0xA7u, 's' ^ 0xA7u, '_' ^ 0xA7u, 'O' ^ 0xA7u,
    'K' ^ 0xA7u, '_' ^ 0xA7u, '1' ^ 0xA7u, '2' ^ 0xA7u, '3' ^ 0xA7u,
    '4' ^ 0xA7u, '5' ^ 0xA7u, '6' ^ 0xA7u, '7' ^ 0xA7u, '8' ^ 0xA7u,
    '9' ^ 0xA7u, '0' ^ 0xA7u, 0u ^ 0xA7u,
};

int main() {
    // The data-morph decoder calls kernel32!VirtualProtect to flip
    // .rdata pages writeable while it XORs the secret back. The
    // sample must import that API so morphkatz can find it in the
    // IAT - this `volatile` reference forces the linker to keep the
    // import (otherwise dead-code elimination throws it away).
    volatile auto vp = &VirtualProtect;
    (void)vp;

    std::puts(kSecret);

    // Reconstruct expected bytes at runtime by XOR'ing kExpectedMasked
    // back; this guarantees the .rdata never contains an unencoded
    // "MorphKatz_..." literal that could be deduped with kSecret.
    unsigned char expected[sizeof(kExpectedMasked)];
    for (size_t i = 0; i < sizeof(kExpectedMasked); ++i) {
        expected[i] = static_cast<unsigned char>(kExpectedMasked[i] ^ kMask);
    }
    return verify_bytes(kSecret, expected, sizeof(kSecret));
}
