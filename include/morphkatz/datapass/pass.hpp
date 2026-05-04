#pragma once

#include "morphkatz/common/error.hpp"
#include "morphkatz/datapass/atom.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace morphkatz::format { class PeImage; }

namespace morphkatz::datapass {

enum class DecoderPlacement : unsigned {
    Auto,
    EpThunk,
    TlsCallback,   // not yet supported in v1; falls back to EpThunk
};

// What the pass actually does to the binary.
//   Full       - the v1 pipeline: XOR atoms in place, append the
//                .morph section with the decoder stub, redirect the
//                entry point so the stub runs first. Runtime is
//                preserved.
//   EncodeOnly - XOR atoms in place and stop. No section is appended,
//                no entry-point change is made. The output passes
//                static AV scans (no decoder shape to fingerprint)
//                but will not execute correctly. Use this for
//                detection-engineering coverage testing where the
//                artifact is never run; never ship an EncodeOnly
//                output as a runnable program.
enum class PassMode : unsigned {
    Full,
    EncodeOnly,
};

struct DataPassConfig {
    uint32_t         xor_key      = 0;             // derived from --seed
    DecoderPlacement placement    = DecoderPlacement::EpThunk;
    PassMode         mode         = PassMode::Full;
    std::string      section_name = ".morph";
};

struct DataPassReport {
    bool        encoded                = false;
    uint32_t    atoms_encoded          = 0;
    uint64_t    morph_section_size     = 0;
    uint32_t    morph_section_rva      = 0;
    bool        entry_point_changed    = false;
    std::string decoder_placement;            // "ep_thunk" / "tls_callback" / "skipped"
    std::string skip_reason;                  // populated when encoded=false
};

// Apply the data-section morphing pass to `image`:
//   1) Look up VirtualProtect IAT thunk RVA (bails if missing).
//   2) Build the decoder stub for `atoms` using `cfg.xor_key`.
//   3) Append a new section (`cfg.section_name`) holding the stub +
//      directory.
//   4) Patch the four RIP-relative displacements in the stub.
//   5) Fill in `target_rva` for each atom's DirEntry (file_offset -> RVA).
//   6) XOR-encode each atom's bytes in place inside the existing PE
//      sections.
//   7) Patch IMAGE_OPTIONAL_HEADER::AddressOfEntryPoint to the stub.
//
// Returns a report describing what was actually done; an empty atom
// list is a clean no-op (encoded=false, skip_reason="no atoms").
[[nodiscard]] Result<DataPassReport>
run_data_pass(format::PeImage&         image,
              std::span<const Atom>    atoms,
              const DataPassConfig&    cfg);

}
