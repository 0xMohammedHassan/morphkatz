#pragma once

#include <string_view>

namespace morphkatz::cli {

// ASCII-art banner printed on `morphkatz` with no arguments and at the
// top of `--version`. The visual metaphor - three cat heads, one body -
// encodes the tool's identity: many polymorphic faces over one binary.
inline constexpr std::string_view kBanner =
    "\n"
    "           /\\_/\\      /\\_/\\      /\\_/\\\n"
    "          ( o.o )    ( -.- )    ( ^.^ )\n"
    "           > ^ <      > ^ <      > ^ <\n"
    "              \\_________|_________/\n"
    "                        |\n"
    "                     [  PE  ]\n"
    "\n"
    "               M o r p h K a t z\n"
    "\n"
    "   N faces, one body - polymorphic PE rewriter (Windows x64)\n"
    "               Coded by Mohammed Abuhassan\n"
    "\n";

// One-line synopsis and top examples, printed after kBanner when the
// user runs morphkatz with zero arguments.
inline constexpr std::string_view kFirstRunHint =
    "Usage:  morphkatz <input> [options]\n"
    "        morphkatz compare <a> <b> [more...] [--report out.json]\n"
    "        morphkatz scan    <input> [--bisect] [--report out.html]\n"
    "\n"
    "Quick start:\n"
    "  morphkatz payload.exe --seed 42 --report report.html\n"
    "  morphkatz payload.exe --seed 1 --variants 8 --report batch.json\n"
    "  morphkatz target.exe  --target yara/*.yar -vv\n"
    "  morphkatz target.exe  --target-defender target.exe --report run.html\n"
    "  morphkatz compare v0.exe v1.exe --report cmp.html\n"
    "  morphkatz scan suspect.exe --bisect --bisect-mode all --report scan.json\n"
    "\n"
    "Run 'morphkatz --help'         for all options.\n"
    "Run 'morphkatz compare --help' for the comparison subcommand.\n"
    "Run 'morphkatz scan --help'    for Defender scanning options.\n"
    "Run 'morphkatz --version'      for build info.\n";

}
