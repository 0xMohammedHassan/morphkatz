# Security Policy

MorphKatz is a binary-rewriting tool. It parses attacker-controlled PE files,
disassembles them, rewrites their instruction bytes and writes new binaries.
Any of those steps can be a security boundary, both for MorphKatz itself and
for whatever runs the produced output. We take that seriously.

## Supported versions

The `main` branch is the only branch that receives security fixes.
Tagged releases of the most recent **minor** version are also supported;
older minor versions receive fixes for **critical** severity issues only.

| Version          | Supported                 |
| ---------------- | ------------------------- |
| `main`           | ✅ full support           |
| `v0.x` (current) | ✅ full support           |
| `v0.(x-1)`       | ⚠️  critical-only          |
| `<= v0.(x-2)`    | ❌ no longer supported    |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, use one of:

1. **GitHub Security Advisory** (preferred): go to the repository →
   *Security* tab → *Report a vulnerability*.

Please include:

- The MorphKatz version or commit SHA.
- The affected preset / build flags (e.g. `vs2022-x64-asan`).
- A minimal reproducer — ideally a PE file (even a 512-byte MS-DOS stub is
  enough for most parsing bugs).
- The impact you observed (crash, out-of-bounds read, heap corruption,
  arbitrary file write, etc.).
- Whether you'd like credit in the advisory, and under what name/handle.

We aim to:

- Acknowledge receipt within **2 business days**.
- Provide an initial severity assessment within **5 business days**.
- Ship a fix, advisory, and coordinated release within **90 days** for
  "High" severity and **30 days** for "Critical".

If you have not heard back in the timeframes above, feel free to nudge via a
**private** channel.

## Scope

Within scope:

- Memory-safety bugs in the decoder (`src/disasm/**`), encoder
  (`src/engine/encoder.cpp`), patcher (`src/engine/patcher.cpp`), CFG
  reconstructor (`src/disasm/cfg.cpp`), PE image parser
  (`src/format/pe_image.cpp`), YAML rule loader (`src/rules/rule_loader.cpp`),
  YARA target compiler (`src/yara/yara_target.cpp`), and any other reachable
  code path when processing an untrusted input PE or rule pack.
- Logic bugs that cause MorphKatz to produce a PE file that crashes the
  Windows loader, re-introduces a signature it was supposed to break, or
  silently drops coverage the diff report claims was applied.
- Supply-chain issues in MorphKatz's own CI / release pipeline
  (`.github/workflows/**`), including artefact tampering, fake releases,
  or loss of signing keys.
- Bugs in the one-click installer scripts (`Open-in-VS.cmd`,
  `scripts/open-in-vs.ps1`, Chocolatey / Scoop manifests) that allow a
  remote attacker to escalate when the user runs them.

Out of scope:

- Any issue that requires attacker control over `VCPKG_ROOT`, the Visual
  Studio install, or another part of the user's local build environment.
- Upstream dependency vulnerabilities (Zydis, LIEF, spdlog, etc.).
  Please file those with the upstream project; we'll track and pin.
- Abuse scenarios where MorphKatz is used to obfuscate live malware —
  that's a [`RESPONSIBLE_USE.md`](RESPONSIBLE_USE.md) matter, not a security
  bug. Our threat model assumes the *user* is authorised.

## Disclosure

Once a fix is ready we will:

1. Release a new patch version on GitHub Releases.
2. Publish a GitHub Security Advisory with CVE identifier (if applicable).
3. Credit the reporter in the advisory and the release notes (unless they
   ask us not to).
4. Backport the fix to any currently-supported minor version (see table
   above).

## Bug bounty

There is **no** monetary bug-bounty programme at this time. For serious,
well-documented reports we send out a set of MorphKatz stickers, a
*hall-of-fame* entry in the README, and a line in the advisory credits.
If that ever changes it will be announced here and on the release blog
first.
