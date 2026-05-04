# Responsible Use of MorphKatz

MorphKatz is a **binary-rewriting research tool**. It produces polymorphic
variants of Windows x64 executables for the sole purpose of **defensive
research** — evaluating detection engines, testing YARA rule-pack coverage,
and building datasets for academic work.

This file is the short version of the ethics policy. The long version
lives in the [NOTICE](NOTICE) file and in [`docs/responsible-use.md`](docs/responsible-use.md).

## What MorphKatz is for

- Red-team exercises authorised **in writing** by the system owner.
- Security-tool evaluation in labs you own or are contracted to test.
- Academic study of binary similarity, signature robustness, and
  equivalence-preserving rewrites.
- Tool-chain research: better disassemblers, CFG algorithms, flag-aware
  dataflow passes, multi-byte-NOP padding policies, verifiable rewrites.

## What MorphKatz is *not* for

- **Bypassing anti-virus or EDR** on systems you do not own or are not
  explicitly authorised to test.
- Evading detection as part of an actual intrusion.
- Distributing malware, whether your own or someone else's, with a
  MorphKatz-rewritten wrapper to slip past a vendor's signatures.
- Generating customer-specific obfuscated payloads as a paid service
  without a clear authorisation trail from the end customer.

The maintainers will:

- Close, without review, pull requests that ship rules designed to keep
  active malware families alive in the wild.
- Decline to debug crash reports, emulator divergences, or false-positive
  reports that appear to originate from an offensive operation.
- Ban, from the repository and all MorphKatz-adjacent community spaces,
  users whose public identity shows a pattern of ransomware deployment,
  sale of evasion-as-a-service, or similar.

## If you are a vendor whose product MorphKatz evades

Please open a **private** Security Advisory (see [`SECURITY.md`](SECURITY.md))
describing the signature class that is being broken. We will engage in good
faith with any vendor doing detection engineering.

## Ethical rule-pack contributions

When contributing rules under `rules/x64/**/*.yaml`, please avoid:

- Packs named after specific threat actors or commercial red-team tools
  whose primary purpose is to obscure detection of live operations.
- Rules derived solely from reverse-engineering a paid commercial AV/EDR
  signature database. Publish the *technique*, not the leaked vendor IP.

Do include:

- A citation for every instruction-level transformation (Intel SDM,
  AMD64 APM, peer-reviewed paper).
- A `flags_effect: equivalent` claim **only** when you have hand-verified
  both the arithmetic and the observable side effects.
- A unit test in `tests/unit/` or a new test file that exercises the new
  rule on a synthetic input.

## Legal

MorphKatz is licensed under the **GNU Affero General Public License,
version 3.0 or later** — see [`LICENSE`](LICENSE). The licence grants you
the right to use, study, modify and redistribute the source code. It does
**not** grant authorisation to run the produced binaries against third-party
infrastructure. You remain solely responsible for complying with:

- Your local computer-misuse laws (CFAA in the US, Computer Misuse Act in
  the UK, §202c StGB in Germany, Personal Data Protection Act in many
  other jurisdictions, etc.).
- Contracts, NDAs and rules-of-engagement for any assessment you perform.
- Platform and distribution terms (Microsoft Store, Scoop, Chocolatey,
  package registries, CI providers) when redistributing binaries.

When in doubt, don't.
